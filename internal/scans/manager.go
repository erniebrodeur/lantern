package scans

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
)

const (
	maxOutputLineBytes       = 1024 * 1024
	maxHTTPSCertificatePorts = 8
)

type activeRun struct {
	cancel        context.CancelFunc
	desiredStatus Status
	tools         map[string]ToolActivity
	toolRefs      map[string]int
}

// Manager coordinates scan execution, persistence, providers, and subscribers.
type Manager struct {
	store           Store
	mu              sync.Mutex
	active          map[string]*activeRun
	subs            map[string]map[chan Event]struct{}
	globalSubs      map[chan Event]struct{}
	closing         bool
	workers         sync.WaitGroup
	privileged      bool
	routeSlots      chan struct{}
	enrichmentSlots chan struct{}
	providers       *providers.Registry
}

// NewManager constructs a manager with Lantern's default provider registry.
func NewManager(store Store, nmapPath string) (*Manager, error) {
	registry := providers.NewRegistry(runtime.GOOS, os.Getenv,
		providers.NewDNSSDProvider(nil),
		providers.NewAvahiProvider(nil),
		providers.NewRDAPProvider(nil, ""),
		providers.NewWHOISProvider(nil, os.Getenv("LANTERN_WHOIS_PATH")),
		providers.NewReverseDNSProvider(nil),
		providers.NewTLSCertificateProvider(nil),
		providers.NewMTRProvider(nil),
		providers.NewTracerouteProvider(nil),
	)
	return NewManagerWithProviders(store, nmapPath, registry)
}

// NewManagerWithProviders constructs a manager with an explicit provider registry.
func NewManagerWithProviders(store Store, nmapPath string, registry *providers.Registry) (*Manager, error) {
	privileged := runningPrivileged()
	if registry == nil {
		registry = providers.NewRegistry(runtime.GOOS, os.Getenv)
	}
	registry.Register(newNmapProvider(nmapPath))
	manager := &Manager{
		store:           store,
		active:          make(map[string]*activeRun),
		subs:            make(map[string]map[chan Event]struct{}),
		globalSubs:      make(map[chan Event]struct{}),
		privileged:      privileged,
		routeSlots:      make(chan struct{}, 10),
		enrichmentSlots: make(chan struct{}, 12),
		providers:       registry,
	}
	if manager.providers != nil {
		probeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		manager.providers.Refresh(probeContext)
		cancel()
	}
	if err := store.InterruptRunning(context.Background(), time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("reconcile interrupted scans: %w", err)
	}
	return manager, nil
}

// Start begins a scan with the default profile.
func (m *Manager) Start(ctx context.Context, rawTarget string) (Scan, error) {
	return m.StartRequest(ctx, ScanRequest{Target: rawTarget, ProfileID: DefaultProfileID})
}

// StartRequest validates, persists, and asynchronously starts a scan.
func (m *Manager) StartRequest(ctx context.Context, request ScanRequest) (Scan, error) {
	target, err := ValidateTarget(request.Target)
	if err != nil {
		return Scan{}, err
	}
	profileID := request.ProfileID
	if profileID == "" {
		profileID = DefaultProfileID
	}
	profile, err := m.profile(ctx, profileID)
	if err != nil {
		return Scan{}, err
	}
	profileArguments := append([]string(nil), profile.Arguments...)
	profileArguments = append(profileArguments, request.AdditionalArguments...)
	if err := ValidateArguments(profileArguments); err != nil {
		return Scan{}, err
	}
	arguments, osDetection := resolveArguments(profileArguments, target, request.OSDetection)
	if osDetection && !m.privileged {
		return Scan{}, ErrPrivilegeRequired
	}
	identifier, err := newID()
	if err != nil {
		return Scan{}, err
	}
	runContext, cancel := context.WithCancel(context.Background())
	scan := Scan{
		ID:          identifier,
		Target:      target,
		ProfileID:   profile.ID,
		OSDetection: osDetection,
		Status:      StatusQueued,
		Arguments:   arguments,
		CreatedAt:   time.Now().UTC(),
		Output:      "",
	}

	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		cancel()
		return Scan{}, fmt.Errorf("scan manager is shutting down")
	}
	m.active[identifier] = &activeRun{
		cancel: cancel, desiredStatus: StatusCancelled,
		tools:    make(map[string]ToolActivity),
		toolRefs: make(map[string]int),
	}
	m.workers.Add(1)
	m.mu.Unlock()

	if err := m.store.Create(ctx, scan); err != nil {
		m.mu.Lock()
		delete(m.active, identifier)
		m.mu.Unlock()
		cancel()
		m.workers.Done()
		return Scan{}, err
	}

	go m.execute(runContext, scan)
	return scan, nil
}

// Capabilities returns a snapshot of available scan features and providers.
func (m *Manager) Capabilities() Capabilities {
	capabilities := Capabilities{Privileged: m.privileged, OSDetection: m.privileged, ToolActivity: true}
	if m.providers != nil {
		capabilities.Providers = m.providers.Statuses()
	} else {
		capabilities.Providers = make([]providers.Status, 0)
	}
	var routes []providers.Selection
	if m.providers != nil {
		routes = m.providers.ResolveAll("route")
	}
	if len(routes) > 0 {
		capabilities.RouteMapping = true
		names := make([]string, 0, len(routes))
		for _, selection := range routes {
			names = append(names, selection.Status.ProviderID)
		}
		capabilities.RouteTool = strings.Join(names, " / ")
	} else {
		capabilities.RouteMappingReason = "Install mtr or traceroute on the Lantern host to enable Map"
	}
	return capabilities
}

// RefreshProviders probes all providers and returns their current statuses.
func (m *Manager) RefreshProviders(ctx context.Context) []providers.Status {
	if m.providers == nil {
		return []providers.Status{}
	}
	m.providers.Refresh(ctx)
	return m.providers.Statuses()
}

func argumentsRequestOSDetection(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "-O" || argument == "-A" {
			return true
		}
	}
	return false
}

func resolveArguments(profileArguments []string, target string, requestedOSDetection bool) ([]string, bool) {
	osDetection := requestedOSDetection || argumentsRequestOSDetection(profileArguments)
	arguments := append([]string(nil), profileArguments...)
	if singleIPTarget(target) && !containsArgument(arguments, "-sn") && !containsArgument(arguments, "-Pn") {
		arguments = append(arguments, "-Pn")
	}
	if requestedOSDetection && !argumentsRequestOSDetection(arguments) {
		arguments = append(arguments, "-O")
	}
	arguments = append(arguments, "--stats-every", "1s", "-oX", "-", target)
	return arguments, osDetection
}

func singleIPTarget(target string) bool {
	if _, err := netip.ParseAddr(target); err == nil {
		return true
	}
	prefix, err := netip.ParsePrefix(target)
	return err == nil && prefix.Bits() == prefix.Addr().BitLen()
}

func containsArgument(arguments []string, target string) bool {
	for _, argument := range arguments {
		if argument == target {
			return true
		}
	}
	return false
}

// Profiles returns built-in and user-defined scan profiles.
func (m *Manager) Profiles(ctx context.Context) ([]Profile, error) {
	custom, err := m.store.ListProfiles(ctx)
	if err != nil {
		return nil, err
	}
	return append(BuiltInProfiles(), custom...), nil
}

// SaveProfile creates a profile or updates the user-defined profile identified by identifier.
func (m *Manager) SaveProfile(ctx context.Context, identifier, argumentText string) (Profile, error) {
	arguments, err := ParseArgumentText(argumentText)
	if err != nil {
		return Profile{}, err
	}
	now := time.Now().UTC()
	profile := Profile{
		ID:           identifier,
		ArgumentText: strings.TrimSpace(argumentText),
		Arguments:    arguments,
		CreatedAt:    &now,
		UpdatedAt:    &now,
	}
	if profile.ID == "" {
		profile.ID, err = newID()
		if err != nil {
			return Profile{}, err
		}
		if err := m.store.CreateProfile(ctx, profile); err != nil {
			return Profile{}, err
		}
		return profile, nil
	}
	if _, builtIn := BuiltInProfile(profile.ID); builtIn {
		return Profile{}, fmt.Errorf("built-in profiles are immutable")
	}
	existing, err := m.store.GetProfile(ctx, profile.ID)
	if err != nil {
		return Profile{}, err
	}
	profile.CreatedAt = existing.CreatedAt
	if err := m.store.UpdateProfile(ctx, profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// DeleteProfile removes a user-defined profile.
func (m *Manager) DeleteProfile(ctx context.Context, identifier string) error {
	if _, builtIn := BuiltInProfile(identifier); builtIn {
		return fmt.Errorf("built-in profiles are immutable")
	}
	return m.store.DeleteProfile(ctx, identifier)
}

func (m *Manager) profile(ctx context.Context, identifier string) (Profile, error) {
	if profile, ok := BuiltInProfile(identifier); ok {
		return profile, nil
	}
	return m.store.GetProfile(ctx, identifier)
}

// List returns all scans in reverse chronological order.
func (m *Manager) List(ctx context.Context) ([]Scan, error) {
	return m.store.List(ctx)
}

// Get returns the scan identified by identifier.
func (m *Manager) Get(ctx context.Context, identifier string) (Scan, error) {
	return m.store.Get(ctx, identifier)
}

// ActiveTools returns an in-memory snapshot of tools active for a scan.
func (m *Manager) ActiveTools(identifier string) []ToolActivity {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.active[identifier]
	if !ok {
		return []ToolActivity{}
	}
	tools := make([]ToolActivity, 0, len(run.tools))
	for _, tool := range run.tools {
		tools = append(tools, tool)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
	return tools
}

// ListTools merges stored provider runs with currently active tools.
func (m *Manager) ListTools(ctx context.Context, identifier string) ([]ToolActivity, error) {
	tools, err := m.store.ListTools(ctx, identifier)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]ToolActivity, len(tools))
	for _, tool := range tools {
		byID[tool.ID] = tool
	}
	for _, tool := range m.ActiveTools(identifier) {
		byID[tool.ID] = tool
	}
	tools = tools[:0]
	for _, tool := range byID {
		tools = append(tools, tool)
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].ID == "nmap" {
			return true
		}
		if tools[j].ID == "nmap" {
			return false
		}
		return tools[i].Label < tools[j].Label
	})
	return tools, nil
}

// Delete removes a completed scan and its associated data.
func (m *Manager) Delete(ctx context.Context, identifier string) error {
	m.mu.Lock()
	_, active := m.active[identifier]
	m.mu.Unlock()
	if active {
		return ErrScanActive
	}
	return m.store.Delete(ctx, identifier)
}

// ListHosts returns a page of hosts observed by a scan.
func (m *Manager) ListHosts(ctx context.Context, identifier string, limit, offset int) (HostPage, error) {
	if _, err := m.store.Get(ctx, identifier); err != nil {
		return HostPage{}, err
	}
	return m.store.ListHosts(ctx, identifier, limit, offset)
}

// GetHost returns one host observation from a scan.
func (m *Manager) GetHost(ctx context.Context, scanID string, hostID int64) (HostObservation, error) {
	host, err := m.store.GetHost(ctx, scanID, hostID)
	if err != nil || host.Ownership != nil {
		return host, err
	}
	address, ok := hostIPAddress(host)
	if !ok {
		return host, nil
	}
	ownership := m.providerOwnership(ctx, scanID, address.Address)
	if ownership == nil {
		return host, nil
	}
	enriched, saveErr := m.store.SaveHostEnrichment(ctx, scanID, address, nil, ownership)
	if saveErr != nil {
		return host, nil
	}
	return enriched, nil
}

func (m *Manager) providerHostnames(ctx context.Context, scanID, address string) []Hostname {
	if m.providers == nil {
		return nil
	}
	provider, _, ok := m.providers.Resolve("reverse-dns")
	if !ok {
		return nil
	}
	var hostnames []Hostname
	_, err := m.runProvider(ctx, scanID, providers.Request{Target: address}, provider, func(event providers.Event) error {
		if event.Evidence == nil || event.Evidence.Kind != "dns.ptr" {
			return nil
		}
		var result providers.ReverseDNS
		if err := json.Unmarshal(event.Evidence.Payload, &result); err != nil {
			return err
		}
		for _, name := range result.Names {
			hostnames = append(hostnames, Hostname{Name: name, Type: "PTR"})
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return hostnames
}

func (m *Manager) providerCertificateHostnames(ctx context.Context, scanID, address string, ports []Port) []Hostname {
	if m.providers == nil {
		return nil
	}
	provider, _, ok := m.providers.Resolve("tls-certificate")
	if !ok {
		return nil
	}
	seen := make(map[string]struct{})
	hostnames := make([]Hostname, 0)
	for _, port := range httpsPorts(ports) {
		_, err := m.runProvider(ctx, scanID, providers.Request{
			Target: address, Options: map[string]string{"port": fmt.Sprint(port)},
		}, provider, func(event providers.Event) error {
			if event.Evidence == nil || event.Evidence.Kind != "tls.certificate" {
				return nil
			}
			var certificate providers.TLSCertificate
			if err := json.Unmarshal(event.Evidence.Payload, &certificate); err != nil {
				return fmt.Errorf("decode TLS certificate: %w", err)
			}
			names := certificate.DNSNames
			hostnameType := "TLS_SAN"
			if len(names) == 0 && certificate.CommonName != "" {
				names = []string{certificate.CommonName}
				hostnameType = "TLS_CN"
			}
			for _, name := range names {
				name = normalizeUsableHostname(name)
				if name == "" {
					continue
				}
				if _, exists := seen[name]; exists {
					continue
				}
				seen[name] = struct{}{}
				hostnames = append(hostnames, Hostname{Name: name, Type: hostnameType})
			}
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return hostnames
		}
	}
	return hostnames
}

// Cancel requests cancellation of an active scan.
func (m *Manager) Cancel(identifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.active[identifier]
	if !ok {
		return ErrNotFound
	}
	run.desiredStatus = StatusCancelled
	run.cancel()
	return nil
}

// Subscribe streams events for one scan and returns an unsubscribe function.
func (m *Manager) Subscribe(identifier string) (<-chan Event, func()) {
	channel := make(chan Event, 128)
	m.mu.Lock()
	if m.subs[identifier] == nil {
		m.subs[identifier] = make(map[chan Event]struct{})
	}
	m.subs[identifier][channel] = struct{}{}
	m.mu.Unlock()

	var once sync.Once
	return channel, func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.subs[identifier], channel)
			if len(m.subs[identifier]) == 0 {
				delete(m.subs, identifier)
			}
			m.mu.Unlock()
		})
	}
}

// SubscribeAll receives persisted scan and host updates for every scan. Detailed
// output, progress, and provider evidence remain on dedicated subscriptions.
// SubscribeAll streams events for every scan and returns an unsubscribe function.
func (m *Manager) SubscribeAll() (<-chan Event, func()) {
	channel := make(chan Event, 128)
	m.mu.Lock()
	m.globalSubs[channel] = struct{}{}
	m.mu.Unlock()

	var once sync.Once
	return channel, func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.globalSubs, channel)
			m.mu.Unlock()
		})
	}
}

// Shutdown cancels active work and waits until it finishes or ctx expires.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	m.closing = true
	for _, run := range m.active {
		run.desiredStatus = StatusInterrupted
		run.cancel()
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (m *Manager) execute(ctx context.Context, scan Scan) {
	defer m.workers.Done()
	defer func() {
		m.mu.Lock()
		delete(m.active, scan.ID)
		m.mu.Unlock()
	}()

	startedAt := time.Now().UTC()
	if err := m.store.MarkStarted(context.Background(), scan.ID, startedAt); err != nil {
		m.appendOutput(scan.ID, "stderr", "Lantern could not persist the scan start: "+err.Error()+"\n")
	}
	if current, err := m.store.Get(context.Background(), scan.ID); err == nil {
		m.publish(scan.ID, Event{Type: "scan", Scan: &current})
	}
	var providerRuns sync.WaitGroup
	if m.providerTargetEligible(scan.Target) {
		if provider, status, ok := m.providers.Resolve("mdns"); ok {
			providerRuns.Add(1)
			go func() {
				defer providerRuns.Done()
				m.collectProvider(ctx, scan.ID, scan.Target, provider, status)
			}()
		}
	}

	var enrichments sync.WaitGroup
	var enrichmentStarted sync.Map
	if address, ok := scanTargetIPAddress(scan.Target); ok {
		enrichments.Add(1)
		go func() {
			defer enrichments.Done()
			m.enrichScanOwnership(ctx, scan.ID, address)
		}()
	}
	var result Result
	observationCount := 0
	var exitCode *int
	var runErr error
	provider, availability, ok := m.providers.Resolve("scan")
	if !ok {
		reason := availability.Reason
		if reason == "" {
			reason = "no scan provider is available"
		}
		runErr = errors.New(reason)
	} else {
		_, runErr = m.runProvider(ctx, scan.ID, providers.Request{Target: scan.Target, Arguments: scan.Arguments}, provider, func(event providers.Event) error {
			if event.Type == "complete" {
				exitCode = event.ExitCode
				return nil
			}
			if event.Evidence == nil {
				return nil
			}
			switch event.Evidence.Kind {
			case "host.observation":
				var host HostObservation
				if err := json.Unmarshal(event.Evidence.Payload, &host); err != nil {
					return fmt.Errorf("decode host observation: %w", err)
				}
				if scan.OSDetection {
					if len(host.OSMatches) > 0 {
						host.OSStatus = "matched"
					} else {
						host.OSStatus = "inconclusive"
					}
				}
				saved, err := m.store.SaveHost(context.Background(), scan.ID, host)
				if err != nil {
					return err
				}
				m.publish(scan.ID, Event{Type: "host", Host: &saved})
				if current, err := m.store.Get(context.Background(), scan.ID); err == nil {
					m.publish(scan.ID, Event{Type: "scan", Scan: &current})
				}
				if !saved.Provisional {
					address, ok := hostIPAddress(saved)
					if !ok {
						break
					}
					key := address.Type + ":" + address.Address
					if _, loaded := enrichmentStarted.LoadOrStore(key, struct{}{}); !loaded {
						enrichments.Add(1)
						go func(host HostObservation) {
							defer enrichments.Done()
							m.enrichHost(ctx, scan.ID, host)
						}(saved)
					}
				}
			case "scan.summary":
				var summary nmapSummary
				if err := json.Unmarshal(event.Evidence.Payload, &summary); err != nil {
					return fmt.Errorf("decode scan summary: %w", err)
				}
				result.NmapVersion = summary.NmapVersion
				result.XMLOutputVersion = summary.XMLOutputVersion
				result.HostsUp = summary.HostsUp
				result.HostsDown = summary.HostsDown
				result.HostsTotal = summary.HostsTotal
				observationCount = summary.Observations
			}
			return nil
		})
	}
	enrichments.Wait()
	providerRuns.Wait()
	finishedAt := time.Now().UTC()
	status := StatusCompleted
	errorMessage := ""
	if ctx.Err() != nil {
		status = m.desiredStatus(scan.ID)
	} else if runErr != nil {
		status = StatusFailed
		errorMessage = runErr.Error()
		m.appendOutput(scan.ID, "stderr", "Lantern scan provider failed: "+errorMessage+"\n")
	} else if err := m.store.SaveSummary(context.Background(), scan.ID, result); err != nil {
		status = StatusFailed
		errorMessage = "persist Nmap summary: " + err.Error()
		m.appendOutput(scan.ID, "stderr", "Lantern could not ingest Nmap results: "+errorMessage+"\n")
	} else {
		m.appendOutput(scan.ID, "stdout", fmt.Sprintf(
			"Nmap completed: %d host(s) up, %d down, %d total; %d observation(s) stored.\n",
			result.HostsUp, result.HostsDown,
			result.HostsTotal, observationCount,
		))
	}
	if err := m.store.Finish(context.Background(), scan.ID, status, finishedAt, exitCode, errorMessage); err != nil {
		m.appendOutput(scan.ID, "stderr", "Lantern could not persist scan completion: "+err.Error()+"\n")
	}
	if current, err := m.store.Get(context.Background(), scan.ID); err == nil {
		m.publish(scan.ID, Event{Type: "scan", Scan: &current})
	}
}

func (m *Manager) collectProvider(ctx context.Context, scanID, target string, provider providers.Provider, availability providers.Status) {
	count, runErr := m.runProvider(ctx, scanID, providers.Request{Target: target}, provider, func(event providers.Event) error {
		if event.Evidence == nil {
			return nil
		}
		saved := *event.Evidence
		if saved.Kind == "host.observed" && saved.Subject.Type == "address" {
			address, parseErr := netip.ParseAddr(saved.Subject.Key)
			if parseErr != nil {
				return fmt.Errorf("provider emitted an invalid observed address: %w", parseErr)
			}
			var observation providers.ObservedHost
			if unmarshalErr := json.Unmarshal(saved.Payload, &observation); unmarshalErr != nil {
				return fmt.Errorf("provider emitted an invalid host observation: %w", unmarshalErr)
			}
			addressType := "ipv6"
			if address.Is4() {
				addressType = "ipv4"
			}
			var hostnames []Hostname
			if observation.Hostname != "" {
				hostnames = []Hostname{{Name: observation.Hostname, Type: "MDNS"}}
			}
			host, _, ensureErr := m.store.EnsureHost(context.Background(), scanID, Address{Address: address.String(), Type: addressType}, hostnames, observation.Reason)
			if ensureErr != nil {
				return ensureErr
			}
			m.publish(scanID, Event{Type: "host", Host: &host})
		}
		return nil
	})
	if runErr != nil {
		m.appendOutput(scanID, "stderr", fmt.Sprintf("%s provider failed: %s\n", availability.ProviderID, runErr))
		return
	}
	m.appendOutput(scanID, "stdout", fmt.Sprintf("%s provider stored %d evidence record(s).\n", availability.ProviderID, count))
}

func (m *Manager) runProvider(ctx context.Context, scanID string, request providers.Request, provider providers.Provider, observe func(providers.Event) error) (int, error) {
	descriptor := provider.Describe()
	label := descriptor.Label
	if label == "" {
		label = descriptor.ID
	}
	if descriptor.Capability != "" {
		capability := descriptor.Capability
		if strings.EqualFold(capability, "mdns") {
			capability = "mDNS"
		}
		label += " (" + capability + ")"
	}
	m.setToolActive(scanID, ToolActivity{ID: descriptor.ID, Label: label, Active: true})
	defer m.setToolActive(scanID, ToolActivity{ID: descriptor.ID, Label: label, Active: false})
	identifier, err := newID()
	if err != nil {
		return 0, fmt.Errorf("create provider run: %w", err)
	}
	run := providers.Run{
		ID: identifier, ScanID: scanID, Capability: descriptor.Capability,
		ProviderID: descriptor.ID, Label: label, Status: "running", StartedAt: time.Now().UTC(),
	}
	if err := m.store.CreateProviderRun(context.Background(), run); err != nil {
		return 0, fmt.Errorf("persist provider run: %w", err)
	}
	request.RunID = identifier
	count := 0
	runErr := provider.Run(ctx, request, func(event providers.Event) error {
		switch event.Type {
		case "log":
			stream := event.Stream
			if stream == "" {
				stream = "stdout"
			}
			m.appendOutput(scanID, stream, event.Message)
		case "progress":
			if event.Progress != nil {
				progress := Progress{Task: event.Progress.Task, Percent: event.Progress.Percent, Remaining: event.Progress.Remaining}
				m.appendOutput(scanID, "stdout", formatProgress(progress))
				m.publish(scanID, Event{Type: "progress", Progress: &progress})
			}
		case "evidence":
			if event.Evidence == nil {
				return nil
			}
			event.Evidence.ProviderRunID = identifier
			event.Evidence.ProviderID = descriptor.ID
			event.Evidence.Capability = descriptor.Capability
			saved, err := m.store.SaveEvidence(context.Background(), identifier, *event.Evidence)
			if err != nil {
				return err
			}
			saved.ProviderID = descriptor.ID
			saved.Capability = descriptor.Capability
			event.Evidence = &saved
			count++
			m.publish(scanID, Event{Type: "evidence", Evidence: &saved})
		}
		if observe != nil {
			return observe(event)
		}
		return nil
	})
	status := "completed"
	errorMessage := ""
	if runErr != nil {
		status = "failed"
		errorMessage = runErr.Error()
		if ctx.Err() != nil {
			status = "cancelled"
		}
	}
	if err := m.store.FinishProviderRun(context.Background(), identifier, status, time.Now().UTC(), errorMessage); err != nil {
		m.appendOutput(scanID, "stderr", "Lantern could not persist provider completion: "+err.Error()+"\n")
	}
	return count, runErr
}

func (m *Manager) providerOwnership(ctx context.Context, scanID, address string) *Ownership {
	if m.providers == nil {
		return nil
	}
	if !publicAddress(address) {
		return nil
	}
	selections := m.providers.ResolveAll("ownership")
	if len(selections) == 0 {
		return nil
	}
	candidates := make([]ownershipCandidate, 0, len(selections))
	for _, selection := range selections {
		var candidate *Ownership
		var confidence float64
		_, err := m.runProvider(ctx, scanID, providers.Request{Target: address}, selection.Provider, func(event providers.Event) error {
			if event.Evidence == nil {
				return nil
			}
			evidence := *event.Evidence
			if evidence.Kind != "network.registration" || evidence.Subject.Type != "address" {
				return nil
			}
			var registration providers.NetworkRegistration
			if err := json.Unmarshal(evidence.Payload, &registration); err != nil {
				return fmt.Errorf("decode network registration: %w", err)
			}
			candidate = &Ownership{
				Organization: registration.Organization, NetworkName: registration.NetworkName,
				Range: registration.Range, CIDR: registration.CIDR, City: registration.City,
				Region: registration.Region, Country: registration.Country, Origin: registration.Origin,
				Sources: []string{evidence.ProviderID},
			}
			if candidate.Sources[0] == "" {
				candidate.Sources[0] = selection.Status.ProviderID
			}
			confidence = evidence.Confidence
			return nil
		})
		if err != nil {
			m.appendOutput(scanID, "stderr", fmt.Sprintf("%s provider failed: %s\n", selection.Status.ProviderID, err))
			continue
		}
		candidates = append(candidates, ownershipCandidate{ownership: candidate, confidence: confidence})
	}
	return mergeOwnershipCandidates(candidates)
}

// ListEvidence returns provider evidence for a scan matching query.
func (m *Manager) ListEvidence(ctx context.Context, scanID string, query providers.EvidenceQuery) ([]providers.Evidence, error) {
	if _, err := m.store.Get(ctx, scanID); err != nil {
		return nil, err
	}
	return m.store.ListEvidence(ctx, scanID, query)
}

func (m *Manager) providerTargetEligible(target string) bool {
	if m.providers == nil {
		return false
	}
	var targetPrefix netip.Prefix
	if prefix, err := netip.ParsePrefix(target); err == nil {
		targetPrefix = prefix.Masked()
	} else if address, err := netip.ParseAddr(target); err == nil {
		address = address.Unmap()
		targetPrefix = netip.PrefixFrom(address, address.BitLen())
	} else {
		return false
	}
	if targetPrefix.Addr().IsLoopback() || targetPrefix.Addr().IsMulticast() {
		return false
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, local := range addresses {
		prefix, err := netip.ParsePrefix(local.String())
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if prefix.Addr().IsLoopback() || prefix.Addr().BitLen() != targetPrefix.Addr().BitLen() {
			continue
		}
		if prefix.Contains(targetPrefix.Addr()) || targetPrefix.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func (m *Manager) enrichHost(ctx context.Context, scanID string, host HostObservation) {
	select {
	case m.enrichmentSlots <- struct{}{}:
		defer func() { <-m.enrichmentSlots }()
	case <-ctx.Done():
		return
	}
	address, ok := hostIPAddress(host)
	if !ok {
		return
	}
	var hostnames []Hostname
	var certificateHostnames []Hostname
	var ownership *Ownership
	var lookups sync.WaitGroup
	lookups.Add(3)
	go func() {
		defer lookups.Done()
		hostnames = m.providerHostnames(ctx, scanID, address.Address)
	}()
	go func() {
		defer lookups.Done()
		certificateHostnames = m.providerCertificateHostnames(ctx, scanID, address.Address, host.Ports)
	}()
	go func() {
		defer lookups.Done()
		ownership = m.providerOwnership(ctx, scanID, address.Address)
	}()
	lookups.Wait()
	hostnames = mergeHostnames(certificateHostnames, hostnames)
	if len(hostnames) == 0 && ownership == nil {
		if len(httpsPorts(host.Ports)) > 0 {
			if refreshed, err := m.store.GetHost(context.Background(), scanID, host.ID); err == nil {
				m.publish(scanID, Event{Type: "host", Host: &refreshed})
			}
		}
		return
	}
	saved, err := m.store.SaveHostEnrichment(context.Background(), scanID, address, hostnames, ownership)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			m.appendOutput(scanID, "stderr", "Lantern could not persist host enrichment: "+err.Error()+"\n")
		}
		return
	}
	m.publish(scanID, Event{Type: "host", Host: &saved})
}

func httpsPorts(ports []Port) []int {
	seen := make(map[int]struct{})
	result := make([]int, 0)
	for _, port := range ports {
		if port.Protocol != "tcp" || port.State != "open" {
			continue
		}
		service := strings.ToLower(strings.TrimSpace(port.Service))
		tunnel := strings.ToLower(strings.TrimSpace(port.Tunnel))
		https := port.Number == 443 || service == "https" || strings.HasPrefix(service, "https-") ||
			strings.HasPrefix(service, "ssl/http") || (tunnel == "ssl" && (service == "http" || strings.HasPrefix(service, "http-")))
		if !https {
			continue
		}
		if _, exists := seen[port.Number]; exists {
			continue
		}
		seen[port.Number] = struct{}{}
		result = append(result, port.Number)
	}
	sort.Ints(result)
	if len(result) > maxHTTPSCertificatePorts {
		result = result[:maxHTTPSCertificatePorts]
	}
	return result
}

func normalizeUsableHostname(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 || strings.Contains(value, "*") {
		return ""
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return ""
			}
		}
	}
	return value
}

func mergeHostnames(groups ...[]Hostname) []Hostname {
	seen := make(map[string]struct{})
	var result []Hostname
	for _, group := range groups {
		for _, hostname := range group {
			key := strings.ToLower(hostname.Name)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, hostname)
		}
	}
	return result
}

func (m *Manager) enrichScanOwnership(ctx context.Context, scanID, address string) {
	select {
	case m.enrichmentSlots <- struct{}{}:
		defer func() { <-m.enrichmentSlots }()
	case <-ctx.Done():
		return
	}
	ownership := m.providerOwnership(ctx, scanID, address)
	if ownership == nil {
		return
	}
	saved, err := m.store.SaveScanOwnership(context.Background(), scanID, ownership)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			m.appendOutput(scanID, "stderr", "Lantern could not persist scan ownership: "+err.Error()+"\n")
		}
		return
	}
	m.publish(scanID, Event{Type: "scan", Scan: &saved})
}

func scanTargetIPAddress(target string) (string, bool) {
	if address, err := netip.ParseAddr(target); err == nil {
		return address.String(), true
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Masked().Addr().String(), true
	}
	return "", false
}

func hostIPAddress(host HostObservation) (Address, bool) {
	for _, address := range host.Addresses {
		if address.Type == "ipv4" || address.Type == "ipv6" {
			return address, true
		}
	}
	return Address{}, false
}

func formatProgress(progress Progress) string {
	message := progress.Task
	if message == "" {
		message = "Nmap"
	}
	if progress.Percent != "" {
		message += ": " + progress.Percent + "%"
	}
	if progress.Remaining != "" {
		message += " (about " + progress.Remaining + "s remaining)"
	}
	return message + "\n"
}

func (m *Manager) appendOutput(identifier, stream, text string) {
	if err := m.store.AppendOutput(context.Background(), identifier, text); err != nil {
		text = "Lantern could not persist output: " + err.Error() + "\n" + text
		stream = "stderr"
		m.publish(identifier, Event{Type: "output", Text: text, Stream: stream})
		return
	}
	m.publish(identifier, Event{Type: "output", Text: text, Stream: stream})
}

func (m *Manager) desiredStatus(identifier string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run, ok := m.active[identifier]; ok {
		return run.desiredStatus
	}
	return StatusInterrupted
}

func (m *Manager) setToolActive(identifier string, tool ToolActivity) {
	m.mu.Lock()
	run, ok := m.active[identifier]
	if ok {
		if run.toolRefs == nil {
			run.toolRefs = make(map[string]int)
		}
		if tool.Active {
			run.toolRefs[tool.ID]++
		} else if run.toolRefs[tool.ID] > 0 {
			run.toolRefs[tool.ID]--
		}
		tool.Active = run.toolRefs[tool.ID] > 0
		run.tools[tool.ID] = tool
	}
	m.mu.Unlock()
	if ok {
		m.publish(identifier, Event{Type: "tool", Tool: &tool})
	}
}

func (m *Manager) publish(identifier string, event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	event.ScanID = identifier
	for channel := range m.subs[identifier] {
		select {
		case channel <- event:
		default:
		}
	}
	if event.Scan != nil || event.Host != nil {
		for channel := range m.globalSubs {
			select {
			case channel <- event:
			default:
			}
		}
	}
}

func newID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// IsNotFound reports whether err represents a missing scan or profile.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
