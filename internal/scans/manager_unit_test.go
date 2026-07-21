package scans

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
)

type stubStore struct {
	Store
	err              error
	scans            []Scan
	scan             Scan
	profiles         []Profile
	profile          Profile
	host             HostObservation
	page             HostPage
	routes           RouteMap
	tools            []ToolActivity
	evidence         []providers.Evidence
	createdProfile   Profile
	updatedProfile   Profile
	createdRun       providers.Run
	finishedRun      string
	outputs          []string
	savedEvidence    providers.Evidence
	ensuredAddress   Address
	ensuredHostnames []Hostname
}

func (s *stubStore) InterruptRunning(context.Context, time.Time) error { return s.err }
func (s *stubStore) Create(context.Context, Scan) error                { return s.err }
func (s *stubStore) List(context.Context) ([]Scan, error)              { return s.scans, s.err }
func (s *stubStore) Get(context.Context, string) (Scan, error)         { return s.scan, s.err }
func (s *stubStore) Delete(context.Context, string) error              { return s.err }
func (s *stubStore) ListProfiles(context.Context) ([]Profile, error)   { return s.profiles, s.err }
func (s *stubStore) GetProfile(context.Context, string) (Profile, error) {
	return s.profile, s.err
}
func (s *stubStore) CreateProfile(_ context.Context, profile Profile) error {
	s.createdProfile = profile
	return s.err
}
func (s *stubStore) UpdateProfile(_ context.Context, profile Profile) error {
	s.updatedProfile = profile
	return s.err
}
func (s *stubStore) DeleteProfile(context.Context, string) error { return s.err }
func (s *stubStore) ListHosts(context.Context, string, int, int) (HostPage, error) {
	return s.page, s.err
}
func (s *stubStore) GetHost(context.Context, string, int64) (HostObservation, error) {
	return s.host, s.err
}
func (s *stubStore) SaveHostEnrichment(context.Context, string, Address, []Hostname, *Ownership) (HostObservation, error) {
	return s.host, s.err
}
func (s *stubStore) SaveScanOwnership(context.Context, string, *Ownership) (Scan, error) {
	return s.scan, s.err
}
func (s *stubStore) SaveRoute(context.Context, string, HostRoute) error { return s.err }
func (s *stubStore) ListRoutes(context.Context, string) (RouteMap, error) {
	return s.routes, s.err
}
func (s *stubStore) ListEvidence(context.Context, string, providers.EvidenceQuery) ([]providers.Evidence, error) {
	return s.evidence, s.err
}
func (s *stubStore) ListTools(context.Context, string) ([]ToolActivity, error) {
	return s.tools, s.err
}
func (s *stubStore) CreateProviderRun(_ context.Context, run providers.Run) error {
	s.createdRun = run
	return s.err
}
func (s *stubStore) FinishProviderRun(_ context.Context, _ string, status string, _ time.Time, _ string) error {
	s.finishedRun = status
	return s.err
}
func (s *stubStore) SaveEvidence(_ context.Context, _ string, evidence providers.Evidence) (providers.Evidence, error) {
	evidence.ID = 7
	s.savedEvidence = evidence
	return evidence, s.err
}
func (s *stubStore) EnsureHost(_ context.Context, _ string, address Address, hostnames []Hostname, _ string) (HostObservation, bool, error) {
	s.ensuredAddress = address
	s.ensuredHostnames = hostnames
	return s.host, true, s.err
}
func (s *stubStore) AppendOutput(_ context.Context, _ string, output string) error {
	s.outputs = append(s.outputs, output)
	return s.err
}

type unitProvider struct {
	descriptor providers.Descriptor
	status     providers.Status
	run        func(context.Context, providers.Request, providers.EmitFunc) error
}

func (p unitProvider) Describe() providers.Descriptor { return p.descriptor }
func (p unitProvider) Probe(context.Context) providers.Status {
	return p.status
}
func (p unitProvider) Run(ctx context.Context, request providers.Request, emit providers.EmitFunc) error {
	if p.run != nil {
		return p.run(ctx, request, emit)
	}
	return nil
}

func unitManager(store Store, registry *providers.Registry) *Manager {
	return &Manager{
		store: store, active: make(map[string]*activeRun), subs: make(map[string]map[chan Event]struct{}),
		globalSubs: make(map[chan Event]struct{}), routeSlots: make(chan struct{}, 1),
		enrichmentSlots: make(chan struct{}, 2), providers: registry,
	}
}

func TestNewManagerAndCapabilities(t *testing.T) {
	want := errors.New("interrupt failed")
	if _, err := NewManagerWithProviders(&stubStore{err: want}, "missing", nil); err == nil || !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("constructor error = %v", err)
	}
	store := &stubStore{}
	registry := providers.NewRegistry(runtime.GOOS, nil,
		unitProvider{descriptor: providers.Descriptor{ID: "route", Capability: "route", SupportedOS: []string{runtime.GOOS}, OSPriorities: map[string]int{runtime.GOOS: 1}}, status: providers.Status{ProviderID: "route", Available: true, Status: "available"}},
	)
	manager, err := NewManagerWithProviders(store, "missing", registry)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := manager.Capabilities()
	if !capabilities.RouteMapping || capabilities.RouteTool != "route" || !capabilities.ToolActivity || len(capabilities.Providers) == 0 {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	if len(manager.RefreshProviders(context.Background())) == 0 {
		t.Fatal("refresh returned no statuses")
	}
	manager.providers = nil
	capabilities = manager.Capabilities()
	if capabilities.Providers == nil || capabilities.RouteMapping || capabilities.RouteMappingReason == "" || len(manager.RefreshProviders(context.Background())) != 0 {
		t.Fatalf("empty capabilities = %#v", capabilities)
	}
}

func TestNmapProviderRejectsInvalidInvocation(t *testing.T) {
	provider := &nmapProvider{}
	if err := provider.Run(context.Background(), providers.Request{Arguments: []string{"-sn"}}, func(providers.Event) error { return nil }); err == nil {
		t.Fatal("unprobed provider ran")
	}
	provider.path = "/bin/true"
	if err := provider.Run(context.Background(), providers.Request{}, func(providers.Event) error { return nil }); err == nil {
		t.Fatal("provider accepted empty arguments")
	}
}

func TestManagerProfilesAndDelegation(t *testing.T) {
	now := time.Now().UTC()
	store := &stubStore{
		scans: []Scan{{ID: "scan"}}, scan: Scan{ID: "scan"}, profiles: []Profile{{ID: "custom"}},
		profile: Profile{ID: "custom", CreatedAt: &now}, page: HostPage{Total: 1},
		host:   HostObservation{ID: 3, Ownership: &Ownership{Organization: "known"}},
		routes: RouteMap{Tool: "route"}, evidence: []providers.Evidence{{ID: 1}}, tools: []ToolActivity{{ID: "stored", Label: "Stored"}},
	}
	manager := unitManager(store, nil)
	profiles, err := manager.Profiles(context.Background())
	if err != nil || len(profiles) != len(BuiltInProfiles())+1 {
		t.Fatalf("profiles = %#v %v", profiles, err)
	}
	created, err := manager.SaveProfile(context.Background(), "", "-sn")
	if err != nil || created.ID == "" || store.createdProfile.ID != created.ID {
		t.Fatalf("created = %#v %v", created, err)
	}
	updated, err := manager.SaveProfile(context.Background(), "custom", "-sT")
	if err != nil || updated.CreatedAt != &now || store.updatedProfile.ID != "custom" {
		t.Fatalf("updated = %#v %v", updated, err)
	}
	if _, err := manager.SaveProfile(context.Background(), DefaultProfileID, "-sn"); err == nil {
		t.Fatal("updated built-in profile")
	}
	if err := manager.DeleteProfile(context.Background(), DefaultProfileID); err == nil {
		t.Fatal("deleted built-in profile")
	}
	if err := manager.DeleteProfile(context.Background(), "custom"); err != nil {
		t.Fatal(err)
	}
	if scans, err := manager.List(context.Background()); err != nil || len(scans) != 1 {
		t.Fatalf("list = %#v %v", scans, err)
	}
	if scan, err := manager.Get(context.Background(), "scan"); err != nil || scan.ID != "scan" {
		t.Fatalf("get = %#v %v", scan, err)
	}
	if page, err := manager.ListHosts(context.Background(), "scan", 10, 0); err != nil || page.Total != 1 {
		t.Fatalf("hosts = %#v %v", page, err)
	}
	if host, err := manager.GetHost(context.Background(), "scan", 3); err != nil || host.ID != 3 {
		t.Fatalf("host = %#v %v", host, err)
	}
	if evidence, err := manager.ListEvidence(context.Background(), "scan", providers.EvidenceQuery{}); err != nil || len(evidence) != 1 {
		t.Fatalf("evidence = %#v %v", evidence, err)
	}
	if routes, err := manager.SavedRoutes(context.Background(), "scan"); err != nil || routes.Tool != "route" {
		t.Fatalf("routes = %#v %v", routes, err)
	}
	if err := manager.Delete(context.Background(), "scan"); err != nil {
		t.Fatal(err)
	}
}

func TestManagerStartValidationAndState(t *testing.T) {
	store := &stubStore{}
	manager := unitManager(store, nil)
	if _, err := manager.Start(context.Background(), "bad target!"); err == nil {
		t.Fatal("invalid target succeeded")
	}
	store.err = ErrNotFound
	if _, err := manager.StartRequest(context.Background(), ScanRequest{Target: "127.0.0.1", ProfileID: "missing"}); err == nil {
		t.Fatal("missing profile succeeded")
	}
	store.err = nil
	manager.store = &stubStore{profile: Profile{ID: "custom", Arguments: []string{"-oX"}}}
	if _, err := manager.StartRequest(context.Background(), ScanRequest{Target: "127.0.0.1", ProfileID: "custom"}); err == nil {
		t.Fatal("invalid profile arguments succeeded")
	}
	manager.store = &stubStore{}
	if _, err := manager.StartRequest(context.Background(), ScanRequest{Target: "127.0.0.1", OSDetection: true}); !errors.Is(err, ErrPrivilegeRequired) {
		t.Fatalf("privilege error = %v", err)
	}
	manager.closing = true
	if _, err := manager.Start(context.Background(), "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Fatalf("closing error = %v", err)
	}
	manager.closing = false
	manager.store = &stubStore{err: errors.New("create failed")}
	if _, err := manager.Start(context.Background(), "127.0.0.1"); err == nil || len(manager.active) != 0 {
		t.Fatalf("create error = %v active=%d", err, len(manager.active))
	}
}

func TestManagerToolsDeleteAndSubscriptions(t *testing.T) {
	store := &stubStore{tools: []ToolActivity{{ID: "z", Label: "Zulu"}, {ID: "nmap", Label: "Nmap"}}}
	manager := unitManager(store, nil)
	manager.active["scan"] = &activeRun{cancel: func() {}, desiredStatus: StatusCancelled, tools: map[string]ToolActivity{"a": {ID: "a", Label: "Alpha", Active: true}}, toolRefs: make(map[string]int)}
	tools, err := manager.ListTools(context.Background(), "scan")
	if err != nil || len(tools) != 3 || tools[0].ID != "nmap" {
		t.Fatalf("tools = %#v %v", tools, err)
	}
	if err := manager.Delete(context.Background(), "scan"); !errors.Is(err, ErrScanActive) {
		t.Fatalf("active delete = %v", err)
	}
	channel, unsubscribe := manager.Subscribe("scan")
	global, unsubscribeGlobal := manager.SubscribeAll()
	manager.publish("scan", Event{Type: "progress", Progress: &Progress{Task: "work"}})
	if event := <-channel; event.ScanID != "scan" || event.Type != "progress" {
		t.Fatalf("scan event = %#v", event)
	}
	select {
	case event := <-global:
		t.Fatalf("global received progress: %#v", event)
	default:
	}
	manager.publish("scan", Event{Type: "scan", Scan: &Scan{ID: "scan"}})
	<-channel
	if event := <-global; event.ScanID != "scan" {
		t.Fatalf("global event = %#v", event)
	}
	unsubscribe()
	unsubscribe()
	unsubscribeGlobal()
	unsubscribeGlobal()
	if len(manager.subs) != 0 || len(manager.globalSubs) != 0 {
		t.Fatalf("subscriptions remain: %#v %#v", manager.subs, manager.globalSubs)
	}
	if err := manager.Cancel("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel missing = %v", err)
	}
	if err := manager.Cancel("scan"); err != nil || manager.desiredStatus("scan") != StatusCancelled {
		t.Fatalf("cancel = %v", err)
	}
}

func TestManagerRunProviderAndOutput(t *testing.T) {
	store := &stubStore{}
	manager := unitManager(store, nil)
	manager.active["scan"] = &activeRun{tools: make(map[string]ToolActivity), toolRefs: make(map[string]int)}
	provider := unitProvider{
		descriptor: providers.Descriptor{ID: "unit", Capability: "mdns"},
		run: func(_ context.Context, request providers.Request, emit providers.EmitFunc) error {
			if request.RunID == "" {
				t.Fatal("missing run ID")
			}
			_ = emit(providers.Event{Type: "log", Message: "hello\n"})
			_ = emit(providers.Event{Type: "progress", Progress: &providers.Progress{Percent: "50", Remaining: "2"}})
			return emit(providers.Event{Type: "evidence", Evidence: &providers.Evidence{Kind: "unit", PayloadVersion: 1, Payload: []byte(`{}`), ObservedAt: time.Now(), Confidence: 1}})
		},
	}
	count, err := manager.runProvider(context.Background(), "scan", providers.Request{}, provider, nil)
	if err != nil || count != 1 || store.createdRun.Label != "unit (mDNS)" || store.finishedRun != "completed" || store.savedEvidence.ProviderID != "unit" || len(store.outputs) != 2 {
		t.Fatalf("run = %d %v store=%#v", count, err, store)
	}
	if tools := manager.ActiveTools("scan"); len(tools) != 1 || tools[0].Active {
		t.Fatalf("active tools = %#v", tools)
	}

	store.err = errors.New("persist failed")
	if _, err := manager.runProvider(context.Background(), "scan", providers.Request{}, provider, nil); err == nil || !strings.Contains(err.Error(), "persist provider") {
		t.Fatalf("persist error = %v", err)
	}
	store.err = nil
	want := errors.New("provider failed")
	provider.run = func(context.Context, providers.Request, providers.EmitFunc) error { return want }
	if _, err := manager.runProvider(context.Background(), "scan", providers.Request{}, provider, nil); !errors.Is(err, want) || store.finishedRun != "failed" {
		t.Fatalf("provider error = %v status=%q", err, store.finishedRun)
	}

	store.err = errors.New("append failed")
	events, unsubscribe := manager.Subscribe("scan")
	defer unsubscribe()
	manager.appendOutput("scan", "stdout", "original\n")
	if event := <-events; event.Stream != "stderr" || !strings.Contains(event.Text, "could not persist") {
		t.Fatalf("fallback output = %#v", event)
	}
}

func TestManagerProviderObservationAndHelpers(t *testing.T) {
	store := &stubStore{host: HostObservation{ID: 4}}
	manager := unitManager(store, nil)
	manager.active["scan"] = &activeRun{tools: make(map[string]ToolActivity), toolRefs: make(map[string]int)}
	provider := unitProvider{
		descriptor: providers.Descriptor{ID: "observer", Capability: "mdns"},
		run: func(_ context.Context, _ providers.Request, emit providers.EmitFunc) error {
			payload, _ := json.Marshal(providers.ObservedHost{Hostname: "host.local", Reason: "mdns"})
			return emit(providers.Event{Type: "evidence", Evidence: &providers.Evidence{
				Kind: "host.observed", Subject: providers.EntityRef{Type: "address", Key: "192.168.1.2"}, PayloadVersion: 1, Payload: payload, ObservedAt: time.Now(), Confidence: 1,
			}})
		},
	}
	manager.collectProvider(context.Background(), "scan", "192.168.1.0/24", provider, providers.Status{ProviderID: "observer"})
	if store.ensuredAddress.Address != "192.168.1.2" || len(store.ensuredHostnames) != 1 {
		t.Fatalf("ensured = %#v %#v", store.ensuredAddress, store.ensuredHostnames)
	}

	provider.run = func(_ context.Context, _ providers.Request, emit providers.EmitFunc) error {
		return emit(providers.Event{Type: "evidence", Evidence: &providers.Evidence{Kind: "host.observed", Subject: providers.EntityRef{Type: "address", Key: "bad"}, PayloadVersion: 1, Payload: []byte(`{}`)}})
	}
	manager.collectProvider(context.Background(), "scan", "target", provider, providers.Status{ProviderID: "observer"})
	if !strings.Contains(store.outputs[len(store.outputs)-1], "invalid observed address") {
		t.Fatalf("provider failure output = %#v", store.outputs)
	}

	if got := formatProgress(Progress{}); got != "Nmap\n" {
		t.Fatalf("default progress = %q", got)
	}
	if got := formatProgress(Progress{Task: "Task", Percent: "25", Remaining: "3"}); got != "Task: 25% (about 3s remaining)\n" {
		t.Fatalf("progress = %q", got)
	}
	if address, ok := hostIPAddress(HostObservation{Addresses: []Address{{Type: "mac"}, {Type: "ipv6", Address: "::1"}}}); !ok || address.Type != "ipv6" {
		t.Fatalf("host address = %#v %v", address, ok)
	}
	if _, ok := hostIPAddress(HostObservation{}); ok {
		t.Fatal("empty host had IP")
	}
	for _, target := range []string{"127.0.0.1", "224.0.0.1", "bad"} {
		if manager.providerTargetEligible(target) {
			t.Fatalf("target %q eligible", target)
		}
	}
	if !IsNotFound(ErrNotFound) || IsNotFound(errors.New("other")) {
		t.Fatal("IsNotFound mismatch")
	}
}

func TestManagerShutdownPaths(t *testing.T) {
	manager := unitManager(&stubStore{}, nil)
	cancelled := false
	manager.active["scan"] = &activeRun{cancel: func() { cancelled = true }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager.Shutdown(ctx)
	if !cancelled || !manager.closing || manager.active["scan"].desiredStatus != StatusInterrupted {
		t.Fatalf("shutdown state = %#v", manager.active["scan"])
	}
	manager = unitManager(&stubStore{}, nil)
	manager.Shutdown(context.Background())
}

func TestRouteValidationBranches(t *testing.T) {
	emptyRegistry := providers.NewRegistry(runtime.GOOS, nil)
	emptyRegistry.Refresh(context.Background())
	manager := unitManager(&stubStore{}, emptyRegistry)
	if _, err := manager.Route(context.Background(), "scan", "192.168.1.2"); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("no-provider error = %v", err)
	}

	registry := providers.NewRegistry(runtime.GOOS, nil, unitProvider{
		descriptor: providers.Descriptor{ID: "route", Capability: "route", SupportedOS: []string{runtime.GOOS}},
		status:     providers.Status{ProviderID: "route", Available: true, Status: "available"},
	})
	registry.Refresh(context.Background())
	manager = unitManager(&stubStore{}, registry)
	if _, err := manager.Route(context.Background(), "scan", "not-an-ip"); err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Fatalf("invalid-target error = %v", err)
	}
	manager.store = &stubStore{err: ErrNotFound}
	if _, err := manager.Route(context.Background(), "scan", "192.168.1.2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing-scan error = %v", err)
	}
	manager.store = &stubStore{scan: Scan{ID: "scan"}, page: HostPage{Items: []HostSummary{{State: "down", Address: "192.168.1.2"}}}}
	if _, err := manager.Route(context.Background(), "scan", "192.168.1.2"); err == nil || !strings.Contains(err.Error(), "not an observed up host") {
		t.Fatalf("unobserved error = %v", err)
	}
}
