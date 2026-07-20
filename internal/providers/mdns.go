package providers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	mdnsCapability        = "mdns"
	mdnsOutputLimit       = 1024 * 1024
	mdnsCollectionLimit   = 10 * time.Second
	mdnsBrowseLimit       = 1500 * time.Millisecond
	mdnsQueryLimit        = 1800 * time.Millisecond
	maxMDNSServiceTypes   = 64
	maxMDNSAdvertisements = 512
)

type ServiceAdvertisement struct {
	Instance       string            `json:"instance"`
	ServiceType    string            `json:"serviceType"`
	Domain         string            `json:"domain"`
	Hostname       string            `json:"hostname"`
	Port           uint16            `json:"port"`
	TXT            map[string]string `json:"txt,omitempty"`
	Interface      string            `json:"interface,omitempty"`
	InterfaceIndex int               `json:"interfaceIndex,omitempty"`
}

type dnsSDProvider struct {
	runner CommandRunner
	mu     sync.RWMutex
	path   string
}

func NewDNSSDProvider(runner CommandRunner) Provider {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &dnsSDProvider{runner: runner}
}

func (p *dnsSDProvider) Describe() Descriptor {
	return Descriptor{
		ID: "dns-sd", Capability: mdnsCapability, Label: "Bonjour DNS-SD",
		SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 100},
	}
}

func (p *dnsSDProvider) Probe(ctx context.Context) Status {
	status := Status{Capability: mdnsCapability, ProviderID: "dns-sd", Label: "Bonjour DNS-SD", Status: "unavailable"}
	path := ResolveExecutable("", "dns-sd", nil)
	if path == "" {
		status.Reason = "dns-sd was not found on PATH"
		return status
	}
	result, err := p.runner.Run(ctx, path, []string{"-V"}, 2*time.Second, 64*1024)
	if err != nil {
		status.Path = path
		status.Reason = commandReason(err, result)
		return status
	}
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()
	status.Available = true
	status.Status = "available"
	status.Path = path
	status.Version = firstNonemptyLine(result.Stdout, result.Stderr)
	return status
}

func (p *dnsSDProvider) Run(parent context.Context, request Request, emit EmitFunc) error {
	p.mu.RLock()
	path := p.path
	p.mu.RUnlock()
	if path == "" {
		return errors.New("dns-sd provider has not passed its availability probe")
	}
	ctx, cancel := context.WithTimeout(parent, mdnsCollectionLimit)
	defer cancel()

	meta, err := p.runner.Run(ctx, path, []string{"-B", "_services._dns-sd._udp", "local."}, mdnsBrowseLimit, mdnsOutputLimit)
	if err != nil && len(meta.Stdout) == 0 {
		return fmt.Errorf("browse DNS-SD service types: %w", err)
	}
	serviceTypes := parseDNSSDServiceTypes(string(meta.Stdout))
	if len(serviceTypes) > maxMDNSServiceTypes {
		serviceTypes = serviceTypes[:maxMDNSServiceTypes]
	}
	if emit != nil {
		_ = emit(Event{Type: "progress", Progress: &Progress{Phase: "browse", Total: len(serviceTypes)}})
	}

	type zoneResult struct {
		advertisements []ServiceAdvertisement
	}
	zones := make(chan zoneResult, len(serviceTypes))
	semaphore := make(chan struct{}, 8)
	var queries sync.WaitGroup
	for _, serviceType := range serviceTypes {
		serviceType := serviceType
		queries.Add(1)
		go func() {
			defer queries.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			result, runErr := p.runner.Run(ctx, path, []string{"-Z", serviceType, "local."}, mdnsQueryLimit, mdnsOutputLimit)
			if runErr != nil && len(result.Stdout) == 0 {
				return
			}
			zones <- zoneResult{advertisements: parseDNSSDZone(string(result.Stdout), serviceType)}
		}()
	}
	queries.Wait()
	close(zones)

	advertisements := make([]ServiceAdvertisement, 0)
	for result := range zones {
		advertisements = append(advertisements, result.advertisements...)
		if len(advertisements) >= maxMDNSAdvertisements {
			advertisements = advertisements[:maxMDNSAdvertisements]
			break
		}
	}
	addresses := p.resolveHosts(ctx, path, advertisements)
	emitted := 0
	seen := make(map[string]struct{})
	seenHosts := make(map[string]struct{})
	for _, advertisement := range advertisements {
		for _, resolved := range addresses[normalizeHostname(advertisement.Hostname)] {
			if !mdnsTargetMatches(request.Target, advertisement.Hostname, resolved.address) {
				continue
			}
			advertisement.InterfaceIndex = resolved.interfaceIndex
			if _, observed := seenHosts[resolved.address.String()]; !observed {
				if err := emitObservedHost(emit, resolved.address, advertisement.Hostname); err != nil {
					return err
				}
				seenHosts[resolved.address.String()] = struct{}{}
			}
			encoded, marshalErr := json.Marshal(advertisement)
			if marshalErr != nil {
				return marshalErr
			}
			key := resolved.address.String() + "\x00" + advertisement.ServiceType + "\x00" + advertisement.Instance
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			evidence := Evidence{
				Kind: "service.advertisement", Subject: EntityRef{Type: "address", Key: resolved.address.String()},
				PayloadVersion: 1, Payload: encoded, ObservedAt: time.Now().UTC(), Confidence: 1,
			}
			if emit != nil {
				if emitErr := emit(Event{Type: "evidence", Evidence: &evidence}); emitErr != nil {
					return emitErr
				}
			}
			emitted++
		}
	}
	if emit != nil {
		_ = emit(Event{Type: "progress", Progress: &Progress{Phase: "complete", Completed: emitted, Total: emitted}})
	}
	return nil
}

type resolvedAddress struct {
	address        netip.Addr
	interfaceIndex int
}

func (p *dnsSDProvider) resolveHosts(ctx context.Context, path string, advertisements []ServiceAdvertisement) map[string][]resolvedAddress {
	hosts := make(map[string]string)
	for _, advertisement := range advertisements {
		if normalized := normalizeHostname(advertisement.Hostname); normalized != "" {
			hosts[normalized] = advertisement.Hostname
		}
	}
	type hostResult struct {
		host      string
		addresses []resolvedAddress
	}
	results := make(chan hostResult, len(hosts))
	semaphore := make(chan struct{}, 8)
	var wait sync.WaitGroup
	for normalized, hostname := range hosts {
		normalized, hostname := normalized, hostname
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			result, err := p.runner.Run(ctx, path, []string{"-G", "v4v6", hostname}, mdnsQueryLimit, mdnsOutputLimit)
			if err != nil && len(result.Stdout) == 0 {
				return
			}
			results <- hostResult{host: normalized, addresses: parseDNSSDAddresses(string(result.Stdout))}
		}()
	}
	wait.Wait()
	close(results)
	resolved := make(map[string][]resolvedAddress)
	for result := range results {
		resolved[result.host] = result.addresses
	}
	return resolved
}

type avahiProvider struct {
	runner CommandRunner
	mu     sync.RWMutex
	path   string
}

func NewAvahiProvider(runner CommandRunner) Provider {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &avahiProvider{runner: runner}
}

func (p *avahiProvider) Describe() Descriptor {
	return Descriptor{
		ID: "avahi", Capability: mdnsCapability, Label: "Avahi",
		SupportedOS: []string{"linux"}, OSPriorities: map[string]int{"linux": 100},
	}
}

func (p *avahiProvider) Probe(ctx context.Context) Status {
	status := Status{Capability: mdnsCapability, ProviderID: "avahi", Label: "Avahi", Status: "unavailable"}
	path := ResolveExecutable("", "avahi-browse", nil)
	if path == "" {
		status.Reason = "avahi-browse was not found on PATH"
		return status
	}
	result, err := p.runner.Run(ctx, path, []string{"--version"}, 2*time.Second, 64*1024)
	if err != nil {
		status.Path = path
		status.Reason = commandReason(err, result)
		return status
	}
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()
	status.Available = true
	status.Status = "available"
	status.Path = path
	status.Version = firstNonemptyLine(result.Stdout, result.Stderr)
	return status
}

func (p *avahiProvider) Run(ctx context.Context, request Request, emit EmitFunc) error {
	p.mu.RLock()
	path := p.path
	p.mu.RUnlock()
	if path == "" {
		return errors.New("Avahi provider has not passed its availability probe")
	}
	result, err := p.runner.Run(ctx, path, []string{"--all", "--resolve", "--parsable", "--terminate"}, mdnsCollectionLimit, mdnsOutputLimit)
	if err != nil && len(result.Stdout) == 0 {
		return fmt.Errorf("browse Avahi services: %w", err)
	}
	advertisements := parseAvahiBrowse(string(result.Stdout))
	emitted := 0
	seenHosts := make(map[string]struct{})
	for _, record := range advertisements {
		if !mdnsTargetMatches(request.Target, record.advertisement.Hostname, record.address) {
			continue
		}
		if _, observed := seenHosts[record.address.String()]; !observed {
			if err := emitObservedHost(emit, record.address, record.advertisement.Hostname); err != nil {
				return err
			}
			seenHosts[record.address.String()] = struct{}{}
		}
		encoded, marshalErr := json.Marshal(record.advertisement)
		if marshalErr != nil {
			return marshalErr
		}
		evidence := Evidence{
			Kind: "service.advertisement", Subject: EntityRef{Type: "address", Key: record.address.String()},
			PayloadVersion: 1, Payload: encoded, ObservedAt: time.Now().UTC(), Confidence: 1,
		}
		if emit != nil {
			if emitErr := emit(Event{Type: "evidence", Evidence: &evidence}); emitErr != nil {
				return emitErr
			}
		}
		emitted++
	}
	if emit != nil {
		_ = emit(Event{Type: "progress", Progress: &Progress{Phase: "complete", Completed: emitted, Total: emitted}})
	}
	return nil
}

func emitObservedHost(emit EmitFunc, address netip.Addr, hostname string) error {
	if emit == nil {
		return nil
	}
	payload, err := json.Marshal(ObservedHost{Hostname: hostname, Reason: "mdns-response"})
	if err != nil {
		return err
	}
	evidence := Evidence{
		Kind: "host.observed", Subject: EntityRef{Type: "address", Key: address.String()},
		PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
	}
	return emit(Event{Type: "evidence", Evidence: &evidence})
}

func parseDNSSDServiceTypes(output string) []string {
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[1] != "Add" {
			continue
		}
		transport := fields[len(fields)-2]
		name := fields[len(fields)-1]
		if !strings.HasPrefix(name, "_") || (!strings.HasPrefix(transport, "_tcp.") && !strings.HasPrefix(transport, "_udp.")) {
			continue
		}
		protocol := strings.SplitN(transport, ".", 2)[0]
		serviceType := name + "." + protocol
		if len(serviceType) <= 255 {
			seen[serviceType] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for serviceType := range seen {
		result = append(result, serviceType)
	}
	sort.Strings(result)
	return result
}

func parseDNSSDZone(output, serviceType string) []ServiceAdvertisement {
	records := make(map[string]*ServiceAdvertisement)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch {
		case len(fields) >= 6 && fields[1] == "SRV":
			port, err := strconv.ParseUint(fields[4], 10, 16)
			if err != nil {
				continue
			}
			owner := fields[0]
			instance := decodeDNSEscapes(strings.TrimSuffix(owner, "."+serviceType))
			if instance == owner || instance == "" {
				continue
			}
			records[owner] = &ServiceAdvertisement{
				Instance: instance, ServiceType: serviceType, Domain: "local.",
				Hostname: fields[5], Port: uint16(port), TXT: make(map[string]string),
			}
		case fields[1] == "TXT":
			owner := fields[0]
			record := records[owner]
			if record == nil {
				continue
			}
			for _, value := range quotedValues(line) {
				key, item, found := strings.Cut(value, "=")
				if found && key != "" && len(key) <= 255 && len(item) <= 4096 {
					record.TXT[key] = item
				}
			}
		}
	}
	result := make([]ServiceAdvertisement, 0, len(records))
	for _, record := range records {
		result = append(result, *record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ServiceType != result[j].ServiceType {
			return result[i].ServiceType < result[j].ServiceType
		}
		return result[i].Instance < result[j].Instance
	})
	return result
}

func quotedValues(line string) []string {
	var result []string
	for index := 0; index < len(line); index++ {
		if line[index] != '"' {
			continue
		}
		start := index
		index++
		for index < len(line) {
			if line[index] == '\\' {
				index += 2
				continue
			}
			if line[index] == '"' {
				quoted := line[start : index+1]
				if value, err := strconv.Unquote(quoted); err == nil {
					result = append(result, value)
				}
				break
			}
			index++
		}
	}
	return result
}

func parseDNSSDAddresses(output string) []resolvedAddress {
	seen := make(map[netip.Addr]struct{})
	var result []resolvedAddress
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[1] != "Add" {
			continue
		}
		interfaceIndex, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		rawAddress := fields[5]
		if zone := strings.IndexByte(rawAddress, '%'); zone >= 0 {
			rawAddress = rawAddress[:zone]
		}
		address, err := netip.ParseAddr(rawAddress)
		if err != nil || !address.IsValid() {
			continue
		}
		address = address.Unmap()
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, resolvedAddress{address: address, interfaceIndex: interfaceIndex})
	}
	return result
}

type avahiRecord struct {
	advertisement ServiceAdvertisement
	address       netip.Addr
}

func parseAvahiBrowse(output string) []avahiRecord {
	var result []avahiRecord
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ";")
		if len(fields) < 9 || fields[0] != "=" {
			continue
		}
		address, err := netip.ParseAddr(strings.SplitN(fields[7], "%", 2)[0])
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(fields[8], 10, 16)
		if err != nil {
			continue
		}
		txt := make(map[string]string)
		if len(fields) > 9 {
			for _, item := range quotedValues(strings.Join(fields[9:], ";")) {
				key, value, found := strings.Cut(decodeDNSEscapes(item), "=")
				if found && key != "" {
					txt[key] = value
				}
			}
		}
		result = append(result, avahiRecord{
			address: address.Unmap(),
			advertisement: ServiceAdvertisement{
				Instance: decodeDNSEscapes(fields[3]), ServiceType: fields[4], Domain: fields[5],
				Hostname: decodeDNSEscapes(fields[6]), Port: uint16(port), TXT: txt, Interface: fields[1],
			},
		})
		if len(result) >= maxMDNSAdvertisements {
			break
		}
	}
	return result
}

func decodeDNSEscapes(value string) string {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 >= len(value) {
			result.WriteByte(value[index])
			continue
		}
		if index+3 < len(value) && isASCIIDigit(value[index+1]) && isASCIIDigit(value[index+2]) && isASCIIDigit(value[index+3]) {
			number, err := strconv.Atoi(value[index+1 : index+4])
			if err == nil && number <= 255 {
				result.WriteByte(byte(number))
				index += 3
				continue
			}
		}
		index++
		result.WriteByte(value[index])
	}
	return result.String()
}

func isASCIIDigit(value byte) bool { return value >= '0' && value <= '9' }

func mdnsTargetMatches(target, hostname string, address netip.Addr) bool {
	target = strings.TrimSpace(target)
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Contains(address)
	}
	if parsed, err := netip.ParseAddr(target); err == nil {
		return parsed.Unmap() == address.Unmap()
	}
	return strings.EqualFold(normalizeHostname(target), normalizeHostname(hostname))
}

func normalizeHostname(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func commandReason(err error, result CommandResult) string {
	message := firstNonemptyLine(result.Stderr, result.Stdout)
	if message != "" {
		return message
	}
	return err.Error()
}

func firstNonemptyLine(values ...[]byte) string {
	for _, value := range values {
		scanner := bufio.NewScanner(strings.NewReader(string(value)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				return strings.Map(func(character rune) rune {
					if unicode.IsControl(character) {
						return -1
					}
					return character
				}, line)
			}
		}
	}
	return ""
}
