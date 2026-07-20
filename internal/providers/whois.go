package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	whoisTimeout   = 5 * time.Second
	maxWHOISOutput = 2 * 1024 * 1024
)

type whoisProvider struct {
	runner     CommandRunner
	configured string
	mu         sync.RWMutex
	path       string
	lookup     sync.Mutex
	cache      []whoisCacheEntry
}

type whoisCacheEntry struct {
	prefix       netip.Prefix
	registration *NetworkRegistration
	expiresAt    time.Time
}

// NewWHOISProvider returns an ownership provider backed by a WHOIS command.
func NewWHOISProvider(runner CommandRunner, configuredPath string) Provider {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &whoisProvider{runner: runner, configured: strings.TrimSpace(configuredPath)}
}

func (p *whoisProvider) Describe() Descriptor {
	return Descriptor{
		ID: "whois", Capability: rdapCapability, Label: "WHOIS",
		SupportedOS: []string{"darwin", "linux"}, OSPriorities: map[string]int{"darwin": 50, "linux": 50},
	}
}

func (p *whoisProvider) Probe(context.Context) Status {
	status := Status{Capability: rdapCapability, ProviderID: "whois", Label: "WHOIS", Status: "unavailable"}
	path := ResolveExecutable(p.configured, "whois", []string{"/usr/bin/whois", "/usr/local/bin/whois", "/opt/homebrew/bin/whois"})
	if path == "" {
		status.Reason = "whois was not found on PATH"
		return status
	}
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()
	status.Available = true
	status.Status = "available"
	status.Path = path
	return status
}

func (p *whoisProvider) Run(ctx context.Context, request Request, emit EmitFunc) error {
	address, err := netip.ParseAddr(request.Target)
	if err != nil {
		return fmt.Errorf("WHOIS target must be an IP address: %w", err)
	}
	address = address.Unmap()
	if !isPublicAddress(address) {
		return nil
	}
	if registration, ok := p.cached(address); ok {
		return emitRegistrationEvidence(address, registration, 0.8, emit)
	}
	p.lookup.Lock()
	defer p.lookup.Unlock()
	if registration, ok := p.cached(address); ok {
		return emitRegistrationEvidence(address, registration, 0.8, emit)
	}
	p.mu.RLock()
	path := p.path
	p.mu.RUnlock()
	if path == "" {
		return errors.New("WHOIS provider has not passed its availability probe")
	}
	result, err := p.runner.Run(ctx, path, []string{address.String()}, whoisTimeout, maxWHOISOutput)
	if err != nil {
		return err
	}
	registration := parseWHOIS(result.Stdout)
	p.cacheRegistration(address, registration)
	return emitRegistrationEvidence(address, registration, 0.8, emit)
}

func emitRegistrationEvidence(address netip.Addr, registration *NetworkRegistration, confidence float64, emit EmitFunc) error {
	if registration == nil {
		return nil
	}
	payload, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	return emit(Event{Type: "evidence", Evidence: &Evidence{
		Kind: "network.registration", Subject: EntityRef{Type: "address", Key: address.String()},
		PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: confidence,
	}})
}

func (p *whoisProvider) cached(address netip.Addr) (*NetworkRegistration, bool) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := 0; index < len(p.cache); {
		entry := p.cache[index]
		if !now.Before(entry.expiresAt) {
			p.cache = append(p.cache[:index], p.cache[index+1:]...)
			continue
		}
		if entry.prefix.Contains(address) {
			return entry.registration, true
		}
		index++
	}
	return nil, false
}

func (p *whoisProvider) cacheRegistration(address netip.Addr, registration *NetworkRegistration) {
	prefix := netip.PrefixFrom(address, address.BitLen())
	ttl := rdapNegativeCacheTTL
	if registration != nil {
		ttl = rdapPositiveCacheTTL
		for _, value := range strings.Split(registration.CIDR, ",") {
			candidate, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err == nil && candidate.Contains(address) {
				prefix = candidate.Masked()
				break
			}
		}
	}
	p.mu.Lock()
	p.cache = append(p.cache, whoisCacheEntry{prefix: prefix, registration: registration, expiresAt: time.Now().Add(ttl)})
	p.mu.Unlock()
}

func parseWHOIS(output []byte) *NetworkRegistration {
	fields := make(map[string][]string)
	for _, rawLine := range bytes.Split(output, []byte{'\n'}) {
		line := strings.TrimSpace(string(rawLine))
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(value) == "" {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		fields[key] = append(fields[key], strings.TrimSpace(value))
	}
	first := func(keys ...string) string {
		for _, key := range keys {
			for _, value := range fields[key] {
				if value != "" {
					return value
				}
			}
		}
		return ""
	}
	registration := &NetworkRegistration{
		Organization: first("orgname", "org-name", "organization", "owner", "org", "descr"),
		NetworkName:  first("netname", "network-name"),
		Range:        first("netrange", "inetnum", "inet6num"),
		CIDR:         first("cidr", "route", "route6"),
		City:         first("city", "locality"),
		Region:       first("stateprov", "state", "province", "region"),
		Country:      first("country"),
		Origin:       first("originas", "origin"),
	}
	if registration.Organization == "" && registration.NetworkName == "" && registration.Range == "" && registration.CIDR == "" {
		return nil
	}
	return registration
}
