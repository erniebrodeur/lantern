package providers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Registry probes providers and resolves the best available implementation of
// each capability for the current operating system.
type Registry struct {
	goos      string
	lookupEnv func(string) string
	providers []Provider

	mu          sync.RWMutex
	selected    map[string]Provider
	available   map[string][]Selection
	statuses    map[string]Status
	diagnostics []Status
}

// NewRegistry constructs and probes a provider registry for goos.
func NewRegistry(goos string, lookupEnv func(string) string, available ...Provider) *Registry {
	return &Registry{
		goos:      goos,
		lookupEnv: lookupEnv,
		providers: append([]Provider(nil), available...),
		selected:  make(map[string]Provider),
		available: make(map[string][]Selection),
		statuses:  make(map[string]Status),
	}
}

// Register adds providers to the registry and probes them.
func (r *Registry) Register(additional ...Provider) {
	r.mu.Lock()
	r.providers = append(r.providers, additional...)
	r.mu.Unlock()
}

// Refresh probes every registered provider again.
func (r *Registry) Refresh(ctx context.Context) {
	r.mu.RLock()
	registered := append([]Provider(nil), r.providers...)
	r.mu.RUnlock()
	capabilities := make(map[string][]Provider)
	for _, current := range registered {
		descriptor := current.Describe()
		if supportsOS(descriptor, r.goos) {
			capabilities[descriptor.Capability] = append(capabilities[descriptor.Capability], current)
		}
	}

	selected := make(map[string]Provider)
	available := make(map[string][]Selection)
	statuses := make(map[string]Status)
	diagnostics := make([]Status, 0, len(registered))
	for capability, candidates := range capabilities {
		override := ""
		if r.lookupEnv != nil {
			override = strings.TrimSpace(r.lookupEnv(providerOverrideName(capability)))
		}
		if strings.EqualFold(override, "disabled") {
			statuses[capability] = Status{Capability: capability, OS: r.goos, Status: "disabled", Reason: "disabled by configuration"}
			diagnostics = append(diagnostics, statuses[capability])
			continue
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			return candidates[i].Describe().OSPriorities[r.goos] > candidates[j].Describe().OSPriorities[r.goos]
		})
		if override != "" {
			filtered := candidates[:0]
			for _, candidate := range candidates {
				if candidate.Describe().ID == override {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
			if len(candidates) == 0 {
				statuses[capability] = Status{Capability: capability, ProviderID: override, OS: r.goos, Status: "unavailable", Reason: fmt.Sprintf("configured provider %q is not supported on %s", override, r.goos)}
				diagnostics = append(diagnostics, statuses[capability])
				continue
			}
		}

		var last Status
		for _, candidate := range candidates {
			last = candidate.Probe(ctx)
			last.Capability = capability
			last.OS = r.goos
			diagnostics = append(diagnostics, last)
			if last.Available {
				available[capability] = append(available[capability], Selection{Provider: candidate, Status: last})
			}
		}
		if len(available[capability]) > 0 {
			selected[capability] = available[capability][0].Provider
			statuses[capability] = available[capability][0].Status
		}
		if _, ok := statuses[capability]; !ok {
			if last.Capability == "" {
				last = Status{Capability: capability, OS: r.goos, Status: "unavailable", Reason: "no compatible provider is available"}
			}
			statuses[capability] = last
		}
	}

	r.mu.Lock()
	r.selected = selected
	r.available = available
	r.statuses = statuses
	r.diagnostics = diagnostics
	r.mu.Unlock()
}

// ResolveAll returns all available providers for capability in priority order.
func (r *Registry) ResolveAll(capability string) []Selection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Selection(nil), r.available[capability]...)
}

// Resolve returns the highest-priority available provider for capability.
func (r *Registry) Resolve(capability string) (Provider, Status, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	provider, ok := r.selected[capability]
	return provider, r.statuses[capability], ok
}

// Statuses returns a snapshot of all provider probe results.
func (r *Registry) Statuses() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := append([]Status(nil), r.diagnostics...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Capability != result[j].Capability {
			return result[i].Capability < result[j].Capability
		}
		return result[i].ProviderID < result[j].ProviderID
	})
	return result
}

func supportsOS(descriptor Descriptor, goos string) bool {
	for _, supported := range descriptor.SupportedOS {
		if supported == goos {
			return true
		}
	}
	return false
}

func providerOverrideName(capability string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return "LANTERN_" + strings.ToUpper(replacer.Replace(capability)) + "_PROVIDER"
}
