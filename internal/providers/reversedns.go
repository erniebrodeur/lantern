package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const reverseDNSTimeout = 2 * time.Second

type ReverseDNSResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
}

type ReverseDNS struct {
	Names []string `json:"names"`
}

type reverseDNSProvider struct {
	resolver ReverseDNSResolver
}

func NewReverseDNSProvider(resolver ReverseDNSResolver) Provider {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &reverseDNSProvider{resolver: resolver}
}

func (p *reverseDNSProvider) Describe() Descriptor {
	return Descriptor{
		ID: "reverse-dns", Capability: "reverse-dns", Label: "Reverse DNS",
		SupportedOS: []string{"darwin", "linux"}, OSPriorities: map[string]int{"darwin": 100, "linux": 100},
	}
}

func (p *reverseDNSProvider) Probe(context.Context) Status {
	return Status{Capability: "reverse-dns", ProviderID: "reverse-dns", Label: "Reverse DNS", Status: "available", Available: true, Path: "native"}
}

func (p *reverseDNSProvider) Run(parent context.Context, request Request, emit EmitFunc) error {
	address, err := netip.ParseAddr(request.Target)
	if err != nil {
		return fmt.Errorf("reverse DNS target must be an IP address: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, reverseDNSTimeout)
	defer cancel()
	names, lookupErr := p.resolver.LookupAddr(ctx, address.Unmap().String())
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".")
		key := strings.ToLower(name)
		if name == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		if lookupErr != nil {
			return lookupErr
		}
		return nil
	}
	payload, err := json.Marshal(ReverseDNS{Names: normalized})
	if err != nil {
		return err
	}
	return emit(Event{Type: "evidence", Evidence: &Evidence{
		Kind: "dns.ptr", Subject: EntityRef{Type: "address", Key: address.Unmap().String()},
		PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
	}})
}
