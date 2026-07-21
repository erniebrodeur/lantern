package providers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeReverseDNSResolver struct {
	names []string
	err   error
}

func (r fakeReverseDNSResolver) LookupAddr(context.Context, string) ([]string, error) {
	return r.names, r.err
}

func TestReverseDNSProviderNormalizesAndEmitsNames(t *testing.T) {
	provider := NewReverseDNSProvider(fakeReverseDNSResolver{names: []string{"Router.EXAMPLE.", "router.example", ""}})
	var evidence *Evidence
	if err := provider.Run(context.Background(), Request{Target: "192.0.2.1"}, func(event Event) error { evidence = event.Evidence; return nil }); err != nil {
		t.Fatal(err)
	}
	if evidence == nil || evidence.Kind != "dns.ptr" {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
	var result ReverseDNS
	if err := json.Unmarshal(evidence.Payload, &result); err != nil || len(result.Names) != 1 || result.Names[0] != "Router.EXAMPLE" {
		t.Fatalf("unexpected names: %#v, %v", result, err)
	}
}

func TestReverseDNSMetadataAndDefaults(t *testing.T) {
	provider := NewReverseDNSProvider(nil)
	descriptor := provider.Describe()
	status := provider.Probe(context.Background())
	if descriptor.ID != "reverse-dns" || descriptor.Capability != "reverse-dns" || !status.Available || status.Path != "native" {
		t.Fatalf("descriptor/status = %#v %#v", descriptor, status)
	}
}

func TestReverseDNSErrorsAndEmptyResults(t *testing.T) {
	if err := NewReverseDNSProvider(fakeReverseDNSResolver{}).Run(context.Background(), Request{Target: "bad"}, nil); err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Fatalf("invalid target error = %v", err)
	}
	want := errors.New("lookup failed")
	if err := NewReverseDNSProvider(fakeReverseDNSResolver{err: want}).Run(context.Background(), Request{Target: "192.0.2.1"}, nil); !errors.Is(err, want) {
		t.Fatalf("lookup error = %v", err)
	}
	if err := NewReverseDNSProvider(fakeReverseDNSResolver{names: []string{"", "."}}).Run(context.Background(), Request{Target: "192.0.2.1"}, nil); err != nil {
		t.Fatalf("empty result = %v", err)
	}
	want = errors.New("emit failed")
	provider := NewReverseDNSProvider(fakeReverseDNSResolver{names: []string{"host.example."}})
	if err := provider.Run(context.Background(), Request{Target: "::ffff:192.0.2.1"}, func(Event) error { return want }); !errors.Is(err, want) {
		t.Fatalf("emit error = %v", err)
	}
}
