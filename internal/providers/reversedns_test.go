package providers

import (
	"context"
	"encoding/json"
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
