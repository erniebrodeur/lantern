package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseWHOISRegistration(t *testing.T) {
	result := parseWHOIS([]byte(`
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
OrgName:        Google LLC
City:           Mountain View
StateProv:      CA
Country:        US
OriginAS:       AS15169
`))
	if result == nil || result.Organization != "Google LLC" || result.NetworkName != "GOGL" || result.CIDR != "8.8.8.0/24" || result.City != "Mountain View" || result.Region != "CA" || result.Country != "US" || result.Origin != "AS15169" {
		t.Fatalf("unexpected registration: %#v", result)
	}
}

func TestWHOISMetadataAndProbe(t *testing.T) {
	path := executableOnPath(t, "whois")
	provider := NewWHOISProvider(nil, "")
	descriptor := provider.Describe()
	status := provider.Probe(context.Background())
	if descriptor.ID != "whois" || descriptor.Capability != "ownership" || !status.Available || status.Path != path {
		t.Fatalf("descriptor/status = %#v %#v", descriptor, status)
	}
	t.Setenv("PATH", t.TempDir())
	provider = NewWHOISProvider(nil, "/missing/whois")
	if status := provider.Probe(context.Background()); status.Available || !strings.Contains(status.Reason, "not found") {
		t.Fatalf("missing status = %#v", status)
	}
}

func TestWHOISRunAndCache(t *testing.T) {
	var calls atomic.Int32
	runner := commandRunnerFunc(func(_ context.Context, _ string, arguments []string, timeout time.Duration, limit int) (CommandResult, error) {
		calls.Add(1)
		if len(arguments) != 1 || timeout != whoisTimeout || limit != maxWHOISOutput {
			t.Fatalf("call = %#v %v %d", arguments, timeout, limit)
		}
		return CommandResult{Stdout: []byte("OrgName: Example Inc\nCIDR: 8.8.8.0/24\nCountry: US\n")}, nil
	})
	provider := NewWHOISProvider(runner, "").(*whoisProvider)
	provider.path = "/fake/whois"
	for _, target := range []string{"8.8.8.8", "8.8.8.9"} {
		var evidence *Evidence
		if err := provider.Run(context.Background(), Request{Target: target}, func(event Event) error { evidence = event.Evidence; return nil }); err != nil {
			t.Fatal(err)
		}
		var registration NetworkRegistration
		if evidence == nil || evidence.Confidence != 0.8 || json.Unmarshal(evidence.Payload, &registration) != nil || registration.Organization != "Example Inc" {
			t.Fatalf("evidence = %#v", evidence)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("runner calls = %d", calls.Load())
	}
}

func TestWHOISRunErrorsAndNegativeCache(t *testing.T) {
	provider := NewWHOISProvider(nil, "").(*whoisProvider)
	if err := provider.Run(context.Background(), Request{Target: "bad"}, nil); err == nil {
		t.Fatal("invalid target succeeded")
	}
	if err := provider.Run(context.Background(), Request{Target: "192.168.1.1"}, nil); err != nil {
		t.Fatalf("private address = %v", err)
	}
	if err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, nil); err == nil || !strings.Contains(err.Error(), "probe") {
		t.Fatalf("unprobed error = %v", err)
	}

	want := errors.New("runner failed")
	provider.runner = commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		return CommandResult{}, want
	})
	provider.path = "/fake/whois"
	if err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, nil); !errors.Is(err, want) {
		t.Fatalf("runner error = %v", err)
	}

	var calls atomic.Int32
	provider = NewWHOISProvider(commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		calls.Add(1)
		return CommandResult{Stdout: []byte("comments only\n")}, nil
	}), "").(*whoisProvider)
	provider.path = "/fake/whois"
	for range 2 {
		if err := provider.Run(context.Background(), Request{Target: "9.9.9.9"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("negative-cache calls = %d", calls.Load())
	}

	want = errors.New("emit failed")
	provider.cache = nil
	provider.runner = commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		return CommandResult{Stdout: []byte("NetName: Quad9\n")}, nil
	})
	if err := provider.Run(context.Background(), Request{Target: "9.9.9.10"}, func(Event) error { return want }); !errors.Is(err, want) {
		t.Fatalf("emit error = %v", err)
	}
}

func TestWHOISCacheExpirationAndPrefixes(t *testing.T) {
	provider := &whoisProvider{}
	address := netip.MustParseAddr("8.8.8.8")
	provider.cache = []whoisCacheEntry{{prefix: netip.MustParsePrefix("8.8.8.0/24"), registration: &NetworkRegistration{NetworkName: "expired"}, expiresAt: time.Now().Add(-time.Second)}}
	if _, ok := provider.cached(address); ok || len(provider.cache) != 0 {
		t.Fatalf("expired cache = %#v", provider.cache)
	}
	provider.cacheRegistration(address, &NetworkRegistration{CIDR: "bad, 8.8.8.0/24", NetworkName: "active"})
	if registration, ok := provider.cached(netip.MustParseAddr("8.8.8.9")); !ok || registration.NetworkName != "active" {
		t.Fatalf("cached registration = %#v %v", registration, ok)
	}
}
