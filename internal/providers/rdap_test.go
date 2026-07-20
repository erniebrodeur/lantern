package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

const testRDAPResponse = `{
  "handle": "NET-8-8-8-0-1",
  "name": "GOOGLE",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "country": null,
  "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
  "entities": [{
    "roles": ["registrant"],
    "vcardArray": ["vcard", [
      ["fn", {}, "text", "Google LLC"],
      ["adr", {"label": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"}, "text", ["", "", "", "", "", "", ""]]
    ]]
  }]
}`

func TestParseRDAPNetworkAndRegistrantLocation(t *testing.T) {
	registration, prefix, err := parseRDAP([]byte(testRDAPResponse), netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if registration == nil || registration.Organization != "Google LLC" || registration.NetworkName != "GOOGLE" || registration.CIDR != "8.8.8.0/24" || registration.City != "Mountain View" || registration.Region != "CA" || registration.Country != "United States" {
		t.Fatalf("unexpected registration: %#v", registration)
	}
	if prefix.String() != "8.8.8.0/24" {
		t.Fatalf("unexpected prefix: %s", prefix)
	}
}

func TestRDAPProviderEmitsEvidenceAndCachesNetwork(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/rdap+json"}},
			Body:       io.NopCloser(strings.NewReader(testRDAPResponse)),
			Request:    request,
		}, nil
	})}

	provider := NewRDAPProvider(client, "https://rdap.example.test/ip/")
	for _, address := range []string{"8.8.8.8", "8.8.8.9"} {
		var emitted *Evidence
		err := provider.Run(context.Background(), Request{Target: address}, func(event Event) error {
			emitted = event.Evidence
			return nil
		})
		if err != nil || emitted == nil || emitted.Kind != "network.registration" || emitted.Subject.Key != address {
			t.Fatalf("run %s: %#v, %v", address, emitted, err)
		}
		var registration NetworkRegistration
		if err := json.Unmarshal(emitted.Payload, &registration); err != nil || registration.City != "Mountain View" {
			t.Fatalf("payload %s: %#v, %v", address, registration, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one RDAP request, got %d", requests.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRDAPProviderSkipsPrivateAddresses(t *testing.T) {
	provider := NewRDAPProvider(http.DefaultClient, "https://example.invalid/ip/")
	called := false
	if err := provider.Run(context.Background(), Request{Target: "192.168.1.2"}, func(Event) error { called = true; return nil }); err != nil || called {
		t.Fatalf("private lookup emitted evidence: called=%v err=%v", called, err)
	}
}
