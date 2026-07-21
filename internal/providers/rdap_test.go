package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

func TestRDAPMetadataDefaultsAndRedirects(t *testing.T) {
	provider := NewRDAPProvider(nil, "  ").(*rdapProvider)
	descriptor := provider.Describe()
	status := provider.Probe(context.Background())
	if descriptor.ID != "rdap" || descriptor.Capability != "ownership" || !status.Available || status.Path != defaultRDAPBaseURL || provider.client.Timeout != rdapTimeout {
		t.Fatalf("descriptor/status/client = %#v %#v %#v", descriptor, status, provider.client)
	}
	httpsRequest, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err := provider.client.CheckRedirect(httpsRequest, nil); err != nil {
		t.Fatalf("HTTPS redirect = %v", err)
	}
	httpRequest, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if err := provider.client.CheckRedirect(httpRequest, nil); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("HTTP redirect = %v", err)
	}
	if err := provider.client.CheckRedirect(httpsRequest, make([]*http.Request, 5)); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("redirect limit = %v", err)
	}
}

func TestRDAPLookupErrorsAndEmptyRegistration(t *testing.T) {
	if err := NewRDAPProvider(http.DefaultClient, "https://example.invalid").Run(context.Background(), Request{Target: "bad"}, nil); err == nil {
		t.Fatal("invalid target succeeded")
	}

	tests := []struct {
		name     string
		response *http.Response
		err      error
		want     string
	}{
		{name: "transport", err: errors.New("offline"), want: "RDAP lookup"},
		{name: "status", response: rdapResponse(http.StatusTooManyRequests, "rate limited"), want: "Too Many Requests"},
		{name: "read", response: &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(errorReader{})}, want: "read RDAP"},
		{name: "oversized", response: rdapResponse(http.StatusOK, strings.Repeat("x", maxRDAPOutput+1)), want: "exceeded"},
		{name: "malformed", response: rdapResponse(http.StatusOK, "{"), want: "decode RDAP"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if test.response != nil {
					test.response.Request = request
				}
				return test.response, test.err
			})}
			provider := NewRDAPProvider(client, "https://rdap.example/ip")
			err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, func(Event) error { return nil })
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		response := rdapResponse(http.StatusOK, `{}`)
		response.Request = request
		return response, nil
	})}
	provider := NewRDAPProvider(client, "https://rdap.example/ip")
	for range 2 {
		if err := provider.Run(context.Background(), Request{Target: "8.8.4.4"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("negative cache calls = %d", calls.Load())
	}
}

func TestRDAPEmitterCacheAndParserEdges(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := rdapResponse(http.StatusOK, testRDAPResponse)
		response.Request = request
		return response, nil
	})}
	want := errors.New("emit failed")
	provider := NewRDAPProvider(client, "https://rdap.example/ip").(*rdapProvider)
	if err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, func(Event) error { return want }); !errors.Is(err, want) {
		t.Fatalf("emit error = %v", err)
	}
	provider.cache = []rdapCacheEntry{{prefix: netip.MustParsePrefix("8.8.8.0/24"), registration: &NetworkRegistration{NetworkName: "expired"}, expiresAt: time.Now().Add(-time.Second)}}
	if _, ok := provider.cached(netip.MustParseAddr("8.8.8.9")); ok || len(provider.cache) != 0 {
		t.Fatalf("expired cache = %#v", provider.cache)
	}

	address := netip.MustParseAddr("2001:4860:4860::8888")
	prefix, cidr := rdapPrefix([]rdapCIDR{{V6Prefix: "bad", Length: 32}, {V6Prefix: "2001:4860::", Length: 32}, {V6Prefix: "2001:4860:4860::", Length: 48}}, address)
	if !prefix.IsValid() || cidr != "2001:4860:4860::/48" {
		t.Fatalf("prefix = %v %q", prefix, cidr)
	}
	if score := rdapRoleScore([]string{"abuse", "technical", "administrative"}); score != 60 || rdapRoleScore([]string{"registrant"}) != 100 || rdapRoleScore(nil) != 10 {
		t.Fatalf("role score = %d", score)
	}
	if city, region, country := parseRDAPAddressLabel("City\nRegion\n12345\nCountry"); city != "City" || region != "Region" || country != "Country" {
		t.Fatalf("address label = %q %q %q", city, region, country)
	}
	if city, region, country := parseRDAPAddressLabel("Country"); city != "" || region != "" || country != "Country" {
		t.Fatalf("short label = %q %q %q", city, region, country)
	}
	if got := rdapString(json.RawMessage(`["Example","Inc"]`)); got != "Example Inc" {
		t.Fatalf("array string = %q", got)
	}
	if got := rdapString(json.RawMessage(`123`)); got != "" {
		t.Fatalf("invalid string = %q", got)
	}
	for _, test := range []struct{ start, end, want string }{
		{end: "2", want: "2"}, {start: "1", want: "1"}, {start: "1", end: "1", want: "1"}, {start: "1", end: "2", want: "1 - 2"},
	} {
		if got := formatAddressRange(test.start, test.end); got != test.want {
			t.Fatalf("range(%q,%q) = %q", test.start, test.end, got)
		}
	}
	if got := rdapFirstNonempty("", " value "); got != "value" || rdapFirstNonempty(" ") != "" {
		t.Fatalf("first nonempty = %q", got)
	}
}

func rdapResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (errorReader) Close() error             { return nil }
