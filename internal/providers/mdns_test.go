package providers

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestParseDNSSDServiceTypes(t *testing.T) {
	output := `Browsing for _services._dns-sd._udp.local.
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
 9:37:57.905  Add        3  14 .                    _tcp.local.          _airplay
 9:37:58.180  Add        3  14 .                    _tcp.local.          _ipp
 9:37:58.180  Add        3  14 .                    _tcp.local.          _ipp
 9:37:58.180  Rmv        3  14 .                    _tcp.local.          _http
`
	got := parseDNSSDServiceTypes(output)
	if len(got) != 2 || got[0] != "_airplay._tcp" || got[1] != "_ipp._tcp" {
		t.Fatalf("unexpected service types: %#v", got)
	}
}

func TestParseDNSSDZoneAndAddresses(t *testing.T) {
	zone := `_ipp._tcp PTR EPSON\032ET-2980\032Series._ipp._tcp
EPSON\032ET-2980\032Series._ipp._tcp SRV 0 0 631 EPSONF61764.local.
EPSON\032ET-2980\032Series._ipp._tcp TXT "txtvers=1" "ty=EPSON ET-2980 Series" "note="
`
	records := parseDNSSDZone(zone, "_ipp._tcp")
	if len(records) != 1 {
		t.Fatalf("unexpected records: %#v", records)
	}
	record := records[0]
	if record.Instance != "EPSON ET-2980 Series" || record.Hostname != "EPSONF61764.local." || record.Port != 631 || record.TXT["ty"] != "EPSON ET-2980 Series" {
		t.Fatalf("unexpected record: %#v", record)
	}
	addresses := parseDNSSDAddresses(`Timestamp A/R Flags IF Hostname Address TTL
 9:38:43.728 Add 40000003 14 EPSONF61764.local. FE80:0000:0000:0000:6A55:D4FF:FEF6:1764%en0 120
 9:38:43.728 Add 40000002 14 EPSONF61764.local. 10.10.13.97 120
`)
	if len(addresses) != 2 || addresses[1].address.String() != "10.10.13.97" || addresses[1].interfaceIndex != 14 {
		t.Fatalf("unexpected addresses: %#v", addresses)
	}
}

func TestParseAvahiBrowse(t *testing.T) {
	output := `+;eth0;IPv4;Office\032Printer;_ipp._tcp;local
=;eth0;IPv4;Office\032Printer;_ipp._tcp;local;printer.local;192.168.1.42;631;"txtvers=1" "ty=Office Printer"
`
	records := parseAvahiBrowse(output)
	if len(records) != 1 {
		t.Fatalf("unexpected records: %#v", records)
	}
	record := records[0]
	if record.address.String() != "192.168.1.42" || record.advertisement.Instance != "Office Printer" || record.advertisement.Port != 631 || record.advertisement.TXT["ty"] != "Office Printer" {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestMDNSTargetMatches(t *testing.T) {
	address := mustAddress(t, "192.168.1.42")
	if !mdnsTargetMatches("192.168.1.0/24", "printer.local.", address) {
		t.Fatal("expected CIDR match")
	}
	if !mdnsTargetMatches("printer.local", "printer.local.", address) {
		t.Fatal("expected hostname match")
	}
	if mdnsTargetMatches("192.168.2.0/24", "printer.local.", address) {
		t.Fatal("unexpected CIDR match")
	}
}

func TestEvidencePayloadIsJSON(t *testing.T) {
	encoded, err := json.Marshal(ServiceAdvertisement{Instance: "Printer", ServiceType: "_ipp._tcp", Port: 631})
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("invalid payload: %s, %v", encoded, err)
	}
}

func TestDNSSDIntegration(t *testing.T) {
	if os.Getenv("LANTERN_MDNS_INTEGRATION") != "1" {
		t.Skip("set LANTERN_MDNS_INTEGRATION=1 to browse the local multicast domain")
	}
	target, ok := integrationTarget(t)
	if !ok {
		t.Skip("no non-loopback IPv4 interface is available")
	}
	provider := NewDNSSDProvider(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status := provider.Probe(ctx)
	if !status.Available {
		t.Fatalf("dns-sd is unavailable: %s", status.Reason)
	}
	count := 0
	err := provider.Run(ctx, Request{RunID: "integration", Target: target.String()}, func(event Event) error {
		if event.Type == "evidence" && event.Evidence != nil {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("dns-sd returned no service advertisements in %s", target)
	}
}

func integrationTarget(t *testing.T) (netip.Prefix, bool) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
			return prefix.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

func mustAddress(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

type fakeProvider struct {
	descriptor Descriptor
	available  bool
}

func (p fakeProvider) Describe() Descriptor { return p.descriptor }
func (p fakeProvider) Probe(context.Context) Status {
	status := Status{ProviderID: p.descriptor.ID, Label: p.descriptor.Label, Status: "unavailable"}
	if p.available {
		status.Available = true
		status.Status = "available"
	}
	return status
}
func (fakeProvider) Run(context.Context, Request, EmitFunc) error { return nil }

func TestRegistrySelectsAvailableProviderByOSPriority(t *testing.T) {
	registry := NewRegistry("darwin", func(string) string { return "" },
		fakeProvider{descriptor: Descriptor{ID: "fallback", Capability: "mdns", SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 10}}, available: true},
		fakeProvider{descriptor: Descriptor{ID: "preferred", Capability: "mdns", SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 100}}, available: true},
	)
	registry.Refresh(context.Background())
	_, status, ok := registry.Resolve("mdns")
	if !ok || status.ProviderID != "preferred" {
		t.Fatalf("unexpected selection: %#v, %v", status, ok)
	}
	selections := registry.ResolveAll("mdns")
	if len(selections) != 2 || selections[0].Status.ProviderID != "preferred" || selections[1].Status.ProviderID != "fallback" {
		t.Fatalf("unexpected fallback order: %#v", selections)
	}
}

func TestRegistryHonorsProviderOverride(t *testing.T) {
	registry := NewRegistry("darwin", func(name string) string {
		if name == "LANTERN_MDNS_PROVIDER" {
			return "fallback"
		}
		return ""
	},
		fakeProvider{descriptor: Descriptor{ID: "fallback", Capability: "mdns", SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 10}}, available: true},
		fakeProvider{descriptor: Descriptor{ID: "preferred", Capability: "mdns", SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 100}}, available: true},
	)
	registry.Refresh(context.Background())
	_, status, ok := registry.Resolve("mdns")
	if !ok || status.ProviderID != "fallback" {
		t.Fatalf("unexpected selection: %#v, %v", status, ok)
	}
}
