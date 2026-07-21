package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type commandRunnerFunc func(context.Context, string, []string, time.Duration, int) (CommandResult, error)

func (function commandRunnerFunc) Run(ctx context.Context, path string, arguments []string, timeout time.Duration, limit int) (CommandResult, error) {
	return function(ctx, path, arguments, timeout, limit)
}

func executableOnPath(t *testing.T, name string) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	return path
}

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

func TestMDNSProviderMetadataAndProbes(t *testing.T) {
	for _, test := range []struct {
		name    string
		tool    string
		version string
		new     func(CommandRunner) Provider
	}{
		{name: "dns-sd", tool: "dns-sd", version: "dns-sd 1.0", new: NewDNSSDProvider},
		{name: "avahi", tool: "avahi-browse", version: "avahi 1.0", new: NewAvahiProvider},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := executableOnPath(t, test.tool)
			runner := commandRunnerFunc(func(_ context.Context, gotPath string, _ []string, _ time.Duration, _ int) (CommandResult, error) {
				if gotPath != path {
					t.Fatalf("path = %q, want %q", gotPath, path)
				}
				return CommandResult{Stderr: []byte("\n" + test.version + "\n")}, nil
			})
			provider := test.new(runner)
			descriptor := provider.Describe()
			status := provider.Probe(context.Background())
			if descriptor.Capability != "mdns" || descriptor.ID == "" || !status.Available || status.Path != path || status.Version != test.version {
				t.Fatalf("descriptor/status = %#v %#v", descriptor, status)
			}
		})
	}

	t.Run("missing and failed probe", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if status := NewDNSSDProvider(nil).Probe(context.Background()); status.Available || !strings.Contains(status.Reason, "not found") {
			t.Fatalf("missing status = %#v", status)
		}
		executableOnPath(t, "avahi-browse")
		provider := NewAvahiProvider(commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
			return CommandResult{Stderr: []byte(" probe failed\n")}, errors.New("exit")
		}))
		if status := provider.Probe(context.Background()); status.Available || status.Reason != "probe failed" || status.Path == "" {
			t.Fatalf("failed status = %#v", status)
		}
	})
}

func TestDNSSDProviderRun(t *testing.T) {
	runner := commandRunnerFunc(func(_ context.Context, _ string, arguments []string, _ time.Duration, _ int) (CommandResult, error) {
		switch arguments[0] {
		case "-B":
			return CommandResult{Stdout: []byte("12:00 Add 3 4 local. _tcp.local. _ipp\n")}, nil
		case "-Z":
			return CommandResult{Stdout: []byte("Office\\032Printer._ipp._tcp SRV 0 0 631 printer.local.\nOffice\\032Printer._ipp._tcp TXT \"ty=Office Printer\"\n")}, nil
		case "-G":
			return CommandResult{Stdout: []byte("12:00 Add 3 14 printer.local. 192.168.1.42 120\n")}, nil
		default:
			return CommandResult{}, errors.New("unexpected arguments")
		}
	})
	provider := NewDNSSDProvider(runner).(*dnsSDProvider)
	provider.path = "/fake/dns-sd"
	var events []Event
	err := provider.Run(context.Background(), Request{Target: "192.168.1.0/24"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, event := range events {
		if event.Evidence != nil {
			kinds = append(kinds, event.Evidence.Kind)
		}
	}
	if !reflect.DeepEqual(kinds, []string{"host.observed", "service.advertisement"}) || events[0].Progress == nil || events[len(events)-1].Progress.Completed != 1 {
		t.Fatalf("events = %#v", events)
	}

	if err := provider.Run(context.Background(), Request{Target: "other.local"}, nil); err != nil {
		t.Fatalf("nil emitter: %v", err)
	}
}

func TestDNSSDProviderRunErrors(t *testing.T) {
	if err := NewDNSSDProvider(nil).Run(context.Background(), Request{}, nil); err == nil {
		t.Fatal("unprobed provider succeeded")
	}
	provider := NewDNSSDProvider(commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		return CommandResult{}, errors.New("browse failed")
	})).(*dnsSDProvider)
	provider.path = "/fake/dns-sd"
	if err := provider.Run(context.Background(), Request{}, nil); err == nil || !strings.Contains(err.Error(), "browse") {
		t.Fatalf("browse error = %v", err)
	}

	provider.runner = commandRunnerFunc(func(_ context.Context, _ string, arguments []string, _ time.Duration, _ int) (CommandResult, error) {
		switch arguments[0] {
		case "-B":
			return CommandResult{Stdout: []byte("12:00 Add 3 4 local. _tcp.local. _ipp\n")}, errors.New("partial")
		case "-Z":
			return CommandResult{Stdout: []byte("Printer._ipp._tcp SRV 0 0 631 printer.local.\n")}, nil
		default:
			return CommandResult{Stdout: []byte("12:00 Add 3 14 printer.local. 192.168.1.42 120\n")}, nil
		}
	})
	want := errors.New("stop emission")
	if err := provider.Run(context.Background(), Request{Target: "192.168.1.42"}, func(Event) error { return want }); !errors.Is(err, want) {
		t.Fatalf("emitter error = %v", err)
	}
}

func TestAvahiProviderRun(t *testing.T) {
	output := `=;eth0;IPv4;Office\032Printer;_ipp._tcp;local;printer.local;192.168.1.42;631;"ty=Office Printer"`
	provider := NewAvahiProvider(commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		return CommandResult{Stdout: []byte(output)}, errors.New("partial exit")
	})).(*avahiProvider)
	provider.path = "/fake/avahi-browse"
	var events []Event
	if err := provider.Run(context.Background(), Request{Target: "printer.local"}, func(event Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Evidence.Kind != "host.observed" || events[1].Evidence.Kind != "service.advertisement" || events[2].Progress.Completed != 1 {
		t.Fatalf("events = %#v", events)
	}
	if err := provider.Run(context.Background(), Request{Target: "192.168.2.0/24"}, nil); err != nil {
		t.Fatalf("filtered nil emitter: %v", err)
	}
}

func TestAvahiProviderRunErrorsAndHelpers(t *testing.T) {
	if err := NewAvahiProvider(nil).Run(context.Background(), Request{}, nil); err == nil {
		t.Fatal("unprobed provider succeeded")
	}
	provider := NewAvahiProvider(commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		return CommandResult{}, errors.New("avahi failed")
	})).(*avahiProvider)
	provider.path = "/fake/avahi"
	if err := provider.Run(context.Background(), Request{}, nil); err == nil || !strings.Contains(err.Error(), "Avahi") {
		t.Fatalf("runner error = %v", err)
	}
	if got := commandReason(errors.New("fallback"), CommandResult{}); got != "fallback" {
		t.Fatalf("commandReason = %q", got)
	}
	if got := firstNonemptyLine([]byte("\n\x01 useful\tvalue \n")); got != " usefulvalue" {
		t.Fatalf("firstNonemptyLine = %q", got)
	}
	if err := emitObservedHost(nil, mustAddress(t, "192.168.1.2"), "host.local"); err != nil {
		t.Fatal(err)
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
