package scans_test

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/store"
)

type evidenceProvider struct{}

type blockingProvider struct {
	started chan struct{}
	release chan struct{}
}

func (provider *blockingProvider) Describe() providers.Descriptor {
	return providers.Descriptor{ID: "test-mdns", Capability: "mdns", Label: "Test mDNS", SupportedOS: []string{runtime.GOOS}, OSPriorities: map[string]int{runtime.GOOS: 100}}
}

func (provider *blockingProvider) Probe(context.Context) providers.Status {
	return providers.Status{ProviderID: "test-mdns", Label: "Test mDNS", Status: "available", Available: true}
}

func (provider *blockingProvider) Run(ctx context.Context, _ providers.Request, _ providers.EmitFunc) error {
	close(provider.started)
	select {
	case <-provider.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (evidenceProvider) Describe() providers.Descriptor {
	return providers.Descriptor{ID: "test-mdns", Capability: "mdns", Label: "Test mDNS", SupportedOS: []string{runtime.GOOS}, OSPriorities: map[string]int{runtime.GOOS: 100}}
}

func (evidenceProvider) Probe(context.Context) providers.Status {
	return providers.Status{ProviderID: "test-mdns", Label: "Test mDNS", Status: "available", Available: true}
}

func (evidenceProvider) Run(_ context.Context, request providers.Request, emit providers.EmitFunc) error {
	prefix, err := netip.ParsePrefix(request.Target)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(providers.ServiceAdvertisement{Instance: "Test Printer", ServiceType: "_ipp._tcp", Hostname: "printer.local.", Port: 631})
	if err != nil {
		return err
	}
	evidence := providers.Evidence{
		Kind: "service.advertisement", Subject: providers.EntityRef{Type: "address", Key: prefix.Addr().String()},
		PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
	}
	return emit(providers.Event{Type: "evidence", Evidence: &evidence})
}

func TestManagerRunsScannerAndPersistsOutput(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	script := filepath.Join(directory, "fake-nmap")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+sampleNmapXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})

	started, err := manager.Start(context.Background(), "printer.local")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current, err := manager.Get(context.Background(), started.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == scans.StatusCompleted {
			if !strings.Contains(current.Output, "1 host(s) up") {
				t.Fatalf("unexpected output: %q", current.Output)
			}
			if !strings.Contains(strings.Join(current.Arguments, " "), "--top-ports 100") || current.Arguments[len(current.Arguments)-1] != "printer.local" {
				t.Fatalf("unexpected arguments: %#v", current.Arguments)
			}
			page, err := manager.ListHosts(context.Background(), started.ID, 20, 0)
			if err != nil || page.Total != 1 || page.Items[0].Address != "192.168.1.42" {
				t.Fatalf("unexpected hosts: %#v, %v", page, err)
			}
			evidence, err := manager.ListEvidence(context.Background(), started.ID, providers.EvidenceQuery{Kind: "scan.summary", Limit: 20})
			if err != nil || len(evidence) != 1 || evidence[0].ProviderID != "nmap" || evidence[0].Capability != "scan" {
				t.Fatalf("Nmap did not use provider evidence: %#v, %v", evidence, err)
			}
			tools, err := manager.ListTools(context.Background(), started.ID)
			if err != nil || !hasTool(tools, "nmap", false) {
				t.Fatalf("Nmap provider run missing from tool history: %#v, %v", tools, err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scanner did not complete")
}

func hasTool(tools []scans.ToolActivity, identifier string, active bool) bool {
	for _, tool := range tools {
		if tool.ID == identifier && tool.Active == active {
			return true
		}
	}
	return false
}

func TestManagerRunsSelectedProviderAndPersistsEvidence(t *testing.T) {
	prefix, ok := nonLoopbackPrefix(t)
	if !ok {
		t.Skip("no non-loopback interface is available")
	}
	directory := t.TempDir()
	script := filepath.Join(directory, "fake-nmap")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+sampleNmapXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	registry := providers.NewRegistry(runtime.GOOS, func(string) string { return "" }, evidenceProvider{})
	manager, err := scans.NewManagerWithProviders(database, script, registry)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})
	started, err := manager.Start(context.Background(), prefix.String())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current, err := manager.Get(context.Background(), started.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == scans.StatusCompleted {
			evidence, err := manager.ListEvidence(context.Background(), started.ID, providers.EvidenceQuery{Kind: "service.advertisement", Limit: 20})
			if err != nil || len(evidence) != 1 || evidence[0].ProviderID != "test-mdns" {
				t.Fatalf("unexpected provider evidence: %#v, %v", evidence, err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scanner did not complete")
}

func TestManagerReportsActiveMDNSTool(t *testing.T) {
	prefix, ok := nonLoopbackPrefix(t)
	if !ok {
		t.Skip("no non-loopback interface is available")
	}
	directory := t.TempDir()
	script := filepath.Join(directory, "fake-nmap")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+sampleNmapXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	provider := &blockingProvider{started: make(chan struct{}), release: make(chan struct{})}
	registry := providers.NewRegistry(runtime.GOOS, func(string) string { return "" }, provider)
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManagerWithProviders(database, script, registry)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})
	started, err := manager.Start(context.Background(), prefix.String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("mDNS provider did not start")
	}
	tools := manager.ActiveTools(started.ID)
	found := false
	for _, tool := range tools {
		found = found || tool.ID == "test-mdns" && tool.Active && strings.Contains(tool.Label, "mDNS")
	}
	if !found {
		t.Fatalf("active mDNS tool not reported: %#v", tools)
	}
	close(provider.release)
	waitForStatus(t, manager, started.ID, scans.StatusCompleted, 2*time.Second)
	tools, err = manager.ListTools(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, tool := range tools {
		found = found || tool.ID == "test-mdns" && !tool.Active
	}
	if !found {
		t.Fatalf("completed zero-result mDNS run not reported: %#v", tools)
	}
}

func nonLoopbackPrefix(t *testing.T) (netip.Prefix, bool) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && !prefix.Addr().IsLoopback() {
			return prefix.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

func TestManagerRunsConcurrentScansAndPublishesGlobalLifecycle(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	script := filepath.Join(directory, "fake-nmap")
	contents := "#!/bin/sh\nsleep 0.2\nprintf '%s\\n' '" + sampleNmapXML + "'\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})

	events, unsubscribe := manager.SubscribeAll()
	defer unsubscribe()
	first, err := manager.Start(context.Background(), "first.local")
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Start(context.Background(), "second.local")
	if err != nil {
		t.Fatalf("second concurrent scan was rejected: %v", err)
	}
	want := map[string]bool{first.ID: false, second.ID: false}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Scan != nil && event.Scan.Status == scans.StatusCompleted {
				if _, ok := want[event.Scan.ID]; ok {
					want[event.Scan.ID] = true
				}
			}
			if want[first.ID] && want[second.ID] {
				return
			}
		case <-deadline:
			t.Fatalf("missing completed lifecycle events: %#v", want)
		}
	}
}

func TestManagerResolvesAndSnapshotsCustomProfile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	script := filepath.Join(directory, "fake-nmap")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+sampleNmapXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})

	profile, err := manager.SaveProfile(context.Background(), "", "-sT -p 80,443 --reason")
	if err != nil {
		t.Fatal(err)
	}
	started, err := manager.StartRequest(context.Background(), scans.ScanRequest{Target: "printer.local", ProfileID: profile.ID})
	if err != nil {
		t.Fatal(err)
	}
	current := waitForStatus(t, manager, started.ID, scans.StatusCompleted, 2*time.Second)
	want := []string{"-sT", "-p", "80,443", "--reason", "--stats-every", "1s", "-oX", "-", "printer.local"}
	if current.ProfileID != profile.ID || strings.Join(current.Arguments, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected resolved scan: %#v", current)
	}

	if _, err := manager.SaveProfile(context.Background(), profile.ID, "-sn"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Get(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(snapshot.Arguments, " ") != strings.Join(want, " ") {
		t.Fatalf("profile edit changed scan snapshot: %#v", snapshot.Arguments)
	}
}

func TestManagerCancelsScannerProcessGroup(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	script := filepath.Join(directory, "slow-nmap")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho started\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})

	started, err := manager.Start(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, manager, started.ID, scans.StatusRunning, 2*time.Second)
	if err := manager.Cancel(started.ID); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, manager, started.ID, scans.StatusCancelled, 2*time.Second)
}

func TestManagerPersistsObservationBeforeScanCompletes(t *testing.T) {
	directory := t.TempDir()
	script := filepath.Join(directory, "incremental-nmap")
	prefix := `<?xml version="1.0"?><nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05"><hosthint><status state="up" reason="unknown-response"/><address addr="192.168.1.42" addrtype="ipv4"/></hosthint><host><status state="up" reason="syn-ack"/><address addr="192.168.1.42" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port></ports></host>`
	suffix := `<runstats><finished exit="success"/><hosts up="1" down="255" total="256"/></runstats></nmaprun>`
	contents := "#!/bin/sh\nsleep 0.1\nprintf '%s' '" + prefix + "'\nsleep 2\nprintf '%s' '" + suffix + "'\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})

	started, err := manager.Start(context.Background(), "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	events, unsubscribe := manager.SubscribeAll()
	defer unsubscribe()
	sawHostEvent := false
	sawCountEvent := false
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		for draining := true; draining; {
			select {
			case event := <-events:
				sawHostEvent = sawHostEvent || event.Type == "host" && event.Host != nil && event.ScanID == started.ID
				sawCountEvent = sawCountEvent || event.Scan != nil && event.Scan.HostsUp == 1 && event.Scan.HostsTotal == 1
			default:
				draining = false
			}
		}
		current, err := manager.Get(context.Background(), started.ID)
		if err != nil {
			t.Fatal(err)
		}
		page, err := manager.ListHosts(context.Background(), started.ID, 20, 0)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == scans.StatusRunning && current.HostsUp == 1 && current.HostsTotal == 1 && page.Total == 1 && !page.Items[0].Provisional && page.Items[0].OpenPortCount == 1 && sawHostEvent && sawCountEvent {
			waitForStatus(t, manager, started.ID, scans.StatusCompleted, 3*time.Second)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("host observation was not durable while scan remained active")
}

func TestManagerPreservesObservationsFromFailedScan(t *testing.T) {
	directory := t.TempDir()
	script := filepath.Join(directory, "partial-nmap")
	partialXML := strings.Split(sampleNmapXML, "<runstats>")[0]
	contents := "#!/bin/sh\nprintf '%s' '" + partialXML + "'\nexit 7\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})

	started, err := manager.Start(context.Background(), "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitForStatus(t, manager, started.ID, scans.StatusFailed, 3*time.Second)
	if failed.HostsUp != 1 || failed.HostsTotal != 1 || failed.ExitCode == nil || *failed.ExitCode != 7 {
		t.Fatalf("failed scan lost its partial state: %#v", failed)
	}
	page, err := manager.ListHosts(context.Background(), started.ID, 20, 0)
	if err != nil || page.Total != 1 || page.Items[0].Address != "192.168.1.42" || page.Items[0].OpenPortCount != 1 {
		t.Fatalf("failed scan lost its completed host: %#v, %v", page, err)
	}
	evidence, err := manager.ListEvidence(context.Background(), started.ID, providers.EvidenceQuery{Kind: "scan.summary", Limit: 20})
	if err != nil || len(evidence) != 1 || !strings.Contains(string(evidence[0].Payload), `"partial":true`) {
		t.Fatalf("failed scan lost its partial summary: %#v, %v", evidence, err)
	}
}

func waitForStatus(t *testing.T, manager *scans.Manager, identifier string, wanted scans.Status, timeout time.Duration) scans.Scan {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		current, err := manager.Get(context.Background(), identifier)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == wanted {
			return current
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan did not reach %s", wanted)
	return scans.Scan{}
}
