package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
	"github.com/erniebrodeur/lantern/internal/scans"
)

func TestSQLiteScanLifecycle(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	scan := scans.Scan{
		ID:          "scan-1",
		Target:      "printer.local",
		OSDetection: true,
		Status:      scans.StatusQueued,
		Arguments:   []string{"-sT", "printer.local"},
		CreatedAt:   createdAt,
	}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	startedAt := createdAt.Add(time.Second)
	if err := database.MarkStarted(ctx, scan.ID, startedAt); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendOutput(ctx, scan.ID, "Nmap started\n"); err != nil {
		t.Fatal(err)
	}
	scanOwnership := &scans.Ownership{Organization: "Example Networks", CIDR: "192.168.1.0/24", Origin: "AS64500"}
	if _, err := database.SaveScanOwnership(ctx, scan.ID, scanOwnership); err != nil {
		t.Fatal(err)
	}
	finishedAt := startedAt.Add(2 * time.Second)
	exitCode := 0
	if err := database.Finish(ctx, scan.ID, scans.StatusCompleted, finishedAt, &exitCode, ""); err != nil {
		t.Fatal(err)
	}

	got, err := database.Get(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != scans.StatusCompleted || got.Output != "Nmap started\n" || got.Ownership == nil || got.Ownership.Origin != "AS64500" {
		t.Fatalf("unexpected scan: %#v", got)
	}
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("unexpected exit code: %#v", got.ExitCode)
	}
	result := scans.Result{
		NmapVersion: "7.98", XMLOutputVersion: "1.05", HostsUp: 1, HostsTotal: 1,
		Hosts: []scans.HostObservation{{
			State: "up", StateReason: "syn-ack",
			Addresses: []scans.Address{{Address: "192.168.1.42", Type: "ipv4"}, {Address: "00:11:22:33:44:55", Type: "mac", Vendor: "Brother"}},
			Hostnames: []scans.Hostname{{Name: "printer.local", Type: "PTR"}},
			Ports:     []scans.Port{{Protocol: "tcp", Number: 80, State: "open", Service: "http", Product: "Brother Web UI", Confidence: 10}},
			OSStatus:  "matched",
			OSMatches: []scans.OSMatch{{Name: "Embedded Linux", Accuracy: 94, Classes: []scans.OSClass{{Vendor: "Linux", Family: "Linux", Accuracy: 94}}}},
		}},
	}
	if err := database.SaveResult(ctx, scan.ID, result); err != nil {
		t.Fatal(err)
	}
	page, err := database.ListHosts(ctx, scan.ID, 20, 0)
	if err != nil || page.Total != 1 || page.Items[0].Hostname != "printer.local" || page.Items[0].OpenPortCount != 1 || !page.Items[0].WebAvailable {
		t.Fatalf("unexpected host page: %#v, %v", page, err)
	}
	host, err := database.GetHost(ctx, scan.ID, page.Items[0].ID)
	if err != nil || len(host.Ports) != 1 || host.Ports[0].Product != "Brother Web UI" || host.OSStatus != "matched" || len(host.OSMatches) != 1 {
		t.Fatalf("unexpected host detail: %#v, %v", host, err)
	}
	list, err := database.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != scan.ID {
		t.Fatalf("unexpected list: %#v", list)
	}
}

func TestSQLiteProfileLifecycle(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	profile := scans.Profile{ID: "profile-1", ArgumentText: "-sn", Arguments: []string{"-sn"}, CreatedAt: &now, UpdatedAt: &now}
	if err := database.CreateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	got, err := database.GetProfile(ctx, profile.ID)
	if err != nil || got.ArgumentText != "-sn" || len(got.Arguments) != 1 {
		t.Fatalf("unexpected profile: %#v, %v", got, err)
	}
	profile.ArgumentText = "-sT -p 443"
	profile.Arguments = []string{"-sT", "-p", "443"}
	updatedAt := now.Add(time.Second)
	profile.UpdatedAt = &updatedAt
	if err := database.UpdateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	profiles, err := database.ListProfiles(ctx)
	if err != nil || len(profiles) != 1 || profiles[0].ArgumentText != profile.ArgumentText {
		t.Fatalf("unexpected profiles: %#v, %v", profiles, err)
	}
	if err := database.DeleteProfile(ctx, profile.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetProfile(ctx, profile.ID); err != scans.ErrNotFound {
		t.Fatalf("GetProfile after delete returned %v", err)
	}
}

func TestSQLiteRouteLifecycle(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	scan := scans.Scan{ID: "scan-routes", Target: "192.168.1.0/24", Status: scans.StatusCompleted, Arguments: []string{"192.168.1.0/24"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	first := scans.HostRoute{Target: "192.168.1.42", Tool: "mtr", Hops: []scans.RouteHop{{TTL: 1, Address: "192.168.1.1"}, {TTL: 2, Address: "192.168.1.42", LatencyMS: 1.2}}}
	if err := database.SaveRoute(ctx, scan.ID, first); err != nil {
		t.Fatal(err)
	}
	routes, err := database.ListRoutes(ctx, scan.ID)
	if err != nil || routes.Tool != "mtr" || len(routes.Routes) != 1 || len(routes.Routes[0].Hops) != 2 {
		t.Fatalf("unexpected saved routes: %#v, %v", routes, err)
	}

	updated := scans.HostRoute{Target: first.Target, Tool: "traceroute", Hops: []scans.RouteHop{{TTL: 1, Address: first.Target, LatencyMS: 0.4}}}
	if err := database.SaveRoute(ctx, scan.ID, updated); err != nil {
		t.Fatal(err)
	}
	routes, err = database.ListRoutes(ctx, scan.ID)
	if err != nil || routes.Tool != "traceroute" || len(routes.Routes) != 1 || len(routes.Routes[0].Hops) != 1 || routes.Routes[0].Hops[0].LatencyMS != 0.4 {
		t.Fatalf("redo did not replace saved route: %#v, %v", routes, err)
	}

	if err := database.Delete(ctx, scan.ID); err != nil {
		t.Fatal(err)
	}
	routes, err = database.ListRoutes(ctx, scan.ID)
	if err != nil || len(routes.Routes) != 0 {
		t.Fatalf("scan deletion left routes: %#v, %v", routes, err)
	}
}

func TestSQLiteProviderEvidenceLifecycle(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	scan := scans.Scan{ID: "scan-provider", Target: "192.168.1.0/24", Status: scans.StatusRunning, Arguments: []string{"192.168.1.0/24"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC().Truncate(time.Microsecond)
	run := providers.Run{ID: "provider-1", ScanID: scan.ID, Capability: "mdns", ProviderID: "dns-sd", Status: "running", StartedAt: startedAt}
	if err := database.CreateProviderRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	evidence := providers.Evidence{
		Kind: "service.advertisement", Subject: providers.EntityRef{Type: "address", Key: "192.168.1.42"},
		PayloadVersion: 1, Payload: []byte(`{"instance":"Printer","port":631}`), ObservedAt: startedAt, Confidence: 1,
	}
	saved, err := database.SaveEvidence(ctx, run.ID, evidence)
	if err != nil || saved.ID < 1 {
		t.Fatalf("save evidence: %#v, %v", saved, err)
	}
	host, created, err := database.EnsureHost(ctx, scan.ID, scans.Address{Address: "192.168.1.42", Type: "ipv4"}, []scans.Hostname{{Name: "printer.local.", Type: "MDNS"}}, "mdns-response")
	if err != nil || !created || !host.Provisional || len(host.Evidence) != 1 {
		t.Fatalf("ensure evidence host: %#v, %v, %v", host, created, err)
	}
	if err := database.FinishProviderRun(ctx, run.ID, "completed", startedAt.Add(time.Second), ""); err != nil {
		t.Fatal(err)
	}
	items, err := database.ListEvidence(ctx, scan.ID, providers.EvidenceQuery{Kind: "service.advertisement", Limit: 20})
	if err != nil || len(items) != 1 || items[0].ProviderID != "dns-sd" || items[0].Subject.Key != "192.168.1.42" {
		t.Fatalf("unexpected evidence: %#v, %v", items, err)
	}
	if err := database.Delete(ctx, scan.ID); err != nil {
		t.Fatal(err)
	}
	items, err = database.ListEvidence(ctx, scan.ID, providers.EvidenceQuery{Limit: 20})
	if err != nil || len(items) != 0 {
		t.Fatalf("provider evidence survived scan deletion: %#v, %v", items, err)
	}
}

func TestSQLiteOwnedFilesAndSymlinkRejection(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "lantern.db")
	database, err := OpenOwned(path, FileOwner{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(current)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() || int(stat.Gid) != os.Getgid() {
			t.Fatalf("unexpected ownership for %s: %#v", current, info.Sys())
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(directory, "linked.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("expected a database symlink to be rejected")
	}
	if err := os.Remove(path + "-wal"); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Symlink(path, path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected a WAL symlink to be rejected")
	}
	if err := os.Remove(path + "-wal"); err != nil {
		t.Fatal(err)
	}
	directoryLink := filepath.Join(t.TempDir(), "database-dir")
	if err := os.Symlink(directory, directoryLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(directoryLink, "other.db")); err == nil {
		t.Fatal("expected a database directory symlink to be rejected")
	}
}

func TestSQLiteInterruptsAbandonedScan(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	scan := scans.Scan{
		ID:        "scan-2",
		Target:    "192.168.1.1",
		Status:    scans.StatusQueued,
		Arguments: []string{"-sT", "192.168.1.1"},
		CreatedAt: time.Now().UTC(),
	}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := database.InterruptRunning(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := database.Get(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != scans.StatusInterrupted || got.FinishedAt == nil {
		t.Fatalf("unexpected interrupted scan: %#v", got)
	}
}

func TestSQLiteResultWriteRollsBackCompletely(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	scan := scans.Scan{ID: "scan-rollback", Target: "127.0.0.1", Status: scans.StatusRunning, Arguments: []string{"127.0.0.1"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	duplicate := scans.Port{Protocol: "tcp", Number: 80, State: "open"}
	result := scans.Result{
		NmapVersion: "7.98", HostsUp: 1, HostsTotal: 1,
		Hosts: []scans.HostObservation{{State: "up", Ports: []scans.Port{duplicate, duplicate}}},
	}
	if err := database.SaveResult(ctx, scan.ID, result); err == nil {
		t.Fatal("expected duplicate ports to reject the result")
	}
	page, err := database.ListHosts(ctx, scan.ID, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("partial hosts survived rollback: %#v", page)
	}
	stored, err := database.Get(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.HostsTotal != 0 || stored.NmapVersion != "" {
		t.Fatalf("partial scan metadata survived rollback: %#v", stored)
	}
}

func TestSQLiteIncrementalHostUpsertsHintAtomically(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	scan := scans.Scan{ID: "scan-incremental", Target: "192.168.1.0/24", Status: scans.StatusRunning, Arguments: []string{"192.168.1.0/24"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	hint := scans.HostObservation{
		State: "up", Provisional: true,
		Addresses: []scans.Address{{Address: "192.168.1.42", Type: "ipv4"}},
	}
	savedHint, err := database.SaveHost(ctx, scan.ID, hint)
	if err != nil {
		t.Fatal(err)
	}
	storedScan, err := database.Get(ctx, scan.ID)
	if err != nil || storedScan.HostsUp != 1 || storedScan.HostsTotal != 1 {
		t.Fatalf("incremental counters were not persisted: %#v, %v", storedScan, err)
	}
	ownership := &scans.Ownership{Organization: "Example Networks", CIDR: "192.168.1.0/24"}
	enriched, err := database.SaveHostEnrichment(ctx, scan.ID, hint.Addresses[0], []scans.Hostname{{Name: "printer.local", Type: "PTR"}}, ownership)
	if err != nil || enriched.Ownership == nil || enriched.Ownership.Organization != ownership.Organization {
		t.Fatalf("incremental enrichment was not persisted: %#v, %v", enriched, err)
	}
	final := hint
	final.Provisional = false
	final.Ports = []scans.Port{{Protocol: "tcp", Number: 80, State: "open", Service: "http"}}
	savedFinal, err := database.SaveHost(ctx, scan.ID, final)
	if err != nil {
		t.Fatal(err)
	}
	if savedFinal.ID != savedHint.ID {
		t.Fatalf("final record did not replace hint: hint=%d final=%d", savedHint.ID, savedFinal.ID)
	}
	page, err := database.ListHosts(ctx, scan.ID, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Provisional || page.Items[0].OpenPortCount != 1 {
		t.Fatalf("unexpected incremental host: %#v", page)
	}
	detail, err := database.GetHost(ctx, scan.ID, savedFinal.ID)
	if err != nil || detail.Provisional || len(detail.Ports) != 1 || len(detail.Hostnames) != 1 || detail.Hostnames[0].Name != "printer.local" || detail.Ownership == nil {
		t.Fatalf("unexpected final detail: %#v, %v", detail, err)
	}
}

func TestSQLiteDeleteScanCascadesEvidence(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	scan := scans.Scan{ID: "scan-delete", Target: "127.0.0.1", Status: scans.StatusCompleted, Arguments: []string{"127.0.0.1"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SaveHost(ctx, scan.ID, scans.HostObservation{
		State: "up", Addresses: []scans.Address{{Address: "127.0.0.1", Type: "ipv4"}},
		Ports: []scans.Port{{Protocol: "tcp", Number: 80, State: "open"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Delete(ctx, scan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Get(ctx, scan.ID); err != scans.ErrNotFound {
		t.Fatalf("Get after delete returned %v, want ErrNotFound", err)
	}
	var hosts int
	if err := database.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_hosts WHERE scan_id = ?", scan.ID).Scan(&hosts); err != nil {
		t.Fatal(err)
	}
	if hosts != 0 {
		t.Fatalf("delete left %d host rows", hosts)
	}
}

func TestSQLiteSummaryToolsAndMissingRecords(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := scans.Scan{ID: "scan-tools", Target: "127.0.0.1", Status: scans.StatusRunning, Arguments: []string{"127.0.0.1"}, CreatedAt: now}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	summary := scans.Result{NmapVersion: "7.98", XMLOutputVersion: "1.05", HostsUp: 2, HostsDown: 1, HostsTotal: 3}
	if err := database.SaveSummary(ctx, scan.ID, summary); err != nil {
		t.Fatal(err)
	}
	stored, err := database.Get(ctx, scan.ID)
	if err != nil || stored.HostsUp != 2 || stored.HostsDown != 1 || stored.HostsTotal != 3 {
		t.Fatalf("unexpected summary: %#v, %v", stored, err)
	}
	for _, run := range []providers.Run{
		{ID: "tool-1", ScanID: scan.ID, Capability: "route", ProviderID: "trace", Status: "completed", StartedAt: now},
		{ID: "tool-2", ScanID: scan.ID, Capability: "route", ProviderID: "trace", Label: "Tracer", Status: "running", StartedAt: now.Add(time.Second)},
	} {
		if err := database.CreateProviderRun(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	tools, err := database.ListTools(ctx, scan.ID)
	if err != nil || len(tools) != 1 || tools[0].Label != "Tracer" || !tools[0].Active {
		t.Fatalf("unexpected tools: %#v, %v", tools, err)
	}
	if err := database.FinishProviderRun(ctx, "tool-2", "completed", now.Add(2*time.Second), ""); err != nil {
		t.Fatal(err)
	}
	tools, err = database.ListTools(ctx, scan.ID)
	if err != nil || len(tools) != 1 || tools[0].Active {
		t.Fatalf("unexpected finished tools: %#v, %v", tools, err)
	}

	if _, err := database.ListTools(ctx, "missing"); err != scans.ErrNotFound {
		t.Fatalf("ListTools missing returned %v", err)
	}
	missingOperations := []struct {
		name string
		err  error
	}{
		{"summary", database.SaveSummary(ctx, "missing", summary)},
		{"delete scan", database.Delete(ctx, "missing")},
		{"start scan", database.MarkStarted(ctx, "missing", now)},
		{"append output", database.AppendOutput(ctx, "missing", "x")},
		{"finish scan", database.Finish(ctx, "missing", scans.StatusFailed, now, nil, "failed")},
		{"finish provider", database.FinishProviderRun(ctx, "missing", "failed", now, "failed")},
		{"delete profile", database.DeleteProfile(ctx, "missing")},
	}
	for _, operation := range missingOperations {
		if operation.err != scans.ErrNotFound {
			t.Errorf("%s returned %v, want ErrNotFound", operation.name, operation.err)
		}
	}
	if err := database.CreateProfile(ctx, scans.Profile{}); err == nil {
		t.Fatal("CreateProfile accepted missing timestamps")
	}
	if err := database.UpdateProfile(ctx, scans.Profile{}); err == nil {
		t.Fatal("UpdateProfile accepted a missing timestamp")
	}
	updatedAt := now.Add(time.Minute)
	if err := database.UpdateProfile(ctx, scans.Profile{ID: "missing", UpdatedAt: &updatedAt}); err != scans.ErrNotFound {
		t.Fatalf("UpdateProfile missing returned %v", err)
	}
}

func TestSQLiteEvidenceValidationAndFilters(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := scans.Scan{ID: "scan-evidence", Target: "example.test", Status: scans.StatusRunning, Arguments: []string{"example.test"}, CreatedAt: now}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	run := providers.Run{ID: "evidence-run", ScanID: scan.ID, Capability: "ownership", ProviderID: "rdap", Status: "running", StartedAt: now}
	if err := database.CreateProviderRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	object := &providers.EntityRef{Type: "organization", Key: "Example Networks"}
	first, err := database.SaveEvidence(ctx, run.ID, providers.Evidence{
		Kind: "ownership.registration", Subject: providers.EntityRef{Type: "address", Key: "192.0.2.1"}, Object: object,
		PayloadVersion: 1, Payload: []byte(`{"name":"Example Networks"}`), Confidence: .9,
	})
	if err != nil || first.ID == 0 || first.ObservedAt.IsZero() {
		t.Fatalf("unexpected saved evidence: %#v, %v", first, err)
	}
	if _, err := database.SaveEvidence(ctx, run.ID, providers.Evidence{
		Kind: "route.hop", Subject: providers.EntityRef{Type: "address", Key: "192.0.2.2"},
		PayloadVersion: 1, Payload: []byte(`{"ttl":1}`), ObservedAt: now.Add(time.Second), Confidence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	items, err := database.ListEvidence(ctx, scan.ID, providers.EvidenceQuery{Kind: "ownership.registration", SubjectType: "address", SubjectKey: "192.0.2.1", Limit: -1})
	if err != nil || len(items) != 1 || items[0].Object == nil || items[0].Object.Key != object.Key {
		t.Fatalf("unexpected filtered evidence: %#v, %v", items, err)
	}

	invalid := []providers.Evidence{
		{},
		{Kind: "kind", Subject: providers.EntityRef{Type: "address", Key: "x"}, PayloadVersion: 0, Payload: []byte(`{}`)},
		{Kind: "kind", Subject: providers.EntityRef{Type: "address", Key: "x"}, PayloadVersion: 1, Payload: []byte(`not-json`)},
		{Kind: "kind", Subject: providers.EntityRef{Type: "address", Key: "x"}, PayloadVersion: 1, Payload: make([]byte, 1024*1024+1)},
	}
	for index, evidence := range invalid {
		if _, err := database.SaveEvidence(ctx, run.ID, evidence); err == nil {
			t.Errorf("invalid evidence %d was accepted", index)
		}
	}
	if _, err := database.SaveEvidence(ctx, "missing-run", providers.Evidence{Kind: "kind", Subject: providers.EntityRef{Type: "address", Key: "x"}, PayloadVersion: 1, Payload: []byte(`{}`)}); err == nil {
		t.Fatal("evidence for a missing provider run was accepted")
	}
}

func TestSQLiteEnsureHostExistingAndPagination(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	scan := scans.Scan{ID: "scan-page", Target: "192.0.2.0/24", Status: scans.StatusRunning, Arguments: []string{"192.0.2.0/24"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	address := scans.Address{Address: "192.0.2.1", Type: "ipv4"}
	if _, created, err := database.EnsureHost(ctx, scan.ID, address, []scans.Hostname{{Name: "one.test", Type: "PTR"}}, "discovery"); err != nil || !created {
		t.Fatalf("first EnsureHost: created=%v err=%v", created, err)
	}
	host, created, err := database.EnsureHost(ctx, scan.ID, address, []scans.Hostname{{Name: "ONE.test", Type: "MDNS"}, {Name: "second.test", Type: "MDNS"}}, "discovery")
	if err != nil || created || len(host.Hostnames) != 2 {
		t.Fatalf("existing EnsureHost: %#v created=%v err=%v", host, created, err)
	}
	for _, value := range []string{"192.0.2.2", "192.0.2.3"} {
		if _, err := database.SaveHost(ctx, scan.ID, scans.HostObservation{State: "up", Addresses: []scans.Address{{Address: value, Type: "ipv4"}}}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := database.ListHosts(ctx, scan.ID, 1, 1)
	if err != nil || page.Total != 3 || len(page.Items) != 1 || page.Offset != 1 {
		t.Fatalf("unexpected page: %#v, %v", page, err)
	}
	if _, err := database.GetHost(ctx, scan.ID, 99999); err != scans.ErrNotFound {
		t.Fatalf("GetHost missing returned %v", err)
	}
	if _, err := database.SaveHostEnrichment(ctx, scan.ID, scans.Address{Address: "missing", Type: "ipv4"}, nil, nil); err != scans.ErrNotFound {
		t.Fatalf("SaveHostEnrichment missing returned %v", err)
	}
	if _, err := database.SaveScanOwnership(ctx, "missing", nil); err != scans.ErrNotFound {
		t.Fatalf("SaveScanOwnership missing returned %v", err)
	}
	if _, err := database.SaveHost(ctx, scan.ID, scans.HostObservation{}); err == nil {
		t.Fatal("SaveHost accepted an observation without an address")
	}
}

func TestSQLiteRejectsInvalidPaths(t *testing.T) {
	if !containsString([]string{"trace"}, "trace") || containsString([]string{"trace"}, "other") {
		t.Fatal("containsString returned an unexpected result")
	}
	directory := t.TempDir()
	parent := filepath.Join(directory, "regular-file")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(parent, "lantern.db")); err == nil {
		t.Fatal("Open accepted a regular file as its parent directory")
	}
	if _, err := Open(directory); err == nil {
		t.Fatal("Open accepted a directory as its database file")
	}
}

func TestSQLiteClosedDatabaseErrors(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	scan := scans.Scan{ID: "closed", Arguments: []string{"127.0.0.1"}, CreatedAt: now}
	evidence := providers.Evidence{Kind: "kind", Subject: providers.EntityRef{Type: "address", Key: "127.0.0.1"}, PayloadVersion: 1, Payload: []byte(`{}`)}
	checks := []struct {
		name string
		call func() error
	}{
		{"Create", func() error { return database.Create(ctx, scan) }},
		{"ListProfiles", func() error { _, err := database.ListProfiles(ctx); return err }},
		{"GetProfile", func() error { _, err := database.GetProfile(ctx, "x"); return err }},
		{"List", func() error { _, err := database.List(ctx); return err }},
		{"Get", func() error { _, err := database.Get(ctx, "x"); return err }},
		{"SaveResult", func() error { return database.SaveResult(ctx, "x", scans.Result{}) }},
		{"SaveHost", func() error {
			_, err := database.SaveHost(ctx, "x", scans.HostObservation{Addresses: []scans.Address{{Address: "127.0.0.1", Type: "ipv4"}}})
			return err
		}},
		{"EnsureHost", func() error {
			_, _, err := database.EnsureHost(ctx, "x", scans.Address{Address: "127.0.0.1", Type: "ipv4"}, nil, "test")
			return err
		}},
		{"SaveHostEnrichment", func() error {
			_, err := database.SaveHostEnrichment(ctx, "x", scans.Address{Address: "127.0.0.1", Type: "ipv4"}, nil, nil)
			return err
		}},
		{"SaveScanOwnership", func() error { _, err := database.SaveScanOwnership(ctx, "x", nil); return err }},
		{"ListTools", func() error { _, err := database.ListTools(ctx, "x"); return err }},
		{"ListHosts", func() error { _, err := database.ListHosts(ctx, "x", 1, 0); return err }},
		{"GetHost", func() error { _, err := database.GetHost(ctx, "x", 1); return err }},
		{"SaveRoute", func() error { return database.SaveRoute(ctx, "x", scans.HostRoute{Target: "127.0.0.1"}) }},
		{"ListRoutes", func() error { _, err := database.ListRoutes(ctx, "x"); return err }},
		{"CreateProviderRun", func() error {
			return database.CreateProviderRun(ctx, providers.Run{ID: "x", ScanID: "x", StartedAt: now})
		}},
		{"SaveEvidence", func() error { _, err := database.SaveEvidence(ctx, "x", evidence); return err }},
		{"ListEvidence", func() error { _, err := database.ListEvidence(ctx, "x", providers.EvidenceQuery{}); return err }},
		{"InterruptRunning", func() error { return database.InterruptRunning(ctx, now) }},
	}
	for _, check := range checks {
		if err := check.call(); err == nil {
			t.Errorf("%s succeeded after Close", check.name)
		}
	}
}

func TestSQLiteReportsCorruptStoredData(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := scans.Scan{ID: "corrupt", Target: "127.0.0.1", Status: scans.StatusCompleted, Arguments: []string{"127.0.0.1"}, CreatedAt: now}
	if err := database.Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	assertGetFails := func(column, badValue, goodValue string) {
		t.Helper()
		if _, err := database.database.ExecContext(ctx, "UPDATE scan_runs SET "+column+" = ? WHERE id = ?", badValue, scan.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Get(ctx, scan.ID); err == nil {
			t.Fatalf("Get accepted corrupt %s", column)
		}
		if _, err := database.database.ExecContext(ctx, "UPDATE scan_runs SET "+column+" = ? WHERE id = ?", goodValue, scan.ID); err != nil {
			t.Fatal(err)
		}
	}
	assertGetFails("arguments_json", "not-json", `["127.0.0.1"]`)
	assertGetFails("ownership_json", "not-json", "null")
	assertGetFails("created_at", "not-time", formatTime(now))
	assertGetFails("started_at", "not-time", "")
	if _, err := database.database.ExecContext(ctx, "UPDATE scan_runs SET started_at = NULL WHERE id = ?", scan.ID); err != nil {
		t.Fatal(err)
	}
	assertGetFails("finished_at", "not-time", "")

	profile := scans.Profile{ID: "profile-corrupt", Arguments: []string{"-sn"}, CreatedAt: &now, UpdatedAt: &now}
	if err := database.CreateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"arguments_json", "created_at", "updated_at"} {
		if _, err := database.database.ExecContext(ctx, "UPDATE scan_profiles SET "+column+" = 'bad' WHERE id = ?", profile.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.GetProfile(ctx, profile.ID); err == nil {
			t.Fatalf("GetProfile accepted corrupt %s", column)
		}
		good := formatTime(now)
		if column == "arguments_json" {
			good = `[]`
		}
		if _, err := database.database.ExecContext(ctx, "UPDATE scan_profiles SET "+column+" = ? WHERE id = ?", good, profile.ID); err != nil {
			t.Fatal(err)
		}
	}

	host, err := database.SaveHost(ctx, scan.ID, scans.HostObservation{State: "up", Addresses: []scans.Address{{Address: "127.0.0.1", Type: "ipv4"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"os_matches_json", "ownership_json"} {
		if _, err := database.database.ExecContext(ctx, "UPDATE scan_hosts SET "+column+" = 'bad' WHERE id = ?", host.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.GetHost(ctx, scan.ID, host.ID); err == nil {
			t.Fatalf("GetHost accepted corrupt %s", column)
		}
		good := "null"
		if column == "os_matches_json" {
			good = `[]`
		}
		if _, err := database.database.ExecContext(ctx, "UPDATE scan_hosts SET "+column+" = ? WHERE id = ?", good, host.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.SaveRoute(ctx, scan.ID, scans.HostRoute{Target: "127.0.0.1", Tool: "trace"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.database.ExecContext(ctx, "UPDATE scan_routes SET hops_json = 'bad' WHERE scan_id = ?", scan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ListRoutes(ctx, scan.ID); err == nil {
		t.Fatal("ListRoutes accepted corrupt hops")
	}
}
