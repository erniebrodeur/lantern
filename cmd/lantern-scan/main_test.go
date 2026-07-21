package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/store"
)

const testNmapXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
  <host><status state="up" reason="syn-ack"/><address addr="192.168.1.42" addrtype="ipv4"/></host>
  <runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`

func TestParseRequest(t *testing.T) {
	request, err := parseRequest([]string{"quick", "192.168.1.0/24", "--args", "-Pn", "-p", "22,80"})
	if err != nil {
		t.Fatal(err)
	}
	if request.ProfileID != scans.DefaultProfileID || request.Target != "192.168.1.0/24" || !reflect.DeepEqual(request.AdditionalArguments, []string{"-Pn", "-p", "22,80"}) {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestParseRequestRejectsUnknownMode(t *testing.T) {
	if _, err := parseRequest([]string{"thorough", "192.168.1.0/24"}); err == nil || !strings.Contains(err.Error(), "unknown scan mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRequestRequiresArgsMarker(t *testing.T) {
	if _, err := parseRequest([]string{"deep", "192.168.1.0/24", "-Pn"}); err == nil || !strings.Contains(err.Error(), "--args") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRequestUsageErrors(t *testing.T) {
	for _, arguments := range [][]string{nil, {"quick", "127.0.0.1", "--args"}} {
		if _, err := parseRequest(arguments); err == nil {
			t.Fatalf("parseRequest(%q) succeeded", arguments)
		}
	}
	request, err := parseRequest([]string{"QUICK", "127.0.0.1"})
	if err != nil || request.ProfileID != scans.DefaultProfileID {
		t.Fatalf("uppercase mode returned %#v, %v", request, err)
	}
}

func TestTerminalAndReportResult(t *testing.T) {
	if terminal(scans.StatusRunning) {
		t.Fatal("running scan is terminal")
	}
	for _, status := range []scans.Status{scans.StatusCompleted, scans.StatusFailed, scans.StatusCancelled, scans.StatusInterrupted} {
		if !terminal(status) {
			t.Errorf("%s scan is not terminal", status)
		}
	}
	var output bytes.Buffer
	if err := reportResult(&output, scans.Scan{ID: "ok", Status: scans.StatusCompleted, HostsUp: 1, HostsTotal: 1}); err != nil {
		t.Fatal(err)
	}
	if err := reportResult(&output, scans.Scan{ID: "failed", Status: scans.StatusFailed, Error: "nmap failed"}); err == nil || err.Error() != "nmap failed" {
		t.Fatalf("unexpected explicit failure: %v", err)
	}
	if err := reportResult(&output, scans.Scan{ID: "cancelled", Status: scans.StatusCancelled}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("unexpected status failure: %v", err)
	}
}

func TestRunReportsConfigurationAndDatabaseErrors(t *testing.T) {
	t.Setenv("SUDO_USER", "lantern-user-that-does-not-exist")
	if err := run([]string{"quick", "127.0.0.1"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("run accepted an unknown SUDO_USER")
	}
	t.Setenv("SUDO_USER", "")
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANTERN_DB_PATH", filepath.Join(parent, "lantern.db"))
	if err := run([]string{"quick", "127.0.0.1"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("run accepted an invalid database path")
	}
}

func TestRunPersistsScanThroughManager(t *testing.T) {
	directory := t.TempDir()
	nmapPath := filepath.Join(directory, "fake-nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s\\n' '"+testNmapXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "lantern.db")
	t.Setenv("SUDO_USER", "")
	t.Setenv("LANTERN_DB_PATH", databasePath)
	t.Setenv("LANTERN_NMAP_PATH", nmapPath)

	var stdout, stderr bytes.Buffer
	if err := run([]string{"quick", "192.168.1.0/24", "--args", "-Pn"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr: %s", err, stderr.String())
	}
	database, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	results, err := database.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != scans.StatusCompleted || results[0].HostsUp != 1 || !contains(results[0].Arguments, "-Pn") {
		t.Fatalf("unexpected persisted scan: %#v", results)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
