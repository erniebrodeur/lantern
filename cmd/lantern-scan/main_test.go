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
