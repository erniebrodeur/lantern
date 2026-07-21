package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
  <host><status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/></host>
  <runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`

func TestRunLoadsFixtureIdempotently(t *testing.T) {
	directory := t.TempDir()
	xmlPath := filepath.Join(directory, "fixture.xml")
	databasePath := filepath.Join(directory, "fixture.db")
	if err := os.WriteFile(xmlPath, []byte(fixtureXML), 0o600); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) }
	arguments := []string{"-xml", xmlPath, "-db", databasePath, "-target", "192.0.2.0/24"}
	var output bytes.Buffer
	if err := run(arguments, &output, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "1 up, 0 down, 1 total") {
		t.Fatalf("unexpected output: %s", output.String())
	}
	output.Reset()
	if err := run(arguments, &output, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "fixture already loaded") {
		t.Fatalf("unexpected idempotent output: %s", output.String())
	}
}

func TestRunRejectsInvalidInputs(t *testing.T) {
	if err := run([]string{"-unknown"}, &bytes.Buffer{}, time.Now); err == nil {
		t.Fatal("unknown flag was accepted")
	}
	if err := run([]string{"-target", "not-a-target"}, &bytes.Buffer{}, time.Now); err == nil {
		t.Fatal("invalid target was accepted")
	}
	if err := run([]string{"-xml", filepath.Join(t.TempDir(), "missing.xml")}, &bytes.Buffer{}, time.Now); err == nil {
		t.Fatal("missing fixture was accepted")
	}
	directory := t.TempDir()
	large := filepath.Join(directory, "large.xml")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maximumFixtureBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-xml", large}, &bytes.Buffer{}, time.Now); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected oversized fixture error: %v", err)
	}
}

func TestRunRecordsMalformedFixtureFailure(t *testing.T) {
	directory := t.TempDir()
	xmlPath := filepath.Join(directory, "bad.xml")
	if err := os.WriteFile(xmlPath, []byte("<nmaprun>"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-xml", xmlPath, "-db", filepath.Join(directory, "bad.db")}, &bytes.Buffer{}, time.Now)
	if err == nil {
		t.Fatal("malformed fixture was accepted")
	}
}
