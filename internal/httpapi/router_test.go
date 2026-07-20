package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/httpapi"
	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/store"
)

func TestScanAPI(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	script := filepath.Join(directory, "fake-nmap")
	if err := os.WriteFile(script, []byte(`#!/bin/sh
printf '%s\n' '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05"><host><status state="up" reason="localhost-response"/><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost" type="user"/></hostnames><ports><port protocol="tcp" portid="1414"><state state="open" reason="syn-ack"/><service name="http" product="Lantern" method="probed" conf="10"/></port></ports></host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
`), 0o700); err != nil {
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
	router, err := httpapi.NewRouter(manager)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString(`{"target":"127.0.0.1"}`))
	request.Host = "127.0.0.1:1414"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("POST /api/scans returned %d: %s", response.Code, response.Body.String())
	}
	var started scans.Scan
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		request = httptest.NewRequest(http.MethodGet, "/api/scans/"+started.ID, nil)
		request.Host = "127.0.0.1:1414"
		response = httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET scan returned %d: %s", response.Code, response.Body.String())
		}
		var current scans.Scan
		if err := json.Unmarshal(response.Body.Bytes(), &current); err != nil {
			t.Fatal(err)
		}
		if current.Status == scans.StatusCompleted {
			if current.HostsUp != 1 || current.HostsTotal != 1 {
				t.Fatalf("unexpected summary: %#v", current)
			}
			if current.Output != "Nmap completed: 1 host(s) up, 0 down, 1 total; 1 observation(s) stored.\n" {
				t.Fatalf("unexpected output: %q", current.Output)
			}
			request = httptest.NewRequest(http.MethodGet, "/api/scans/"+started.ID+"/hosts", nil)
			request.Host = "127.0.0.1:1414"
			response = httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"address":"127.0.0.1"`)) {
				t.Fatalf("unexpected hosts response %d: %s", response.Code, response.Body.String())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan did not complete")
}

func TestAPIRejectsNonLocalHostHeader(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, "nmap")
	if err != nil {
		t.Fatal(err)
	}
	router, err := httpapi.NewRouter(manager)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	request.Host = "attacker.example"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("request returned %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestProfileAPI(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, "nmap")
	if err != nil {
		t.Fatal(err)
	}
	router, err := httpapi.NewRouter(manager)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/capabilities", nil)
	request.Host = "127.0.0.1:1414"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"osDetection":`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"toolActivity":true`)) {
		t.Fatalf("GET capabilities returned %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/profiles", nil)
	request.Host = "127.0.0.1:1414"
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"id":"builtin:quick"`)) {
		t.Fatalf("GET profiles returned %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/profiles", bytes.NewBufferString(`{"argumentText":"-sT -p 443"}`))
	request.Host = "127.0.0.1:1414"
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("POST profile returned %d: %s", response.Code, response.Body.String())
	}
	var created scans.Profile
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.BuiltIn || created.ID == "" || len(created.Arguments) != 3 {
		t.Fatalf("unexpected created profile: %#v", created)
	}

	request = httptest.NewRequest(http.MethodPut, "/api/profiles/"+created.ID, bytes.NewBufferString(`{"argumentText":"-sn --reason"}`))
	request.Host = "127.0.0.1:1414"
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"argumentText":"-sn --reason"`)) {
		t.Fatalf("PUT profile returned %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/profiles/"+created.ID, nil)
	request.Host = "127.0.0.1:1414"
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("DELETE profile returned %d: %s", response.Code, response.Body.String())
	}
}

func TestDeleteScanAPI(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	scan := scans.Scan{ID: "delete-me", Target: "127.0.0.1", Status: scans.StatusCompleted, Arguments: []string{"127.0.0.1"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	manager, err := scans.NewManager(database, "nmap")
	if err != nil {
		t.Fatal(err)
	}
	router, err := httpapi.NewRouter(manager)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodDelete, "/api/scans/"+scan.ID, nil)
	request.Host = "127.0.0.1:1414"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("DELETE scan returned %d: %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/scans/"+scan.ID, nil)
	request.Host = "127.0.0.1:1414"
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET deleted scan returned %d: %s", response.Code, response.Body.String())
	}
}

func TestSavedRoutesAPI(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	scan := scans.Scan{ID: "mapped-scan", Target: "192.168.1.42", Status: scans.StatusCompleted, Arguments: []string{"192.168.1.42"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveRoute(context.Background(), scan.ID, scans.HostRoute{
		Target: "192.168.1.42", Tool: "mtr", Hops: []scans.RouteHop{{TTL: 1, Address: "192.168.1.42", LatencyMS: 0.8}},
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := scans.NewManager(database, "nmap")
	if err != nil {
		t.Fatal(err)
	}
	router, err := httpapi.NewRouter(manager)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/scans/"+scan.ID+"/routes", nil)
	request.Host = "127.0.0.1:1414"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"tool":"mtr"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"target":"192.168.1.42"`)) {
		t.Fatalf("GET saved routes returned %d: %s", response.Code, response.Body.String())
	}
}
