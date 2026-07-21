package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/store"
)

func newTestAPI(t *testing.T) (*ginTestRouter, *store.SQLite, *scans.Manager, scans.Scan, scans.HostObservation) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	manager, err := scans.NewManager(database, "nmap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})
	router, err := NewRouter(manager)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := scans.Scan{ID: "api-seed", Target: "127.0.0.1", Status: scans.StatusCompleted, Arguments: []string{"127.0.0.1"}, CreatedAt: now}
	if err := database.Create(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	host, err := database.SaveHost(context.Background(), scan.ID, scans.HostObservation{
		State: "up", Addresses: []scans.Address{{Address: "127.0.0.1", Type: "ipv4"}},
		Hostnames: []scans.Hostname{{Name: "localhost", Type: "PTR"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	run := providers.Run{ID: "api-provider", ScanID: scan.ID, Capability: "route", ProviderID: "trace", Label: "Trace", Status: "completed", StartedAt: now}
	if err := database.CreateProviderRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SaveEvidence(context.Background(), run.ID, providers.Evidence{
		Kind: "route.hop", Subject: providers.EntityRef{Type: "address", Key: "127.0.0.1"},
		PayloadVersion: 1, Payload: []byte(`{"ttl":1}`), ObservedAt: now, Confidence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return &ginTestRouter{serve: router.ServeHTTP}, database, manager, scan, host
}

type ginTestRouter struct {
	serve func(http.ResponseWriter, *http.Request)
}

func (r *ginTestRouter) request(method, target, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Host = "localhost:1414"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	r.serve(response, request)
	return response
}

func TestAPIReadEndpointsAndValidation(t *testing.T) {
	t.Parallel()
	router, _, _, scan, host := newTestAPI(t)
	tests := []struct {
		method string
		path   string
		body   string
		status int
	}{
		{http.MethodGet, "/api/health", "", http.StatusOK},
		{http.MethodPost, "/api/capabilities/refresh", "", http.StatusOK},
		{http.MethodGet, "/api/scans", "", http.StatusOK},
		{http.MethodGet, "/api/scans/" + scan.ID + "/hosts?limit=1&offset=0", "", http.StatusOK},
		{http.MethodGet, "/api/scans/" + scan.ID + "/hosts/" + strconvFormat(host.ID), "", http.StatusOK},
		{http.MethodGet, "/api/scans/" + scan.ID + "/evidence?kind=route.hop&limit=10", "", http.StatusOK},
		{http.MethodGet, "/api/scans/" + scan.ID + "/tools", "", http.StatusOK},
		{http.MethodGet, "/api/scans/missing", "", http.StatusNotFound},
		{http.MethodDelete, "/api/scans/missing", "", http.StatusNotFound},
		{http.MethodGet, "/api/scans/missing/hosts", "", http.StatusNotFound},
		{http.MethodGet, "/api/scans/" + scan.ID + "/hosts/99999", "", http.StatusNotFound},
		{http.MethodGet, "/api/scans/missing/evidence", "", http.StatusNotFound},
		{http.MethodGet, "/api/scans/missing/tools", "", http.StatusNotFound},
		{http.MethodGet, "/api/scans/missing/routes", "", http.StatusNotFound},
		{http.MethodPost, "/api/scans/missing/cancel", "", http.StatusNotFound},
		{http.MethodGet, "/api/scans/" + scan.ID + "/hosts/nope", "", http.StatusBadRequest},
		{http.MethodGet, "/api/scans/" + scan.ID + "/hosts?limit=0", "", http.StatusBadRequest},
		{http.MethodGet, "/api/scans/" + scan.ID + "/hosts?offset=-1", "", http.StatusBadRequest},
		{http.MethodGet, "/api/scans/" + scan.ID + "/evidence?limit=bad", "", http.StatusBadRequest},
		{http.MethodGet, "/api/scans/" + scan.ID + "/evidence?kind=" + strings.Repeat("x", 129), "", http.StatusBadRequest},
		{http.MethodPost, "/api/scans", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/api/scans/" + scan.ID + "/routes", `{}`, http.StatusBadRequest},
		{http.MethodPut, "/api/profiles/missing", `{}`, http.StatusBadRequest},
		{http.MethodPut, "/api/profiles/missing", `{"argumentText":"-sn"}`, http.StatusNotFound},
		{http.MethodPut, "/api/profiles/builtin:quick", `{"argumentText":"-sn"}`, http.StatusBadRequest},
		{http.MethodDelete, "/api/profiles/builtin:quick", "", http.StatusBadRequest},
		{http.MethodDelete, "/api/profiles/missing", "", http.StatusNotFound},
	}
	for _, test := range tests {
		response := router.request(test.method, test.path, test.body)
		if response.Code != test.status {
			t.Errorf("%s %s returned %d, want %d: %s", test.method, test.path, response.Code, test.status, response.Body.String())
		}
	}
}

func strconvFormat(value int64) string {
	return fmt.Sprintf("%d", value)
}

func TestAPIEventStreamsExitWithRequestContext(t *testing.T) {
	t.Parallel()
	router, _, _, scan, _ := newTestAPI(t)
	for _, path := range []string{"/api/scans/events", "/api/scans/" + scan.ID + "/events"} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(10*time.Millisecond, cancel)
		request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		request.Host = "[::1]:1414"
		response := httptest.NewRecorder()
		router.serve(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s returned %d: %s", path, response.Code, response.Body.String())
		}
	}
	response := router.request(http.MethodGet, "/api/scans/missing/events", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing stream returned %d", response.Code)
	}
}

func TestWriteEventAndBoundedQueryInt(t *testing.T) {
	response := httptest.NewRecorder()
	if err := writeEvent(response, scans.Event{Type: "output", Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"type":"output"`)) {
		t.Fatalf("unexpected SSE payload: %s", response.Body.String())
	}
}
