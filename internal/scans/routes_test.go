package scans_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/store"
)

type fakeRouteProvider struct {
	id       string
	priority int
	fail     bool
}

func (p fakeRouteProvider) Describe() providers.Descriptor {
	return providers.Descriptor{
		ID: p.id, Capability: "route", Label: p.id,
		SupportedOS: []string{runtime.GOOS}, OSPriorities: map[string]int{runtime.GOOS: p.priority},
	}
}

func (p fakeRouteProvider) Probe(context.Context) providers.Status {
	return providers.Status{ProviderID: p.id, Label: p.id, Status: "available", Available: true}
}

func (p fakeRouteProvider) Run(_ context.Context, request providers.Request, emit providers.EmitFunc) error {
	if p.fail {
		return errors.New("route probe failed")
	}
	payload, _ := json.Marshal(providers.Route{
		Target: request.Target, Tool: p.id,
		Hops: []providers.RouteHop{{TTL: 1, Address: "192.168.1.1", LatencyMS: 1}, {TTL: 2, Address: request.Target, LatencyMS: 4.5}},
	})
	return emit(providers.Event{Type: "evidence", Evidence: &providers.Evidence{
		Kind: "topology.route", Subject: providers.EntityRef{Type: "address", Key: request.Target},
		PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
	}})
}

func TestRouteFallsBackThroughGenericProviders(t *testing.T) {
	directory := t.TempDir()
	nmapPath := filepath.Join(directory, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "lantern.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	scan := scans.Scan{ID: "route-scan", Target: "203.0.113.9", Status: scans.StatusCompleted, Arguments: []string{"203.0.113.9"}, CreatedAt: time.Now().UTC()}
	if err := database.Create(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SaveHost(context.Background(), scan.ID, scans.HostObservation{
		State: "up", Addresses: []scans.Address{{Address: "203.0.113.9", Type: "ipv4"}},
	}); err != nil {
		t.Fatal(err)
	}
	registry := providers.NewRegistry(runtime.GOOS, func(string) string { return "" },
		fakeRouteProvider{id: "first", priority: 100, fail: true},
		fakeRouteProvider{id: "second", priority: 90},
	)
	manager, err := scans.NewManagerWithProviders(database, nmapPath, registry)
	if err != nil {
		t.Fatal(err)
	}
	route, err := manager.Route(context.Background(), scan.ID, "203.0.113.9")
	if err != nil || route.Tool != "second" || len(route.Hops) != 2 {
		t.Fatalf("unexpected fallback route: %#v, %v", route, err)
	}
	evidence, err := manager.ListEvidence(context.Background(), scan.ID, providers.EvidenceQuery{Kind: "topology.route", Limit: 20})
	if err != nil || len(evidence) != 1 || evidence[0].ProviderID != "second" {
		t.Fatalf("unexpected route evidence: %#v, %v", evidence, err)
	}
}
