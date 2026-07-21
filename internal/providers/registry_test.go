package providers

import (
	"context"
	"reflect"
	"testing"
)

func TestRegistryRegistrationDisabledAndStatuses(t *testing.T) {
	registry := NewRegistry("darwin", func(name string) string {
		if name == "LANTERN_MDNS_PROVIDER" {
			return "disabled"
		}
		return ""
	})
	registry.Register(
		fakeProvider{descriptor: Descriptor{ID: "z", Capability: "mdns", SupportedOS: []string{"darwin"}}, available: true},
		fakeProvider{descriptor: Descriptor{ID: "ignored", Capability: "route", SupportedOS: []string{"linux"}}, available: true},
	)
	registry.Refresh(context.Background())
	if _, status, ok := registry.Resolve("mdns"); ok || status.Status != "disabled" {
		t.Fatalf("disabled resolve = %#v %v", status, ok)
	}
	statuses := registry.Statuses()
	if len(statuses) != 1 || statuses[0].Status != "disabled" {
		t.Fatalf("statuses = %#v", statuses)
	}
	statuses[0].Status = "mutated"
	if registry.Statuses()[0].Status != "disabled" {
		t.Fatal("Statuses did not return a copy")
	}
}

func TestRegistryUnavailableAndOverrides(t *testing.T) {
	tests := []struct {
		name     string
		lookup   func(string) string
		provider []Provider
		want     Status
	}{
		{
			name:   "unsupported override",
			lookup: func(string) string { return "missing" },
			provider: []Provider{fakeProvider{descriptor: Descriptor{
				ID: "available", Capability: "mdns", SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 1},
			}, available: true}},
			want: Status{Capability: "mdns", ProviderID: "missing", OS: "darwin", Status: "unavailable", Reason: `configured provider "missing" is not supported on darwin`},
		},
		{
			name: "all probes unavailable",
			provider: []Provider{fakeProvider{descriptor: Descriptor{
				ID: "down", Capability: "mdns", SupportedOS: []string{"darwin"}, OSPriorities: map[string]int{"darwin": 1},
			}}},
			want: Status{Capability: "mdns", ProviderID: "down", Label: "", OS: "darwin", Status: "unavailable"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistry("darwin", test.lookup, test.provider...)
			registry.Refresh(context.Background())
			_, got, ok := registry.Resolve("mdns")
			if ok || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Resolve = %#v %v, want %#v", got, ok, test.want)
			}
		})
	}
	if got := providerOverrideName("reverse.dns-name"); got != "LANTERN_REVERSE_DNS_NAME_PROVIDER" {
		t.Fatalf("override name = %q", got)
	}
}
