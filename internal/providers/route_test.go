package providers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseMTRJSON(t *testing.T) {
	hops, err := parseMTRJSON([]byte(`{"report":{"hubs":[{"count":"1","host":"192.168.1.1","Loss%":0.0,"Avg":1.25},{"count":2,"host":"???","Loss%":100.0,"Avg":0.0}]}}`))
	if err != nil || len(hops) != 2 || hops[0].Address != "192.168.1.1" || hops[0].LatencyMS != 1.25 || hops[1].Address != "" {
		t.Fatalf("unexpected hops: %#v, %v", hops, err)
	}
}

func TestParseTraceroute(t *testing.T) {
	hops := parseTraceroute("1  192.168.1.1  1.234 ms\n2  *\n3  203.0.113.9  8.500 ms\n")
	if len(hops) != 3 || hops[0].Address != "192.168.1.1" || hops[1].Address != "" || hops[2].TTL != 3 {
		t.Fatalf("unexpected hops: %#v", hops)
	}
}

func TestRouteProviderMetadataAndProbe(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func(CommandRunner) Provider
	}{
		{name: "mtr", new: NewMTRProvider},
		{name: "traceroute", new: NewTracerouteProvider},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := executableOnPath(t, test.name)
			provider := test.new(nil)
			descriptor := provider.Describe()
			status := provider.Probe(context.Background())
			if descriptor.ID != test.name || descriptor.Capability != "route" || !status.Available || status.Path != path {
				t.Fatalf("descriptor/status = %#v %#v", descriptor, status)
			}
		})
	}
	t.Setenv("PATH", t.TempDir())
	if status := NewMTRProvider(nil).Probe(context.Background()); status.Available || !strings.Contains(status.Reason, "not found") {
		t.Fatalf("missing status = %#v", status)
	}
}

func TestRouteProvidersRun(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{name: "mtr", output: `{"report":{"hubs":[{"count":1,"host":"192.168.1.1","Loss%":0,"Avg":1.2}]}}`},
		{name: "traceroute", output: "1 192.168.1.1 1.2 ms\n2 8.8.8.8 8.1 ms\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotArguments []string
			runner := commandRunnerFunc(func(_ context.Context, _ string, arguments []string, timeout time.Duration, limit int) (CommandResult, error) {
				gotArguments = append([]string(nil), arguments...)
				if timeout != routeTimeout || limit != maxRouteOutput {
					t.Fatalf("limits = %v %d", timeout, limit)
				}
				return CommandResult{Stdout: []byte(test.output)}, nil
			})
			provider := newRouteProvider(test.name, test.name, 1, runner).(*routeProvider)
			provider.path = "/fake/" + test.name
			var evidence *Evidence
			if err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, func(event Event) error { evidence = event.Evidence; return nil }); err != nil {
				t.Fatal(err)
			}
			var route Route
			if evidence == nil || evidence.Kind != "topology.route" || json.Unmarshal(evidence.Payload, &route) != nil || route.Tool != test.name || len(route.Hops) == 0 || gotArguments[len(gotArguments)-1] != "8.8.8.8" {
				t.Fatalf("evidence/arguments = %#v %#v", evidence, gotArguments)
			}
		})
	}
}

func TestRouteProviderErrors(t *testing.T) {
	if err := NewMTRProvider(nil).Run(context.Background(), Request{Target: "not-an-ip"}, nil); err == nil {
		t.Fatal("invalid target succeeded")
	}
	if err := NewMTRProvider(nil).Run(context.Background(), Request{Target: "8.8.8.8"}, nil); err == nil || !strings.Contains(err.Error(), "probe") {
		t.Fatalf("unprobed error = %v", err)
	}

	tests := []struct {
		name   string
		id     string
		result CommandResult
		runErr error
	}{
		{name: "mtr runner error wins", id: "mtr", result: CommandResult{Stdout: []byte("bad")}, runErr: errors.New("run failed")},
		{name: "mtr empty", id: "mtr", result: CommandResult{Stdout: []byte(`{"report":{"hubs":[]}}`)}},
		{name: "traceroute empty", id: "traceroute"},
		{name: "traceroute runner error", id: "traceroute", runErr: errors.New("run failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newRouteProvider(test.id, test.id, 1, commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
				return test.result, test.runErr
			})).(*routeProvider)
			provider.path = os.Args[0]
			if err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, func(Event) error { return nil }); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	want := errors.New("emit failed")
	provider := newRouteProvider("traceroute", "Traceroute", 1, commandRunnerFunc(func(context.Context, string, []string, time.Duration, int) (CommandResult, error) {
		return CommandResult{Stdout: []byte("1 8.8.8.8 1 ms\n")}, nil
	})).(*routeProvider)
	provider.path = "/fake/traceroute"
	if err := provider.Run(context.Background(), Request{Target: "8.8.8.8"}, func(Event) error { return want }); !errors.Is(err, want) {
		t.Fatalf("emit error = %v", err)
	}
}
