package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	routeTimeout    = 12 * time.Second
	maxRouteOutput  = 2 * 1024 * 1024
	routeCapability = "route"
)

type RouteHop struct {
	TTL       int     `json:"ttl"`
	Address   string  `json:"address,omitempty"`
	Loss      float64 `json:"loss,omitempty"`
	LatencyMS float64 `json:"latencyMs,omitempty"`
}

type Route struct {
	Target string     `json:"target"`
	Tool   string     `json:"tool"`
	Hops   []RouteHop `json:"hops"`
}

type routeProvider struct {
	id       string
	label    string
	priority int
	runner   CommandRunner
	mu       sync.RWMutex
	path     string
}

func NewMTRProvider(runner CommandRunner) Provider {
	return newRouteProvider("mtr", "MTR", 100, runner)
}

func NewTracerouteProvider(runner CommandRunner) Provider {
	return newRouteProvider("traceroute", "Traceroute", 90, runner)
}

func newRouteProvider(id, label string, priority int, runner CommandRunner) Provider {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &routeProvider{id: id, label: label, priority: priority, runner: runner}
}

func (p *routeProvider) Describe() Descriptor {
	return Descriptor{
		ID: p.id, Capability: routeCapability, Label: p.label,
		SupportedOS: []string{"darwin", "linux"}, OSPriorities: map[string]int{"darwin": p.priority, "linux": p.priority},
	}
}

func (p *routeProvider) Probe(context.Context) Status {
	status := Status{Capability: routeCapability, ProviderID: p.id, Label: p.label, Status: "unavailable"}
	path := ResolveExecutable("", p.id, nil)
	if path == "" {
		status.Reason = p.id + " was not found on PATH"
		return status
	}
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()
	status.Available = true
	status.Status = "available"
	status.Path = path
	return status
}

func (p *routeProvider) Run(ctx context.Context, request Request, emit EmitFunc) error {
	address, err := netip.ParseAddr(request.Target)
	if err != nil {
		return fmt.Errorf("route target must be an IP address: %w", err)
	}
	p.mu.RLock()
	path := p.path
	p.mu.RUnlock()
	if path == "" {
		return errors.New(p.id + " provider has not passed its availability probe")
	}
	var arguments []string
	if p.id == "mtr" {
		arguments = []string{"--json", "--report", "--report-cycles", "1", "--no-dns", "--max-ttl", "16", address.String()}
	} else {
		arguments = []string{"-n", "-m", "16", "-q", "1", "-w", "1", address.String()}
	}
	result, runErr := p.runner.Run(ctx, path, arguments, routeTimeout, maxRouteOutput)
	var hops []RouteHop
	if p.id == "mtr" {
		hops, err = parseMTRJSON(result.Stdout)
	} else {
		hops = parseTraceroute(string(result.Stdout))
		if len(hops) == 0 {
			err = errors.New("traceroute returned no hops")
		}
	}
	if err != nil {
		if runErr != nil {
			return runErr
		}
		return err
	}
	if len(hops) == 0 {
		if runErr != nil {
			return runErr
		}
		return errors.New(p.id + " returned no hops")
	}
	payload, err := json.Marshal(Route{Target: address.String(), Tool: p.id, Hops: hops})
	if err != nil {
		return err
	}
	return emit(Event{Type: "evidence", Evidence: &Evidence{
		Kind: "topology.route", Subject: EntityRef{Type: "address", Key: address.String()},
		PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
	}})
}

func parseMTRJSON(data []byte) ([]RouteHop, error) {
	var document struct {
		Report struct {
			Hubs []struct {
				Count json.RawMessage `json:"count"`
				Host  string          `json:"host"`
				Loss  float64         `json:"Loss%"`
				Avg   float64         `json:"Avg"`
			} `json:"hubs"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse mtr output: %w", err)
	}
	hops := make([]RouteHop, 0, len(document.Report.Hubs))
	for _, hub := range document.Report.Hubs {
		ttl, err := strconv.Atoi(strings.Trim(string(hub.Count), `"`))
		if err != nil {
			return nil, fmt.Errorf("parse mtr hop count: %w", err)
		}
		address := hub.Host
		if address == "???" {
			address = ""
		}
		hops = append(hops, RouteHop{TTL: ttl, Address: address, Loss: hub.Loss, LatencyMS: hub.Avg})
	}
	return hops, nil
}

func parseTraceroute(output string) []RouteHop {
	var hops []RouteHop
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ttl, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		hop := RouteHop{TTL: ttl}
		if address, err := netip.ParseAddr(strings.Trim(fields[1], "()")); err == nil {
			hop.Address = address.String()
		}
		for index, field := range fields {
			if field == "ms" && index > 0 {
				hop.LatencyMS, _ = strconv.ParseFloat(fields[index-1], 64)
				break
			}
		}
		hops = append(hops, hop)
	}
	return hops
}
