package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/erniebrodeur/lantern/internal/providers"
)

// Route discovers and stores the route from the local host to target.
func (m *Manager) Route(ctx context.Context, scanID, target string) (HostRoute, error) {
	selections := m.providers.ResolveAll("route")
	if len(selections) == 0 {
		return HostRoute{}, errors.New("route mapping requires mtr or traceroute")
	}
	if net.ParseIP(target) == nil {
		return HostRoute{}, errors.New("route target must be an observed IP address")
	}
	if _, err := m.store.Get(ctx, scanID); err != nil {
		return HostRoute{}, err
	}
	page, err := m.store.ListHosts(ctx, scanID, 500, 0)
	if err != nil {
		return HostRoute{}, err
	}
	observed := false
	for _, host := range page.Items {
		if host.State == "up" && host.Address == target {
			observed = true
			break
		}
	}
	if !observed {
		return HostRoute{}, errors.New("route target is not an observed up host in this scan")
	}
	select {
	case m.routeSlots <- struct{}{}:
		defer func() { <-m.routeSlots }()
	case <-ctx.Done():
		return HostRoute{}, ctx.Err()
	}

	last := HostRoute{Target: target, Hops: []RouteHop{}}
	for _, selection := range selections {
		last.Tool = selection.Status.ProviderID
		last.Error = ""
		_, runErr := m.runProvider(ctx, scanID, providers.Request{Target: target}, selection.Provider, func(event providers.Event) error {
			if event.Evidence == nil || event.Evidence.Kind != "topology.route" {
				return nil
			}
			var route providers.Route
			if err := json.Unmarshal(event.Evidence.Payload, &route); err != nil {
				return fmt.Errorf("decode route evidence: %w", err)
			}
			last.Tool = route.Tool
			last.Hops = make([]RouteHop, len(route.Hops))
			for index, hop := range route.Hops {
				last.Hops[index] = RouteHop{TTL: hop.TTL, Address: hop.Address, Loss: hop.Loss, LatencyMS: hop.LatencyMS}
			}
			return nil
		})
		if runErr == nil && len(last.Hops) > 0 {
			break
		}
		if runErr != nil {
			last.Error = runErr.Error()
		}
	}
	if err := m.store.SaveRoute(ctx, scanID, last); err != nil {
		return HostRoute{}, fmt.Errorf("save route: %w", err)
	}
	return last, nil
}

// SavedRoutes returns routes previously discovered for a scan.
func (m *Manager) SavedRoutes(ctx context.Context, scanID string) (RouteMap, error) {
	if _, err := m.store.Get(ctx, scanID); err != nil {
		return RouteMap{}, err
	}
	return m.store.ListRoutes(ctx, scanID)
}
