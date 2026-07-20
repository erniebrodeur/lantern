package scans

import (
	"net/netip"
	"sort"
	"strings"
)

type ownershipCandidate struct {
	ownership  *Ownership
	confidence float64
}

func publicAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsUnspecified()
}

func mergeOwnership(destination, source *Ownership) {
	if destination == nil || source == nil {
		return
	}
	fields := []struct {
		destination *string
		source      string
	}{
		{&destination.Organization, source.Organization},
		{&destination.NetworkName, source.NetworkName},
		{&destination.Range, source.Range},
		{&destination.CIDR, source.CIDR},
		{&destination.City, source.City},
		{&destination.Region, source.Region},
		{&destination.Country, source.Country},
		{&destination.Origin, source.Origin},
	}
	for _, field := range fields {
		if *field.destination == "" {
			*field.destination = field.source
		}
	}
	for _, sourceName := range source.Sources {
		if sourceName != "" && !containsFold(destination.Sources, sourceName) {
			destination.Sources = append(destination.Sources, sourceName)
		}
	}
}

func mergeOwnershipCandidates(candidates []ownershipCandidate) *Ownership {
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if candidate.ownership != nil {
			filtered = append(filtered, candidate)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].confidence > filtered[j].confidence
	})
	merged := *filtered[0].ownership
	merged.Sources = append([]string(nil), filtered[0].ownership.Sources...)
	for _, candidate := range filtered[1:] {
		mergeOwnership(&merged, candidate.ownership)
	}
	return &merged
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
