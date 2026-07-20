package scans

import "testing"

func TestMergeOwnershipCandidatesPrefersHigherConfidence(t *testing.T) {
	whois := &Ownership{
		Organization: "Amazon.com, Inc.", NetworkName: "AMAZO-4",
		City: "Seattle", Region: "WA", Country: "US", Origin: "AS16509",
		Sources: []string{"whois"},
	}
	rdap := &Ownership{
		Organization: "Amazon Data Services Northern Virginia", NetworkName: "AMAZON-IAD",
		CIDR: "100.24.0.0/13", City: "Herndon", Region: "VA", Country: "United States",
		Sources: []string{"rdap"},
	}

	merged := mergeOwnershipCandidates([]ownershipCandidate{
		{ownership: whois, confidence: 0.8},
		{ownership: rdap, confidence: 0.95},
	})
	if merged == nil || merged.Organization != rdap.Organization || merged.NetworkName != rdap.NetworkName || merged.City != rdap.City {
		t.Fatalf("RDAP fields did not win: %#v", merged)
	}
	if merged.Origin != whois.Origin {
		t.Fatalf("WHOIS fallback field was not retained: %#v", merged)
	}
	if len(merged.Sources) != 2 || merged.Sources[0] != "rdap" || merged.Sources[1] != "whois" {
		t.Fatalf("unexpected sources: %#v", merged.Sources)
	}
}
