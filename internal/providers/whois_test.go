package providers

import "testing"

func TestParseWHOISRegistration(t *testing.T) {
	result := parseWHOIS([]byte(`
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
OrgName:        Google LLC
City:           Mountain View
StateProv:      CA
Country:        US
OriginAS:       AS15169
`))
	if result == nil || result.Organization != "Google LLC" || result.NetworkName != "GOGL" || result.CIDR != "8.8.8.0/24" || result.City != "Mountain View" || result.Region != "CA" || result.Country != "US" || result.Origin != "AS15169" {
		t.Fatalf("unexpected registration: %#v", result)
	}
}
