package scans

import "testing"

func TestValidateTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "hostname", value: "printer.local", want: "printer.local"},
		{name: "trimmed IPv4", value: " 192.168.1.42 ", want: "192.168.1.42"},
		{name: "IPv6", value: "2001:db8::1", want: "2001:db8::1"},
		{name: "CIDR", value: "192.168.1.0/24", want: "192.168.1.0/24"},
		{name: "trailing dot", value: "router.example.", want: "router.example."},
		{name: "empty", value: " ", wantErr: true},
		{name: "option injection", value: "-iR", wantErr: true},
		{name: "spaces", value: "host another-host", wantErr: true},
		{name: "bad label", value: "-host.example", wantErr: true},
		{name: "bad CIDR", value: "192.168.1.0/99", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateTarget(test.value)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ValidateTarget(%q) succeeded, want error", test.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateTarget(%q): %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("ValidateTarget(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestScanTargetIPAddressUsesCIDRNetworkAddress(t *testing.T) {
	t.Parallel()
	address, ok := scanTargetIPAddress("167.99.51.125/24")
	if !ok || address != "167.99.51.0" {
		t.Fatalf("scanTargetIPAddress returned %q, %v", address, ok)
	}
}
