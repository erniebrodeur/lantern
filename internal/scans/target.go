package scans

import (
	"fmt"
	"net/netip"
	"strings"
)

// ValidateTarget normalizes and validates an IP address, hostname, or CIDR scan target.
func ValidateTarget(value string) (string, error) {
	target := strings.TrimSpace(value)
	if target == "" {
		return "", fmt.Errorf("target is required")
	}
	if len(target) > 253 {
		return "", fmt.Errorf("target is too long")
	}
	if strings.HasPrefix(target, "-") {
		return "", fmt.Errorf("target cannot begin with a hyphen")
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return target, nil
	}
	if _, err := netip.ParsePrefix(target); err == nil {
		return target, nil
	}
	if validHostname(target) {
		return target, nil
	}
	return "", fmt.Errorf("target must be a hostname, IP address, or CIDR range")
}

func validHostname(value string) bool {
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !isAlphaNumeric(label[0]) || !isAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
