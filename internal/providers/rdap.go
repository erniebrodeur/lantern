package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	rdapCapability       = "ownership"
	defaultRDAPBaseURL   = "https://rdap.org/ip/"
	maxRDAPOutput        = 2 * 1024 * 1024
	rdapTimeout          = 8 * time.Second
	rdapPositiveCacheTTL = 24 * time.Hour
	rdapNegativeCacheTTL = 5 * time.Minute
)

type NetworkRegistration struct {
	Organization string `json:"organization,omitempty"`
	NetworkName  string `json:"networkName,omitempty"`
	Range        string `json:"range,omitempty"`
	CIDR         string `json:"cidr,omitempty"`
	City         string `json:"city,omitempty"`
	Region       string `json:"region,omitempty"`
	Country      string `json:"country,omitempty"`
	Origin       string `json:"origin,omitempty"`
}

type rdapCacheEntry struct {
	prefix       netip.Prefix
	registration *NetworkRegistration
	expiresAt    time.Time
}

type rdapProvider struct {
	client  *http.Client
	baseURL string
	mu      sync.Mutex
	lookup  sync.Mutex
	cache   []rdapCacheEntry
}

func NewRDAPProvider(client *http.Client, baseURL string) Provider {
	if client == nil {
		client = &http.Client{
			Timeout: rdapTimeout,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many RDAP redirects")
				}
				if request.URL.Scheme != "https" {
					return errors.New("RDAP redirect must use HTTPS")
				}
				return nil
			},
		}
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultRDAPBaseURL
	}
	return &rdapProvider{client: client, baseURL: baseURL}
}

func (p *rdapProvider) Describe() Descriptor {
	return Descriptor{
		ID: "rdap", Capability: rdapCapability, Label: "RDAP",
		SupportedOS:  []string{"darwin", "linux"},
		OSPriorities: map[string]int{"darwin": 100, "linux": 100},
	}
}

func (p *rdapProvider) Probe(context.Context) Status {
	return Status{
		Capability: rdapCapability, ProviderID: "rdap", Label: "RDAP",
		Status: "available", Available: true, Path: p.baseURL,
	}
}

func (p *rdapProvider) Run(ctx context.Context, request Request, emit EmitFunc) error {
	address, err := netip.ParseAddr(request.Target)
	if err != nil {
		return fmt.Errorf("RDAP target must be an IP address: %w", err)
	}
	address = address.Unmap()
	if !isPublicAddress(address) {
		return nil
	}
	registration, err := p.lookupRegistration(ctx, address)
	if err != nil {
		return err
	}
	return emitRegistrationEvidence(address, registration, 0.95, emit)
}

func isPublicAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsUnspecified()
}

func (p *rdapProvider) lookupRegistration(ctx context.Context, address netip.Addr) (*NetworkRegistration, error) {
	if cached, ok := p.cached(address); ok {
		return cached, nil
	}
	p.lookup.Lock()
	defer p.lookup.Unlock()
	if cached, ok := p.cached(address); ok {
		return cached, nil
	}

	lookupContext, cancel := context.WithTimeout(ctx, rdapTimeout)
	defer cancel()
	endpoint, err := url.JoinPath(p.baseURL, address.String())
	if err != nil {
		return nil, fmt.Errorf("build RDAP URL: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(lookupContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create RDAP request: %w", err)
	}
	httpRequest.Header.Set("Accept", "application/rdap+json, application/json")
	httpRequest.Header.Set("User-Agent", "Lantern RDAP client")
	response, err := p.client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("RDAP lookup: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("RDAP lookup returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRDAPOutput+1))
	if err != nil {
		return nil, fmt.Errorf("read RDAP response: %w", err)
	}
	if len(body) > maxRDAPOutput {
		return nil, fmt.Errorf("RDAP response exceeded %d bytes", maxRDAPOutput)
	}
	registration, prefix, err := parseRDAP(body, address)
	if err != nil {
		return nil, err
	}
	ttl := rdapPositiveCacheTTL
	if registration == nil {
		ttl = rdapNegativeCacheTTL
	}
	if !prefix.IsValid() {
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	p.mu.Lock()
	p.cache = append(p.cache, rdapCacheEntry{prefix: prefix, registration: registration, expiresAt: time.Now().Add(ttl)})
	p.mu.Unlock()
	return registration, nil
}

func (p *rdapProvider) cached(address netip.Addr) (*NetworkRegistration, bool) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := 0; index < len(p.cache); {
		entry := p.cache[index]
		if !now.Before(entry.expiresAt) {
			p.cache = append(p.cache[:index], p.cache[index+1:]...)
			continue
		}
		if entry.prefix.Contains(address) {
			return entry.registration, true
		}
		index++
	}
	return nil, false
}

type rdapNetwork struct {
	Name         string       `json:"name"`
	Handle       string       `json:"handle"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Country      string       `json:"country"`
	CIDRs        []rdapCIDR   `json:"cidr0_cidrs"`
	Entities     []rdapEntity `json:"entities"`
}

type rdapCIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

type rdapEntity struct {
	Roles      []string          `json:"roles"`
	VCardArray []json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity      `json:"entities"`
}

type rdapContact struct {
	organization string
	city         string
	region       string
	country      string
	score        int
}

func parseRDAP(body []byte, address netip.Addr) (*NetworkRegistration, netip.Prefix, error) {
	var network rdapNetwork
	if err := json.Unmarshal(body, &network); err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("decode RDAP response: %w", err)
	}
	prefix, cidr := rdapPrefix(network.CIDRs, address)
	contact := bestRDAPContact(network.Entities)
	registration := &NetworkRegistration{
		Organization: contact.organization,
		NetworkName:  rdapFirstNonempty(network.Name, network.Handle),
		Range:        formatAddressRange(network.StartAddress, network.EndAddress),
		CIDR:         cidr,
		City:         contact.city,
		Region:       contact.region,
		Country:      rdapFirstNonempty(contact.country, network.Country),
	}
	if registration.Organization == "" && registration.NetworkName == "" && registration.Range == "" && registration.CIDR == "" {
		return nil, prefix, nil
	}
	return registration, prefix, nil
}

func rdapPrefix(cidrs []rdapCIDR, address netip.Addr) (netip.Prefix, string) {
	var best netip.Prefix
	for _, item := range cidrs {
		value := rdapFirstNonempty(item.V4Prefix, item.V6Prefix)
		candidate, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", value, item.Length))
		if err != nil || !candidate.Contains(address) {
			continue
		}
		candidate = candidate.Masked()
		if !best.IsValid() || candidate.Bits() > best.Bits() {
			best = candidate
		}
	}
	if !best.IsValid() {
		return best, ""
	}
	return best, best.String()
}

func bestRDAPContact(entities []rdapEntity) rdapContact {
	best := rdapContact{score: -1}
	var visit func([]rdapEntity)
	visit = func(items []rdapEntity) {
		for _, entity := range items {
			contact := parseRDAPVCard(entity.VCardArray)
			contact.score = rdapRoleScore(entity.Roles)
			if (contact.organization != "" || contact.city != "" || contact.region != "" || contact.country != "") && contact.score > best.score {
				best = contact
			}
			visit(entity.Entities)
		}
	}
	visit(entities)
	return best
}

func rdapRoleScore(roles []string) int {
	score := 10
	for _, role := range roles {
		switch strings.ToLower(role) {
		case "registrant":
			return 100
		case "administrative":
			if score < 60 {
				score = 60
			}
		case "technical":
			if score < 40 {
				score = 40
			}
		case "abuse":
			if score < 1 {
				score = 1
			}
		}
	}
	return score
}

func parseRDAPVCard(raw []json.RawMessage) rdapContact {
	var contact rdapContact
	if len(raw) != 2 {
		return contact
	}
	var properties []json.RawMessage
	if err := json.Unmarshal(raw[1], &properties); err != nil {
		return contact
	}
	for _, rawProperty := range properties {
		var property []json.RawMessage
		if err := json.Unmarshal(rawProperty, &property); err != nil || len(property) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(property[0], &name); err != nil {
			continue
		}
		switch strings.ToLower(name) {
		case "fn", "org":
			if contact.organization == "" {
				contact.organization = rdapString(property[3])
			}
		case "adr":
			var parts []json.RawMessage
			if json.Unmarshal(property[3], &parts) == nil && len(parts) >= 7 {
				contact.city = rdapString(parts[3])
				contact.region = rdapString(parts[4])
				contact.country = rdapString(parts[6])
			}
			if contact.city == "" || contact.region == "" || contact.country == "" {
				var parameters map[string]json.RawMessage
				if json.Unmarshal(property[1], &parameters) == nil {
					city, region, country := parseRDAPAddressLabel(rdapString(parameters["label"]))
					if contact.city == "" {
						contact.city = city
					}
					if contact.region == "" {
						contact.region = region
					}
					if contact.country == "" {
						contact.country = country
					}
				}
			}
		}
	}
	return contact
}

func parseRDAPAddressLabel(label string) (string, string, string) {
	rawLines := strings.Split(strings.ReplaceAll(label, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return "", "", ""
	}
	country := lines[len(lines)-1]
	if len(lines) < 3 {
		return "", "", country
	}
	regionIndex := len(lines) - 2
	if containsDigit(lines[regionIndex]) && regionIndex >= 2 {
		regionIndex--
	}
	return lines[regionIndex-1], lines[regionIndex], country
}

func containsDigit(value string) bool {
	for _, character := range value {
		if character >= '0' && character <= '9' {
			return true
		}
	}
	return false
}

func rdapString(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return strings.TrimSpace(value)
	}
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return strings.TrimSpace(strings.Join(values, " "))
	}
	return ""
}

func formatAddressRange(start, end string) string {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" {
		return end
	}
	if end == "" || start == end {
		return start
	}
	return start + " - " + end
}

func rdapFirstNonempty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
