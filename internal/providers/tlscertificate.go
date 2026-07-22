package providers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const tlsCertificateTimeout = 4 * time.Second

// TLSCertificateFetcher retrieves the certificates presented by one TLS endpoint.
type TLSCertificateFetcher interface {
	Fetch(context.Context, string, int, string) ([]*x509.Certificate, error)
}

// TLSCertificate is the evidence payload for a TLS endpoint's leaf certificate.
type TLSCertificate struct {
	Port              int       `json:"port"`
	DNSNames          []string  `json:"dnsNames"`
	CommonName        string    `json:"commonName,omitempty"`
	IPAddresses       []string  `json:"ipAddresses,omitempty"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	VerificationName  string    `json:"verificationName"`
	Verified          bool      `json:"verified"`
	VerificationError string    `json:"verificationError,omitempty"`
}

// TLSCertificateFailure is the evidence payload for an HTTPS endpoint whose
// TLS handshake did not yield a certificate.
type TLSCertificateFailure struct {
	Port  int    `json:"port"`
	Error string `json:"error"`
}

type tlsCertificateProvider struct {
	fetcher TLSCertificateFetcher
}

type nativeTLSCertificateFetcher struct{}

// NewTLSCertificateProvider returns a native provider that inspects certificates
// presented by HTTPS endpoints. A nil fetcher selects Go's TLS client.
func NewTLSCertificateProvider(fetcher TLSCertificateFetcher) Provider {
	if fetcher == nil {
		fetcher = nativeTLSCertificateFetcher{}
	}
	return &tlsCertificateProvider{fetcher: fetcher}
}

func (p *tlsCertificateProvider) Describe() Descriptor {
	return Descriptor{
		ID: "tls-certificate", Capability: "tls-certificate", Label: "TLS Certificate",
		SupportedOS: []string{"darwin", "linux"}, OSPriorities: map[string]int{"darwin": 100, "linux": 100},
	}
}

func (p *tlsCertificateProvider) Probe(context.Context) Status {
	return Status{Capability: "tls-certificate", ProviderID: "tls-certificate", Label: "TLS Certificate", Status: "available", Available: true, Path: "native"}
}

func (p *tlsCertificateProvider) Run(parent context.Context, request Request, emit EmitFunc) error {
	address, err := netip.ParseAddr(request.Target)
	if err != nil {
		return fmt.Errorf("TLS certificate target must be an IP address: %w", err)
	}
	port, err := requestPort(request.Options)
	if err != nil {
		return err
	}
	if emit == nil {
		return errors.New("TLS certificate provider requires an event receiver")
	}
	ctx, cancel := context.WithTimeout(parent, tlsCertificateTimeout)
	defer cancel()
	certificates, err := p.fetcher.Fetch(ctx, address.Unmap().String(), port, "")
	if err != nil {
		if parent.Err() == nil {
			failure := TLSCertificateFailure{Port: port, Error: err.Error()}
			encoded, marshalErr := json.Marshal(failure)
			if marshalErr != nil {
				return errors.Join(err, marshalErr)
			}
			emitErr := emit(Event{Type: "evidence", Evidence: &Evidence{
				Kind: "tls.certificate.failure", Subject: EntityRef{Type: "address", Key: address.Unmap().String()},
				PayloadVersion: 1, Payload: encoded, ObservedAt: time.Now().UTC(), Confidence: 1,
			}})
			if emitErr != nil {
				return errors.Join(err, emitErr)
			}
		}
		return err
	}
	if len(certificates) == 0 || certificates[0] == nil {
		return errors.New("TLS endpoint did not present a certificate")
	}
	leaf := certificates[0]
	payload := TLSCertificate{
		Port:              port,
		DNSNames:          normalizedCertificateNames(leaf.DNSNames),
		CommonName:        strings.TrimSuffix(strings.TrimSpace(leaf.Subject.CommonName), "."),
		FingerprintSHA256: certificateFingerprint(leaf),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
	}
	for _, item := range leaf.IPAddresses {
		payload.IPAddresses = append(payload.IPAddresses, item.String())
	}
	payload.VerificationName = verificationName(payload, address)
	payload.Verified, payload.VerificationError = verifyCertificate(certificates, payload.VerificationName)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return emit(Event{Type: "evidence", Evidence: &Evidence{
		Kind: "tls.certificate", Subject: EntityRef{Type: "address", Key: address.Unmap().String()},
		PayloadVersion: 1, Payload: encoded, ObservedAt: time.Now().UTC(), Confidence: 0.95,
	}})
}

func (nativeTLSCertificateFetcher) Fetch(ctx context.Context, address string, port int, serverName string) ([]*x509.Certificate, error) {
	config := &tls.Config{ // nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- collection is followed by offline verification.
		// Certificate trust is evaluated after the handshake so Lantern can retain
		// self-signed, expired, and otherwise untrusted certificates as evidence.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
	}
	dialer := tls.Dialer{Config: config}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("TLS handshake with %s:%d: %w", address, port, err)
	}
	defer connection.Close()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return nil, errors.New("TLS dialer returned a non-TLS connection")
	}
	return append([]*x509.Certificate(nil), tlsConnection.ConnectionState().PeerCertificates...), nil
}

func requestPort(options map[string]string) (int, error) {
	raw := strings.TrimSpace(options["port"])
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("TLS certificate provider requires a valid port")
	}
	return port, nil
}

func normalizedCertificateNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func certificateFingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func verificationName(certificate TLSCertificate, address netip.Addr) string {
	for _, name := range certificate.DNSNames {
		if !strings.Contains(name, "*") {
			return name
		}
	}
	if len(certificate.DNSNames) == 0 && certificate.CommonName != "" && !strings.Contains(certificate.CommonName, "*") {
		return certificate.CommonName
	}
	return address.Unmap().String()
}

func verifyCertificate(certificates []*x509.Certificate, name string) (bool, string) {
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: intermediates})
	if err == nil {
		return true, ""
	}
	return false, err.Error()
}
