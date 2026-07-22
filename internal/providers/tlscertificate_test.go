package providers

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeTLSCertificateFetcher struct {
	certificates []*x509.Certificate
	err          error
	address      string
	port         int
}

func (f *fakeTLSCertificateFetcher) Fetch(_ context.Context, address string, port int, _ string) ([]*x509.Certificate, error) {
	f.address = address
	f.port = port
	return f.certificates, f.err
}

func TestTLSCertificateProviderEmitsCertificateEvidence(t *testing.T) {
	now := time.Now().UTC()
	certificate := &x509.Certificate{
		Raw: []byte("certificate"), Subject: pkix.Name{CommonName: "ignored.example"},
		DNSNames:    []string{"Router.Example.", "router.example", "*.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	fetcher := &fakeTLSCertificateFetcher{certificates: []*x509.Certificate{certificate}}
	provider := NewTLSCertificateProvider(fetcher)
	var evidence *Evidence
	err := provider.Run(context.Background(), Request{Target: "::ffff:192.0.2.10", Options: map[string]string{"port": "8443"}}, func(event Event) error {
		evidence = event.Evidence
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fetcher.address != "192.0.2.10" || fetcher.port != 8443 || evidence == nil || evidence.Kind != "tls.certificate" || evidence.Subject.Key != "192.0.2.10" {
		t.Fatalf("fetch/evidence = %#v %#v", fetcher, evidence)
	}
	var payload TLSCertificate
	if err := json.Unmarshal(evidence.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(certificate.Raw)
	if len(payload.DNSNames) != 2 || payload.DNSNames[0] != "router.example" || payload.CommonName != "ignored.example" ||
		payload.FingerprintSHA256 != strings.ToUpper(hex.EncodeToString(sum[:])) || len(payload.IPAddresses) != 1 || payload.Verified ||
		payload.VerificationName != "router.example" || payload.VerificationError == "" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestTLSCertificateProviderUsesNativeHandshake(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, rawPort, err := net.SplitHostPort(endpoint.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	var result TLSCertificate
	err = NewTLSCertificateProvider(nil).Run(context.Background(), Request{Target: host, Options: map[string]string{"port": rawPort}}, func(event Event) error {
		return json.Unmarshal(event.Evidence.Payload, &result)
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Port != port || result.FingerprintSHA256 == "" || len(result.DNSNames) == 0 {
		t.Fatalf("certificate = %#v", result)
	}
}

func TestTLSCertificateProviderMetadataAndErrors(t *testing.T) {
	provider := NewTLSCertificateProvider(&fakeTLSCertificateFetcher{})
	descriptor := provider.Describe()
	status := provider.Probe(context.Background())
	if descriptor.ID != "tls-certificate" || descriptor.Capability != "tls-certificate" || !status.Available || status.Path != "native" {
		t.Fatalf("descriptor/status = %#v %#v", descriptor, status)
	}
	for _, request := range []Request{
		{Target: "bad", Options: map[string]string{"port": "443"}},
		{Target: "192.0.2.1"},
		{Target: "192.0.2.1", Options: map[string]string{"port": "65536"}},
	} {
		if err := provider.Run(context.Background(), request, func(Event) error { return nil }); err == nil {
			t.Fatalf("request succeeded: %#v", request)
		}
	}
	want := errors.New("handshake failed")
	fetcher := &fakeTLSCertificateFetcher{err: want}
	var failure *Evidence
	if err := NewTLSCertificateProvider(fetcher).Run(context.Background(), Request{Target: "192.0.2.1", Options: map[string]string{"port": "443"}}, func(event Event) error {
		failure = event.Evidence
		return nil
	}); !errors.Is(err, want) {
		t.Fatalf("fetch error = %v", err)
	}
	if failure == nil || failure.Kind != "tls.certificate.failure" {
		t.Fatalf("failure evidence = %#v", failure)
	}
	var failurePayload TLSCertificateFailure
	if err := json.Unmarshal(failure.Payload, &failurePayload); err != nil || failurePayload.Port != 443 || failurePayload.Error != want.Error() {
		t.Fatalf("failure payload = %#v, %v", failurePayload, err)
	}
	fetcher.err = nil
	if err := NewTLSCertificateProvider(fetcher).Run(context.Background(), Request{Target: "192.0.2.1", Options: map[string]string{"port": "443"}}, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "did not present") {
		t.Fatalf("empty certificates error = %v", err)
	}
	if err := NewTLSCertificateProvider(fetcher).Run(context.Background(), Request{Target: "192.0.2.1", Options: map[string]string{"port": "443"}}, nil); err == nil || !strings.Contains(err.Error(), "event receiver") {
		t.Fatalf("nil receiver error = %v", err)
	}
}
