package alidns

import (
	"fmt"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockDNSProvider is a mock implementation of DNSProvider
type MockDNSProvider struct {
	AddTXTRecordFunc       func(domain, rr, value string) (string, error)
	DeleteRecordsByKeyFunc func(domain, rr, value string) error
}

func (m *MockDNSProvider) AddTXTRecord(domain, rr, value string) (string, error) {
	if m.AddTXTRecordFunc != nil {
		return m.AddTXTRecordFunc(domain, rr, value)
	}
	return "mock-record-id", nil
}

func (m *MockDNSProvider) DeleteRecordsByKey(domain, rr, value string) error {
	if m.DeleteRecordsByKeyFunc != nil {
		return m.DeleteRecordsByKeyFunc(domain, rr, value)
	}
	return nil
}

func TestSolver_Name(t *testing.T) {
	solver := &Solver{}
	assert.Equal(t, "alidns", solver.Name(), "Expected solver name to be 'alidns'")
}

func TestSolver_InitializeRejectsInvalidAllowedZones(t *testing.T) {
	for _, value := range []string{"", "example.com,", "bad..example", "bad_name.example"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(allowedZonesEnv, value)
			err := (&Solver{}).Initialize(nil, make(chan struct{}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), allowedZonesEnv)
		})
	}
}

func TestExtractDomainAndRR(t *testing.T) {
	solver := &Solver{}

	tests := []struct {
		name         string
		fqdn         string
		zone         string
		expectDomain string
		expectRR     string
	}{
		{
			name:         "simple case",
			fqdn:         "_acme-challenge.example.com.",
			zone:         "example.com.",
			expectDomain: "example.com",
			expectRR:     "_acme-challenge",
		},
		{
			name:         "subdomain case",
			fqdn:         "_acme-challenge.www.example.com.",
			zone:         "example.com.",
			expectDomain: "example.com",
			expectRR:     "_acme-challenge.www",
		},
		{
			name:         "zone without trailing dot",
			fqdn:         "_acme-challenge.example.com.",
			zone:         "example.com",
			expectDomain: "example.com",
			expectRR:     "_acme-challenge",
		},
		{
			name:         "nested subdomain",
			fqdn:         "_acme-challenge.api.v1.example.com.",
			zone:         "example.com.",
			expectDomain: "example.com",
			expectRR:     "_acme-challenge.api.v1",
		},
		{
			name:         "exact match",
			fqdn:         "example.com.",
			zone:         "example.com.",
			expectDomain: "example.com",
			expectRR:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, rr := solver.extractDomainAndRR(tt.fqdn, tt.zone)
			assert.Equal(t, tt.expectDomain, domain, "Domain mismatch")
			assert.Equal(t, tt.expectRR, rr, "RR mismatch")
		})
	}
}

func TestSolver_Present(t *testing.T) {
	mockProvider := &MockDNSProvider{
		AddTXTRecordFunc: func(domain, rr, value string) (string, error) {
			assert.Equal(t, "example.com", domain)
			assert.Equal(t, "_acme-challenge.api", rr)
			assert.Equal(t, "test-key-value", value)
			return "12345", nil
		},
	}

	solver := &Solver{
		dnsProvider:  mockProvider,
		allowedZones: allowedZoneSet("example.com"),
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.api.example.com.",
		ResolvedZone: "example.com.",
		Key:          "test-key-value",
	}

	err := solver.Present(ch)
	assert.NoError(t, err)
}

func TestSolver_Present_Error(t *testing.T) {
	mockProvider := &MockDNSProvider{
		AddTXTRecordFunc: func(domain, rr, value string) (string, error) {
			return "", fmt.Errorf("mock api error")
		},
	}

	solver := &Solver{
		dnsProvider:  mockProvider,
		allowedZones: allowedZoneSet("example.com"),
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.example.com.",
		ResolvedZone: "example.com.",
		Key:          "test-key-value",
	}

	err := solver.Present(ch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock api error")
}

func TestSolver_CleanUp(t *testing.T) {
	mockProvider := &MockDNSProvider{
		DeleteRecordsByKeyFunc: func(domain, rr, value string) error {
			assert.Equal(t, "example.com", domain)
			assert.Equal(t, "_acme-challenge", rr)
			assert.Equal(t, "test-key-value", value)
			return nil
		},
	}

	solver := &Solver{
		dnsProvider:  mockProvider,
		allowedZones: allowedZoneSet("example.com"),
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.example.com.",
		ResolvedZone: "example.com.",
		Key:          "test-key-value",
	}

	err := solver.CleanUp(ch)
	assert.NoError(t, err)
}

func TestSolver_CleanUp_Error(t *testing.T) {
	mockProvider := &MockDNSProvider{
		DeleteRecordsByKeyFunc: func(domain, rr, value string) error {
			return fmt.Errorf("mock delete error")
		},
	}

	solver := &Solver{
		dnsProvider:  mockProvider,
		allowedZones: allowedZoneSet("example.com"),
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.example.com.",
		ResolvedZone: "example.com.",
		Key:          "test-key-value",
	}

	err := solver.CleanUp(ch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock delete error")
}

func TestSolver_PresentRejectsDisallowedZonesBeforeProviderCall(t *testing.T) {
	for _, zone := range []string{"other.example", "example.com.attacker.example", "example.co"} {
		t.Run(zone, func(t *testing.T) {
			called := false
			solver := &Solver{
				dnsProvider: &MockDNSProvider{AddTXTRecordFunc: func(_, _, _ string) (string, error) {
					called = true
					return "", nil
				}},
				allowedZones: allowedZoneSet("example.com"),
			}

			err := solver.Present(&v1alpha1.ChallengeRequest{
				ResolvedFQDN: "_acme-challenge.sub.example.com.",
				ResolvedZone: zone,
				Key:          "key",
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not allowed")
			assert.False(t, called)
		})
	}
}

func TestSolver_CleanUpRejectsDisallowedZoneBeforeProviderCall(t *testing.T) {
	called := false
	solver := &Solver{
		dnsProvider: &MockDNSProvider{DeleteRecordsByKeyFunc: func(_, _, _ string) error {
			called = true
			return nil
		}},
		allowedZones: allowedZoneSet("example.com"),
	}

	err := solver.CleanUp(&v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.other.example.",
		ResolvedZone: "other.example.",
		Key:          "key",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
	assert.False(t, called)
}

func TestParseAllowedZonesNormalizesAndRejectsInvalidValues(t *testing.T) {
	allowed, err := parseAllowedZones(" EXAMPLE.COM. ,中文.com ")
	require.NoError(t, err)
	assert.Contains(t, allowed, "example.com")
	assert.Contains(t, allowed, "xn--fiq228c.com")

	for _, value := range []string{"", " ", "example.com,", "bad..example", "-bad.example", "bad_name.example"} {
		t.Run(value, func(t *testing.T) {
			_, err := parseAllowedZones(value)
			require.Error(t, err)
		})
	}
}

func TestSolver_Present_Uninitialized(t *testing.T) {
	solver := &Solver{dnsProvider: nil}
	ch := &v1alpha1.ChallengeRequest{}
	err := solver.Present(ch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSolver_CleanUp_Uninitialized(t *testing.T) {
	solver := &Solver{dnsProvider: nil}
	ch := &v1alpha1.ChallengeRequest{}
	err := solver.CleanUp(ch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestExtractDomainAndRR_Punycode(t *testing.T) {
	solver := &Solver{}

	tests := []struct {
		name         string
		fqdn         string
		zone         string
		expectDomain string
		expectRR     string
	}{
		{
			name:         "punycode zone",
			fqdn:         "_acme-challenge.xn--fiq228c.com.",
			zone:         "xn--fiq228c.com.",
			expectDomain: "中文.com",
			expectRR:     "_acme-challenge",
		},
		{
			name:         "punycode subdomain",
			fqdn:         "_acme-challenge.xn--0zwm56d.xn--fiq228c.com.",
			zone:         "xn--fiq228c.com.",
			expectDomain: "中文.com",
			expectRR:     "_acme-challenge.测试",
		},
		{
			name: "mixed punycode and unicode (should fail splitting if mismatch)",
			fqdn: "_acme-challenge.中文.com.",
			zone: "xn--fiq228c.com.",
			// Mismatch causes split failure, so RR is full FQDN.
			// zone "xn--fiq228c.com." -> "中文.com"
			// fqdn "_acme-challenge.中文.com."
			// rr = fqdn (since suffix doesn't match string-wise)
			// rr -> ToUnicode("_acme-challenge.中文.com.") -> "_acme-challenge.中文.com"
			expectDomain: "中文.com",
			expectRR:     "_acme-challenge.中文.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, rr := solver.extractDomainAndRR(tt.fqdn, tt.zone)
			assert.Equal(t, tt.expectDomain, domain, "Domain mismatch")
			assert.Equal(t, tt.expectRR, rr, "RR mismatch")
		})
	}
}

func allowedZoneSet(zones ...string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(zones))
	for _, zone := range zones {
		allowed[zone] = struct{}{}
	}
	return allowed
}
