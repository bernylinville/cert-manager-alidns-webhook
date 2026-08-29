package alidns

import (
	"fmt"
	"os"
	"strings"

	"log/slog"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"golang.org/x/net/idna"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// Solver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
// 实现 cert-manager webhook Solver interface
const allowedZonesEnv = "ALIDNS_ALLOWED_ZONES"

type Solver struct {
	dnsProvider  DNSProvider
	allowedZones map[string]struct{}
}

func NewSolver(dnsProvider DNSProvider) *Solver {
	return &Solver{
		dnsProvider: dnsProvider,
	}
}

// Config is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.

type Config struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.

func (s *Solver) Name() string {
	return "alidns"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *Solver) Present(ch *v1alpha1.ChallengeRequest) error {
	if s.dnsProvider == nil {
		return fmt.Errorf("alidns client not initialized")
	}
	if err := s.ensureZoneAllowed(ch.ResolvedZone); err != nil {
		return err
	}

	// not required in this solver
	// cfg, err := loadConfig(ch.Config)
	// if err != nil {
	// 	return fmt.Errorf("failed to load config: %w", err)
	// }

	// 解析域名和记录名
	domain, rr := s.extractDomainAndRR(ch.ResolvedFQDN, ch.ResolvedZone)

	// 添加 TXT 记录
	recordId, err := s.dnsProvider.AddTXTRecord(domain, rr, ch.Key)
	if err != nil {
		return fmt.Errorf("failed to add TXT record: %w", err)
	}

	slog.Info("Successfully added TXT record",
		"domain", domain,
		"rr", rr,
		"value", ch.Key,
		"recordId", recordId,
	)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *Solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	if s.dnsProvider == nil {
		return fmt.Errorf("alidns client not initialized")
	}
	if err := s.ensureZoneAllowed(ch.ResolvedZone); err != nil {
		return err
	}

	// not required in this solver
	// cfg, err := loadConfig(ch.Config)
	// if err != nil {
	// 	return fmt.Errorf("failed to load config: %w", err)
	// }

	// 解析域名和记录名
	domain, rr := s.extractDomainAndRR(ch.ResolvedFQDN, ch.ResolvedZone)

	// 删除记录（根据 key 值匹配）
	err := s.dnsProvider.DeleteRecordsByKey(domain, rr, ch.Key)
	if err != nil {
		return fmt.Errorf("failed to delete TXT record: %w", err)
	}

	slog.Info("Successfully deleted TXT record",
		"domain", domain,
		"rr", rr,
		"value", ch.Key,
	)
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *Solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	allowedZones, err := parseAllowedZones(os.Getenv(allowedZonesEnv))
	if err != nil {
		return fmt.Errorf("invalid %s: %w", allowedZonesEnv, err)
	}

	client, err := NewDNSProvider()
	if err != nil {
		return fmt.Errorf("failed to create alidns client: %w", err)
	}
	s.allowedZones = allowedZones
	s.dnsProvider = client
	return nil
}

func (s *Solver) ensureZoneAllowed(zone string) error {
	normalized, err := normalizeZone(zone)
	if err != nil {
		return fmt.Errorf("invalid resolved zone %q: %w", zone, err)
	}
	if _, allowed := s.allowedZones[normalized]; !allowed {
		return fmt.Errorf("resolved zone %q is not allowed", normalized)
	}
	return nil
}

func parseAllowedZones(raw string) (map[string]struct{}, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("must contain at least one DNS zone")
	}

	allowed := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		if strings.TrimSpace(item) == "" {
			return nil, fmt.Errorf("contains an empty DNS zone")
		}
		zone, err := normalizeZone(item)
		if err != nil {
			return nil, fmt.Errorf("zone %q: %w", strings.TrimSpace(item), err)
		}
		allowed[zone] = struct{}{}
	}
	return allowed, nil
}

func normalizeZone(zone string) (string, error) {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" || len(zone) > 253 {
		return "", fmt.Errorf("is not a valid DNS zone")
	}

	ascii, err := idna.Lookup.ToASCII(zone)
	if err != nil {
		return "", fmt.Errorf("is not a valid IDNA DNS zone: %w", err)
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("is not a valid DNS zone")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", fmt.Errorf("is not a valid DNS zone")
			}
		}
	}
	return ascii, nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
// func loadConfig(cfgJSON *extapi.JSON) (*Config, error) {
// 	cfg := &Config{}
// 	if cfgJSON == nil {
// 		return cfg, nil
// 	}

// 	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
// 		return nil, fmt.Errorf("error decoding solver config: %w", err)
// 	}

// 	return cfg, nil
// }

// extractDomainAndRR 从 FQDN 和 Zone 中提取域名和记录名
// 例如：
//
//	ResolvedFQDN: _acme-challenge.example.com.example.com.
//	ResolvedZone: example.com.
//
// 返回：
//
//	domain: example.com
//	rr: _acme-challenge.example.com
func (s *Solver) extractDomainAndRR(fqdn, zone string) (string, string) {
	fqdn = util.UnFqdn(fqdn)
	zone = util.UnFqdn(zone)

	// 从 FQDN 中移除 zone 部分，得到记录名
	rr := strings.TrimSuffix(fqdn, zone)

	// 移除 rr 可能的结尾点
	rr = strings.TrimSuffix(rr, ".")

	// Convert Punycode to Unicode for both zone (domain) and rr
	if uZone, err := idna.ToUnicode(zone); err == nil {
		zone = uZone
	}
	if uRR, err := idna.ToUnicode(rr); err == nil {
		rr = uRR
	}

	return zone, rr
}
