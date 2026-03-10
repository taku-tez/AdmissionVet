package webhook

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// ValidateFile reads a YAML file containing webhook configurations and returns findings.
func ValidateFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return validateYAML(data)
}

// ValidateCluster fetches webhook configurations from the cluster via kubectl.
func ValidateCluster() ([]Finding, error) {
	var findings []Finding

	for _, kind := range []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"} {
		out, err := exec.Command("kubectl", "get", kind, "-o", "yaml").Output()
		if err != nil {
			return nil, fmt.Errorf("kubectl get %s: %w", kind, err)
		}
		f, err := validateYAML(out)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}
	return findings, nil
}

// validateYAML parses one or more YAML documents and runs all checks.
func validateYAML(data []byte) ([]Finding, error) {
	var findings []Finding
	decoder := newYAMLDecoder(data)
	for {
		doc, err := decoder()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing YAML: %w", err)
		}
		if doc == nil {
			continue
		}

		var cfg webhookConfig
		if err := yaml.Unmarshal(doc, &cfg); err != nil {
			return nil, fmt.Errorf("unmarshalling webhook config: %w", err)
		}

		switch cfg.Kind {
		case "ValidatingWebhookConfiguration":
			findings = append(findings, checkValidating(cfg)...)
		case "MutatingWebhookConfiguration":
			findings = append(findings, checkMutating(cfg)...)
		case "List":
			// kubectl get -o yaml returns a List; recurse into items.
			var list struct {
				Items []webhookConfig `yaml:"items"`
			}
			if err := yaml.Unmarshal(doc, &list); err == nil {
				for _, item := range list.Items {
					switch item.Kind {
					case "ValidatingWebhookConfiguration":
						findings = append(findings, checkValidating(item)...)
					case "MutatingWebhookConfiguration":
						findings = append(findings, checkMutating(item)...)
					}
				}
			}
		}
	}
	return findings, nil
}

// checkValidating runs all ValidatingWebhookConfiguration checks.
func checkValidating(cfg webhookConfig) []Finding {
	var findings []Finding
	name := cfg.Metadata.Name
	for _, wh := range cfg.Webhooks {
		findings = append(findings, checkCommon(name, "ValidatingWebhookConfiguration", wh)...)
	}
	return findings
}

// checkMutating runs all MutatingWebhookConfiguration checks.
func checkMutating(cfg webhookConfig) []Finding {
	var findings []Finding
	name := cfg.Metadata.Name
	for _, wh := range cfg.Webhooks {
		findings = append(findings, checkCommon(name, "MutatingWebhookConfiguration", wh)...)
		// Mutating-specific: reinvocationPolicy
		findings = append(findings, checkReinvocation(name, wh)...)
	}
	return findings
}

func checkCommon(configName, kind string, wh webhookEntry) []Finding {
	var findings []Finding
	label := fmt.Sprintf("%s/%s", configName, wh.Name)

	// AV3001: failurePolicy: Ignore allows webhook bypass.
	if strings.EqualFold(wh.FailurePolicy, "Ignore") {
		findings = append(findings, Finding{
			RuleID:   "AV3001",
			Severity: SeverityHigh,
			Webhook:  label,
			Kind:     kind,
			Message: fmt.Sprintf(
				"webhook '%s' has failurePolicy: Ignore — if the webhook is unreachable, admission is allowed (bypass risk)",
				label),
		})
	}

	// AV3002: timeoutSeconds too short (< 10s risks false failures).
	if wh.TimeoutSeconds != nil && *wh.TimeoutSeconds < 10 {
		findings = append(findings, Finding{
			RuleID:   "AV3002",
			Severity: SeverityMedium,
			Webhook:  label,
			Kind:     kind,
			Message: fmt.Sprintf(
				"webhook '%s' has timeoutSeconds: %d (< 10s) — may cause false failures under load",
				label, *wh.TimeoutSeconds),
		})
	}

	// AV3003: namespaceSelector missing kube-system exclusion.
	if !excludesKubeSystem(wh.NamespaceSelector) {
		findings = append(findings, Finding{
			RuleID:   "AV3003",
			Severity: SeverityMedium,
			Webhook:  label,
			Kind:     kind,
			Message: fmt.Sprintf(
				"webhook '%s' does not exclude kube-system in namespaceSelector — system pods may be blocked",
				label),
		})
	}

	// AV3004: TLS certificate expiry.
	if wh.ClientConfig.CABundle != "" {
		certFindings := checkCertExpiry(label, kind, wh.ClientConfig.CABundle)
		findings = append(findings, certFindings...)
	}

	return findings
}

// checkReinvocation checks for potential reinvocation loops in MutatingWebhooks.
func checkReinvocation(configName string, wh webhookEntry) []Finding {
	var findings []Finding
	label := fmt.Sprintf("%s/%s", configName, wh.Name)

	if strings.EqualFold(wh.ReinvocationPolicy, "IfNeeded") {
		findings = append(findings, Finding{
			RuleID:   "AV4001",
			Severity: SeverityLow,
			Webhook:  label,
			Kind:     "MutatingWebhookConfiguration",
			Message: fmt.Sprintf(
				"webhook '%s' uses reinvocationPolicy: IfNeeded — ensure mutations are idempotent to avoid infinite loops",
				label),
		})
	}

	return findings
}

// excludesKubeSystem returns true if the selector explicitly excludes kube-system.
func excludesKubeSystem(sel *labelSelector) bool {
	if sel == nil {
		return false
	}
	for _, expr := range sel.MatchExpressions {
		if expr.Key == "kubernetes.io/metadata.name" && strings.EqualFold(expr.Operator, "NotIn") {
			for _, v := range expr.Values {
				if v == "kube-system" {
					return true
				}
			}
		}
		if expr.Key == "control-plane" && strings.EqualFold(expr.Operator, "DoesNotExist") {
			return true
		}
	}
	for k, v := range sel.MatchLabels {
		if k == "admission-webhook" && v == "enabled" {
			return true
		}
	}
	return false
}

// checkCertExpiry decodes the caBundle, verifies the certificate chain, and checks expiry.
func checkCertExpiry(webhookLabel, kind, caBundle string) []Finding {
	var findings []Finding

	pemData, err := base64.StdEncoding.DecodeString(caBundle)
	if err != nil {
		return findings
	}

	// Parse all certificates from the PEM bundle.
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return findings
	}

	// AV3005: Check each certificate for expiry.
	for _, cert := range certs {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		label := cert.Subject.CommonName
		if label == "" {
			label = webhookLabel
		}

		if daysLeft <= 0 {
			findings = append(findings, Finding{
				RuleID:   "AV3005",
				Severity: SeverityCritical,
				Webhook:  webhookLabel,
				Kind:     kind,
				Message:  fmt.Sprintf("TLS certificate '%s' has EXPIRED (expired: %s)", label, cert.NotAfter.Format("2006-01-02")),
			})
		} else if daysLeft <= 30 {
			findings = append(findings, Finding{
				RuleID:   "AV3005",
				Severity: SeverityHigh,
				Webhook:  webhookLabel,
				Kind:     kind,
				Message:  fmt.Sprintf("TLS certificate '%s' expires in %d days (%s)", label, daysLeft, cert.NotAfter.Format("2006-01-02")),
			})
		}
	}

	// AV3006: Verify certificate chain integrity.
	findings = append(findings, checkCertChain(webhookLabel, kind, certs)...)

	return findings
}

// checkCertChain verifies that the certificates form a valid chain.
func checkCertChain(webhookLabel, kind string, certs []*x509.Certificate) []Finding {
	var findings []Finding
	if len(certs) < 2 {
		// Single cert: check if it is self-signed.
		if len(certs) == 1 {
			c := certs[0]
			if c.Issuer.String() == c.Subject.String() {
				findings = append(findings, Finding{
					RuleID:   "AV3006",
					Severity: SeverityLow,
					Webhook:  webhookLabel,
					Kind:     kind,
					Message:  fmt.Sprintf("webhook '%s' uses a self-signed TLS certificate — consider using a proper CA", webhookLabel),
				})
			}
		}
		return findings
	}

	// Build root pool from the last cert in the chain (assumed to be the root CA).
	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	// Build intermediates pool from middle certs.
	intermediates := x509.NewCertPool()
	for _, c := range certs[1 : len(certs)-1] {
		intermediates.AddCert(c)
	}

	// Verify the leaf cert.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}
	if _, err := certs[0].Verify(opts); err != nil {
		findings = append(findings, Finding{
			RuleID:   "AV3006",
			Severity: SeverityHigh,
			Webhook:  webhookLabel,
			Kind:     kind,
			Message:  fmt.Sprintf("webhook '%s' TLS certificate chain is invalid: %v", webhookLabel, err),
		})
	}

	return findings
}

// TestReachability tests the reachability and response time of a webhook endpoint.
type ReachabilityResult struct {
	Webhook      string
	URL          string
	Reachable    bool
	ResponseTime time.Duration
	Error        string
}

// TestWebhookReachability tests that the webhook service endpoint is reachable.
func TestWebhookReachability(path string) ([]ReachabilityResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var results []ReachabilityResult
	decoder := newYAMLDecoder(data)
	for {
		doc, err := decoder()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		var cfg webhookConfig
		if err := yaml.Unmarshal(doc, &cfg); err != nil {
			continue
		}

		for _, wh := range cfg.Webhooks {
			url := webhookURL(wh)
			if url == "" {
				continue
			}

			result := ReachabilityResult{
				Webhook: fmt.Sprintf("%s/%s", cfg.Metadata.Name, wh.Name),
				URL:     url,
			}

			start := time.Now()
			conn, err := tls.Dial("tcp", url, &tls.Config{InsecureSkipVerify: true})
			result.ResponseTime = time.Since(start)
			if err != nil {
				result.Reachable = false
				result.Error = err.Error()
			} else {
				conn.Close()
				result.Reachable = true
			}

			results = append(results, result)
		}
	}
	return results, nil
}

func webhookURL(wh webhookEntry) string {
	if wh.ClientConfig.URL != "" {
		return wh.ClientConfig.URL
	}
	if svc := wh.ClientConfig.Service; svc != nil {
		port := svc.Port
		if port == 0 {
			port = 443
		}
		return fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, port)
	}
	return ""
}

// newYAMLDecoder returns a function that decodes one YAML document at a time.
func newYAMLDecoder(data []byte) func() ([]byte, error) {
	docs := bytes.Split(data, []byte("\n---"))
	idx := 0
	return func() ([]byte, error) {
		for idx < len(docs) {
			doc := bytes.TrimSpace(docs[idx])
			idx++
			if len(doc) == 0 {
				continue
			}
			return doc, nil
		}
		return nil, io.EOF
	}
}
