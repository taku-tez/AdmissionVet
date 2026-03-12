package webhook

import (
	"os"
	"path/filepath"
	"testing"
)

// ── YAML fixture helpers ─────────────────────────────────────────────────────

func writeWebhookFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webhook.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	return path
}

func findFinding(findings []Finding, ruleID string) *Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// ── AV3001: failurePolicy: Ignore ───────────────────────────────────────────

const av3001YAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
webhooks:
  - name: test.webhook.io
    failurePolicy: Ignore
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system]
    clientConfig:
      url: "https://webhook.example.com"
`

func TestAV3001_FailurePolicyIgnore(t *testing.T) {
	path := writeWebhookFile(t, av3001YAML)
	findings, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findFinding(findings, "AV3001")
	if f == nil {
		t.Fatal("expected AV3001 finding for failurePolicy: Ignore")
	}
	if f.Severity != SeverityHigh {
		t.Errorf("want HIGH, got %s", f.Severity)
	}
}

// ── AV3002: timeoutSeconds too short ────────────────────────────────────────

const av3002YAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
webhooks:
  - name: test.webhook.io
    failurePolicy: Fail
    timeoutSeconds: 5
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system]
    clientConfig:
      url: "https://webhook.example.com"
`

func TestAV3002_TimeoutTooShort(t *testing.T) {
	path := writeWebhookFile(t, av3002YAML)
	findings, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findFinding(findings, "AV3002")
	if f == nil {
		t.Fatal("expected AV3002 finding for timeoutSeconds: 5")
	}
	if f.Severity != SeverityMedium {
		t.Errorf("want MEDIUM, got %s", f.Severity)
	}
}

func TestAV3002_TimeoutAcceptable(t *testing.T) {
	yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
webhooks:
  - name: test.webhook.io
    failurePolicy: Fail
    timeoutSeconds: 30
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system]
    clientConfig:
      url: "https://webhook.example.com"
`
	path := writeWebhookFile(t, yaml)
	findings, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f := findFinding(findings, "AV3002"); f != nil {
		t.Errorf("unexpected AV3002 for timeoutSeconds: 30")
	}
}

// ── AV3003: kube-system not excluded ────────────────────────────────────────

const av3003YAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
webhooks:
  - name: test.webhook.io
    failurePolicy: Fail
    clientConfig:
      url: "https://webhook.example.com"
`

func TestAV3003_KubeSystemNotExcluded(t *testing.T) {
	path := writeWebhookFile(t, av3003YAML)
	findings, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findFinding(findings, "AV3003")
	if f == nil {
		t.Fatal("expected AV3003 finding when kube-system not excluded")
	}
	if f.Severity != SeverityMedium {
		t.Errorf("want MEDIUM, got %s", f.Severity)
	}
}

func TestAV3003_KubeSystemExcluded(t *testing.T) {
	yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
webhooks:
  - name: test.webhook.io
    failurePolicy: Fail
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system]
    clientConfig:
      url: "https://webhook.example.com"
`
	path := writeWebhookFile(t, yaml)
	findings, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f := findFinding(findings, "AV3003"); f != nil {
		t.Errorf("unexpected AV3003 when kube-system is excluded")
	}
}

// ── AV4001: reinvocationPolicy: IfNeeded ────────────────────────────────────

const av4001YAML = `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: mutating-webhook
webhooks:
  - name: mutate.webhook.io
    failurePolicy: Fail
    reinvocationPolicy: IfNeeded
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system]
    clientConfig:
      url: "https://webhook.example.com"
`

func TestAV4001_ReinvocationIfNeeded(t *testing.T) {
	path := writeWebhookFile(t, av4001YAML)
	findings, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findFinding(findings, "AV4001")
	if f == nil {
		t.Fatal("expected AV4001 finding for reinvocationPolicy: IfNeeded")
	}
	if f.Severity != SeverityLow {
		t.Errorf("want LOW, got %s", f.Severity)
	}
}

// ── ExcludesKubeSystem ───────────────────────────────────────────────────────

func TestExcludesKubeSystem(t *testing.T) {
	tests := []struct {
		name string
		sel  *labelSelector
		want bool
	}{
		{
			name: "nil selector → false",
			sel:  nil,
			want: false,
		},
		{
			name: "NotIn kube-system → true",
			sel: &labelSelector{
				MatchExpressions: []matchExpression{
					{Key: "kubernetes.io/metadata.name", Operator: "NotIn", Values: []string{"kube-system"}},
				},
			},
			want: true,
		},
		{
			name: "wrong values → false",
			sel: &labelSelector{
				MatchExpressions: []matchExpression{
					{Key: "kubernetes.io/metadata.name", Operator: "NotIn", Values: []string{"other"}},
				},
			},
			want: false,
		},
		{
			name: "DoesNotExist control-plane → true",
			sel: &labelSelector{
				MatchExpressions: []matchExpression{
					{Key: "control-plane", Operator: "DoesNotExist"},
				},
			},
			want: true,
		},
		{
			name: "matchLabel admission-webhook=enabled → true",
			sel: &labelSelector{
				MatchLabels: map[string]string{"admission-webhook": "enabled"},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := excludesKubeSystem(tc.sel)
			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

// ── MissingFile ───────────────────────────────────────────────────────────────

func TestValidateFile_MissingFile(t *testing.T) {
	_, err := ValidateFile("/nonexistent/webhook.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
