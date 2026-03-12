package kyverno

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
)

func TestBuildClusterPolicy(t *testing.T) {
	p := PolicyParams{
		Name:        "test-policy",
		Description: "Test policy for MV1001",
		Rules: []Rule{
			{
				Name:       "deny-privileged",
				MatchKinds: WorkloadKinds,
				Type:       RuleTypeValidate,
				Body: `    validate:
      validationFailureAction: Enforce
      message: "no privileged"`,
			},
		},
	}
	got, err := BuildClusterPolicy(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, got, "apiVersion: kyverno.io/v1")
	mustContain(t, got, "kind: ClusterPolicy")
	mustContain(t, got, "name: test-policy")
	mustContain(t, got, "Test policy for MV1001")
	mustContain(t, got, "deny-privileged")
	mustContain(t, got, "Deployment")
}

func TestBuildClusterPolicy_WithNamespace(t *testing.T) {
	p := PolicyParams{
		Name:        "ns-policy",
		Description: "Namespaced policy",
		Rules: []Rule{
			{
				Name:       "rule-1",
				MatchKinds: []string{"Pod"},
				Namespaces: []string{"production"},
				Type:       RuleTypeValidate,
				Body:       "    validate:\n      validationFailureAction: Enforce",
			},
		},
	}
	got, err := BuildClusterPolicy(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, got, "namespaces:")
	mustContain(t, got, "production")
}

func TestValidationAction(t *testing.T) {
	t.Run("error violation → Enforce", func(t *testing.T) {
		violations := []input.Violation{{Severity: input.SeverityError}}
		if got := ValidationAction(violations); got != "Enforce" {
			t.Errorf("want Enforce, got %s", got)
		}
	})

	t.Run("warning only → Audit", func(t *testing.T) {
		violations := []input.Violation{{Severity: input.SeverityWarning}}
		if got := ValidationAction(violations); got != "Audit" {
			t.Errorf("want Audit, got %s", got)
		}
	})

	t.Run("empty → Audit", func(t *testing.T) {
		if got := ValidationAction(nil); got != "Audit" {
			t.Errorf("want Audit, got %s", got)
		}
	})

	t.Run("mixed severities → Enforce (error present)", func(t *testing.T) {
		violations := []input.Violation{
			{Severity: input.SeverityInfo},
			{Severity: input.SeverityError},
		}
		if got := ValidationAction(violations); got != "Enforce" {
			t.Errorf("want Enforce, got %s", got)
		}
	})
}

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("output missing %q\nfull output:\n%s", substr, s)
	}
}
