package networkvet_test

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"

	// Trigger init() registrations.
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/networkvet"
)

func errViolations(ruleID string) []input.Violation {
	return []input.Violation{{RuleID: ruleID, Severity: input.SeverityError}}
}

func mustContain(t *testing.T, yaml, substr string) {
	t.Helper()
	if !strings.Contains(yaml, substr) {
		t.Errorf("expected YAML to contain %q\ngot:\n%s", substr, yaml)
	}
}

// ── NV1001 ───────────────────────────────────────────────────────────────────

func TestKyverno_NV1001_ClusterPolicy(t *testing.T) {
	g, ok := policy.Get("kyverno", "NV1001")
	if !ok {
		t.Fatal("no kyverno generator registered for NV1001")
	}
	p, err := g.Generate(errViolations("NV1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "kind: ClusterPolicy")
	mustContain(t, p.ClusterPolicy, "nv1001-default-deny-netpol")
	// Generate rule targets Namespace resources.
	mustContain(t, p.ClusterPolicy, "Namespace")
	// Generates a NetworkPolicy.
	mustContain(t, p.ClusterPolicy, "kind: NetworkPolicy")
	mustContain(t, p.ClusterPolicy, "default-deny-all")
	mustContain(t, p.ClusterPolicy, "podSelector: {}")
	mustContain(t, p.ClusterPolicy, "Ingress")
	mustContain(t, p.ClusterPolicy, "Egress")
	mustContain(t, p.ClusterPolicy, "synchronize: true")
}

func TestKyverno_NV1001_NetworkPolicy(t *testing.T) {
	g, ok := policy.Get("kyverno", "NV1001")
	if !ok {
		t.Fatal("no kyverno generator registered for NV1001")
	}
	p, err := g.Generate(errViolations("NV1001"), "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Standalone NetworkPolicy for specified namespace.
	if p.NetworkPolicy == "" {
		t.Error("expected a standalone NetworkPolicy YAML")
	}
	mustContain(t, p.NetworkPolicy, "kind: NetworkPolicy")
	mustContain(t, p.NetworkPolicy, "production")
}

func TestKyverno_NV1001_NoConstraintTemplate(t *testing.T) {
	g, ok := policy.Get("kyverno", "NV1001")
	if !ok {
		t.Fatal("no kyverno generator registered for NV1001")
	}
	p, err := g.Generate(errViolations("NV1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ConstraintTemplate != "" {
		t.Error("Kyverno NV1001 should not produce a ConstraintTemplate")
	}
}

func TestKyverno_NV1001_NoConstraint(t *testing.T) {
	g, ok := policy.Get("kyverno", "NV1001")
	if !ok {
		t.Fatal("no kyverno generator registered for NV1001")
	}
	p, err := g.Generate(errViolations("NV1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Constraint != "" {
		t.Error("Kyverno NV1001 should not produce a Constraint")
	}
}
