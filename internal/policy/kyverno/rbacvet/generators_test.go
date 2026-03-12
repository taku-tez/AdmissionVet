package rbacvet_test

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"

	// Trigger init() registrations.
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/rbacvet"
)

func getGen(t *testing.T, ruleID string) policy.Generator {
	t.Helper()
	g, ok := policy.Get("kyverno", ruleID)
	if !ok {
		t.Fatalf("no kyverno generator registered for %s", ruleID)
	}
	return g
}

func errViolations(ruleID string) []input.Violation {
	return []input.Violation{{RuleID: ruleID, Severity: input.SeverityError}}
}

func warnViolations(ruleID string) []input.Violation {
	return []input.Violation{{RuleID: ruleID, Severity: input.SeverityWarning}}
}

func mustContain(t *testing.T, yaml, substr string) {
	t.Helper()
	if !strings.Contains(yaml, substr) {
		t.Errorf("expected YAML to contain %q\ngot:\n%s", substr, yaml)
	}
}

// ── RB1001 ───────────────────────────────────────────────────────────────────

func TestKyverno_RB1001_Enforce(t *testing.T) {
	g := getGen(t, "RB1001")
	p, err := g.Generate(errViolations("RB1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "kind: ClusterPolicy")
	mustContain(t, p.ClusterPolicy, "rb1001-no-wildcard-verbs")
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
	mustContain(t, p.ClusterPolicy, "ClusterRole")
	mustContain(t, p.ClusterPolicy, "Role")
	mustContain(t, p.ClusterPolicy, "contains(@, '*')")
}

func TestKyverno_RB1001_Audit(t *testing.T) {
	g := getGen(t, "RB1001")
	p, err := g.Generate(warnViolations("RB1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
}

func TestKyverno_RB1001_NoConstraintTemplate(t *testing.T) {
	g := getGen(t, "RB1001")
	p, err := g.Generate(errViolations("RB1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ConstraintTemplate != "" {
		t.Error("Kyverno RB1001 should not produce a ConstraintTemplate")
	}
}

// ── RB1002 ───────────────────────────────────────────────────────────────────

func TestKyverno_RB1002_Enforce(t *testing.T) {
	g := getGen(t, "RB1002")
	p, err := g.Generate(errViolations("RB1002"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "rb1002-no-wildcard-resources")
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
	mustContain(t, p.ClusterPolicy, "ClusterRole")
	mustContain(t, p.ClusterPolicy, "contains(@, '*')")
}

func TestKyverno_RB1002_Audit(t *testing.T) {
	g := getGen(t, "RB1002")
	p, err := g.Generate(warnViolations("RB1002"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
}

// ── RB1003 ───────────────────────────────────────────────────────────────────

func TestKyverno_RB1003_Enforce(t *testing.T) {
	g := getGen(t, "RB1003")
	p, err := g.Generate(errViolations("RB1003"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "rb1003-no-cluster-admin")
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
	mustContain(t, p.ClusterPolicy, "ClusterRoleBinding")
	mustContain(t, p.ClusterPolicy, "RoleBinding")
	mustContain(t, p.ClusterPolicy, "cluster-admin")
	mustContain(t, p.ClusterPolicy, "system:masters")
	// Numeric value (not string "0") for length comparison.
	mustContain(t, p.ClusterPolicy, "value: 0")
	if strings.Contains(p.ClusterPolicy, `value: "0"`) {
		t.Error(`RB1003: value should be numeric 0, not string "0"`)
	}
}

func TestKyverno_RB1003_Audit(t *testing.T) {
	g := getGen(t, "RB1003")
	p, err := g.Generate(warnViolations("RB1003"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
}

func TestKyverno_RB1003_MatchesBindingKinds(t *testing.T) {
	g := getGen(t, "RB1003")
	p, err := g.Generate(errViolations("RB1003"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must not match ClusterRole/Role (those are rbacKinds, not bindingKinds).
	if strings.Contains(p.ClusterPolicy, "- ClusterRole\n") {
		t.Error("RB1003 should match ClusterRoleBinding/RoleBinding, not ClusterRole")
	}
}
