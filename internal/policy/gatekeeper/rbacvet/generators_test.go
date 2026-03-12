package rbacvet_test

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
)

func getGen(t *testing.T, ruleID string) policy.Generator {
	t.Helper()
	g, ok := policy.Get("gatekeeper", ruleID)
	if !ok {
		t.Fatalf("no gatekeeper generator registered for %s", ruleID)
	}
	return g
}

func errViolations(ruleID string) []input.Violation {
	return []input.Violation{{RuleID: ruleID, Severity: input.SeverityError}}
}

func TestRB1001_Generate(t *testing.T) {
	g := getGen(t, "RB1001")
	p, err := g.Generate(errViolations("RB1001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "wildcard verb")
	mustContain(t, p.Constraint, "rbac.authorization.k8s.io")
	mustContain(t, p.Constraint, "kind: Rb1001")
	mustContain(t, p.Constraint, "enforcementAction: deny")
}

func TestRB1002_Generate(t *testing.T) {
	g := getGen(t, "RB1002")
	p, err := g.Generate(errViolations("RB1002"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "wildcard resource")
	mustContain(t, p.Constraint, "kind: Rb1002")
}

func TestRB1003_Generate(t *testing.T) {
	g := getGen(t, "RB1003")
	p, err := g.Generate(errViolations("RB1003"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "cluster-admin")
	mustContain(t, p.ConstraintTemplate, "system:masters")
	mustContain(t, p.Constraint, "kind: Rb1003")
	mustContain(t, p.Constraint, "ClusterRoleBinding")
}

func TestRBACGenerators_RuleIDMatches(t *testing.T) {
	for _, id := range []string{"RB1001", "RB1002", "RB1003"} {
		g := getGen(t, id)
		if g.RuleID() != id {
			t.Errorf("generator for %s reports RuleID()=%s", id, g.RuleID())
		}
	}
}

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("output missing %q\nfull output:\n%s", substr, s)
	}
}
