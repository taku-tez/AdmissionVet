package manifestvet_test

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
)

// errViolations is a helper to build a slice with one error-severity violation.
func errViolations(ruleID string) []input.Violation {
	return []input.Violation{{RuleID: ruleID, Severity: input.SeverityError}}
}

func warnViolations(ruleID string) []input.Violation {
	return []input.Violation{{RuleID: ruleID, Severity: input.SeverityWarning}}
}

func getGen(t *testing.T, ruleID string) policy.Generator {
	t.Helper()
	g, ok := policy.Get("gatekeeper", ruleID)
	if !ok {
		t.Fatalf("no gatekeeper generator registered for %s", ruleID)
	}
	return g
}

func TestMV1001_Generate(t *testing.T) {
	g := getGen(t, "MV1001")

	t.Run("error → enforcementAction deny", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1001"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ConstraintTemplate, "kind: ConstraintTemplate")
		mustContain(t, p.ConstraintTemplate, "privileged")
		mustContain(t, p.Constraint, "enforcementAction: deny")
		mustContain(t, p.Constraint, "kind: Mv1001")
	})

	t.Run("warning → enforcementAction warn", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1001"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.Constraint, "enforcementAction: warn")
	})

	t.Run("with namespace", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1001"), "production")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.Constraint, "production")
	})
}

func TestMV1002_Generate(t *testing.T) {
	g := getGen(t, "MV1002")
	p, err := g.Generate(errViolations("MV1002"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "hostPID")
	mustContain(t, p.ConstraintTemplate, "hostIPC")
	mustContain(t, p.ConstraintTemplate, "hostNetwork")
	mustContain(t, p.Constraint, "kind: Mv1002")
}

func TestMV1003_Generate(t *testing.T) {
	g := getGen(t, "MV1003")
	p, err := g.Generate(errViolations("MV1003"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "hostPath")
	mustContain(t, p.Constraint, "kind: Mv1003")
}

func TestMV1007_Generate(t *testing.T) {
	g := getGen(t, "MV1007")
	p, err := g.Generate(warnViolations("MV1007"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "readOnlyRootFilesystem")
	mustContain(t, p.Constraint, "enforcementAction: warn")
}

func TestMV2001_Generate(t *testing.T) {
	g := getGen(t, "MV2001")
	p, err := g.Generate(errViolations("MV2001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ConstraintTemplate, "secret_like_name")
	mustContain(t, p.ConstraintTemplate, "PASSWORD")
	mustContain(t, p.Constraint, "kind: Mv2001")
}

// ── MV1004 ───────────────────────────────────────────────────────────────────

func TestMV1004_Generate(t *testing.T) {
	g := getGen(t, "MV1004")

	t.Run("produces ConstraintTemplate and Constraint", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1004"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ConstraintTemplate, "kind: ConstraintTemplate")
		mustContain(t, p.ConstraintTemplate, "runAsUser")
		mustContain(t, p.ConstraintTemplate, "runAsNonRoot")
		mustContain(t, p.Constraint, "kind: Mv1004")
		mustContain(t, p.Constraint, "enforcementAction: deny")
	})

	t.Run("warning → warn", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1004"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.Constraint, "enforcementAction: warn")
	})

	t.Run("with namespace", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1004"), "production")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.Constraint, "production")
	})
}

// ── MV1005 ───────────────────────────────────────────────────────────────────

func TestMV1005_Generate(t *testing.T) {
	g := getGen(t, "MV1005")

	t.Run("produces ConstraintTemplate with dangerous caps list", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1005"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ConstraintTemplate, "kind: ConstraintTemplate")
		mustContain(t, p.ConstraintTemplate, "dangerous_caps")
		mustContain(t, p.ConstraintTemplate, "SYS_ADMIN")
		mustContain(t, p.ConstraintTemplate, "NET_ADMIN")
		mustContain(t, p.ConstraintTemplate, "ALL")
		mustContain(t, p.Constraint, "kind: Mv1005")
		mustContain(t, p.Constraint, "enforcementAction: deny")
	})

	t.Run("warning → warn", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1005"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.Constraint, "enforcementAction: warn")
	})
}

// ── MV1006 ───────────────────────────────────────────────────────────────────

func TestMV1006_Generate(t *testing.T) {
	g := getGen(t, "MV1006")

	t.Run("produces ConstraintTemplate for privilege escalation", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1006"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ConstraintTemplate, "kind: ConstraintTemplate")
		mustContain(t, p.ConstraintTemplate, "allowPrivilegeEscalation")
		mustContain(t, p.Constraint, "kind: Mv1006")
		mustContain(t, p.Constraint, "enforcementAction: deny")
	})

	t.Run("warning → warn", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1006"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.Constraint, "enforcementAction: warn")
	})
}

func TestAllGatekeeperGenerators_RuleIDMatches(t *testing.T) {
	ruleIDs := []string{"MV1001", "MV1002", "MV1003", "MV1004", "MV1005", "MV1006", "MV1007", "MV2001"}
	for _, id := range ruleIDs {
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
