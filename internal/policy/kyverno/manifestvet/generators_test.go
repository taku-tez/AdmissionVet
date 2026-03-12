package manifestvet_test

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
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

func TestKyverno_MV1001(t *testing.T) {
	g := getGen(t, "MV1001")

	t.Run("error → Enforce", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1001"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "kind: ClusterPolicy")
		mustContain(t, p.ClusterPolicy, "mv1001-no-privileged")
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
		mustContain(t, p.ClusterPolicy, "privileged: false")
	})

	t.Run("warning → Audit", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1001"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
	})

	t.Run("includes mutate rule", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1001"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "patchStrategicMerge")
	})

	t.Run("with namespace filter", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1001"), "staging")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "staging")
	})
}

func TestKyverno_MV1002(t *testing.T) {
	g := getGen(t, "MV1002")
	p, err := g.Generate(errViolations("MV1002"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "mv1002-no-host-namespaces")
	mustContain(t, p.ClusterPolicy, "hostPID")
	mustContain(t, p.ClusterPolicy, "hostIPC")
	mustContain(t, p.ClusterPolicy, "hostNetwork")
}

func TestKyverno_MV1003(t *testing.T) {
	g := getGen(t, "MV1003")
	p, err := g.Generate(errViolations("MV1003"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "mv1003-no-hostpath")
	mustContain(t, p.ClusterPolicy, "hostPath")
}

func TestKyverno_MV1007(t *testing.T) {
	g := getGen(t, "MV1007")
	p, err := g.Generate(warnViolations("MV1007"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "mv1007-readonly-rootfs")
	mustContain(t, p.ClusterPolicy, "readOnlyRootFilesystem")
	mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
}

func TestKyverno_MV2001(t *testing.T) {
	g := getGen(t, "MV2001")
	p, err := g.Generate(errViolations("MV2001"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "mv2001-no-secret-env")
	mustContain(t, p.ClusterPolicy, "PASSWORD")
	mustContain(t, p.ClusterPolicy, "secretKeyRef")
}

func TestKyverno_MV1007Mutate(t *testing.T) {
	g := getGen(t, "MV1007-MUTATE")
	p, err := g.Generate(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "patchStrategicMerge")
	mustContain(t, p.ClusterPolicy, "readOnlyRootFilesystem: true")
}

func TestKyverno_AutomountMutate(t *testing.T) {
	g := getGen(t, "MV-MUTATE-AUTOMOUNT")
	p, err := g.Generate(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "automountServiceAccountToken: false")
}

func TestKyverno_ImagePullPolicyMutate(t *testing.T) {
	g := getGen(t, "MV-MUTATE-IMAGEPULL")
	p, err := g.Generate(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, p.ClusterPolicy, "imagePullPolicy: Always")
}

// ── MV1004 ───────────────────────────────────────────────────────────────────

func TestKyverno_MV1004(t *testing.T) {
	g := getGen(t, "MV1004")

	t.Run("Enforce", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1004"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "kind: ClusterPolicy")
		mustContain(t, p.ClusterPolicy, "mv1004-no-root-user")
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
		mustContain(t, p.ClusterPolicy, "runAsNonRoot")
	})

	t.Run("Audit", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1004"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
	})

	t.Run("no ConstraintTemplate", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1004"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ConstraintTemplate != "" {
			t.Error("Kyverno MV1004 should not produce ConstraintTemplate")
		}
	})
}

// ── MV1005 ───────────────────────────────────────────────────────────────────

func TestKyverno_MV1005(t *testing.T) {
	g := getGen(t, "MV1005")

	t.Run("Enforce with dangerous caps list", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1005"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "mv1005-no-dangerous-capabilities")
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
		mustContain(t, p.ClusterPolicy, "SYS_ADMIN")
		mustContain(t, p.ClusterPolicy, "NET_ADMIN")
		mustContain(t, p.ClusterPolicy, "ALL")
		// AnyIn operator — exact string matching, correct for capabilities
		mustContain(t, p.ClusterPolicy, "operator: AnyIn")
	})

	t.Run("Audit", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1005"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
	})
}

// ── MV1006 ───────────────────────────────────────────────────────────────────

func TestKyverno_MV1006(t *testing.T) {
	g := getGen(t, "MV1006")

	t.Run("Enforce", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1006"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "mv1006-no-privilege-escalation")
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Enforce")
		mustContain(t, p.ClusterPolicy, "allowPrivilegeEscalation: false")
	})

	t.Run("Audit", func(t *testing.T) {
		p, err := g.Generate(warnViolations("MV1006"), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "validationFailureAction: Audit")
	})

	t.Run("with namespace", func(t *testing.T) {
		p, err := g.Generate(errViolations("MV1006"), "staging")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, p.ClusterPolicy, "staging")
	})
}

func TestAllKyvernoGenerators_RuleIDMatches(t *testing.T) {
	ruleIDs := []string{
		"MV1001", "MV1002", "MV1003", "MV1004", "MV1005", "MV1006",
		"MV1007", "MV2001", "MV1007-MUTATE", "MV-MUTATE-AUTOMOUNT", "MV-MUTATE-IMAGEPULL",
	}
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
