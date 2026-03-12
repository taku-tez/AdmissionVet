package networkvet_test

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
)

func TestNV1001_Generate(t *testing.T) {
	g, ok := policy.Get("gatekeeper", "NV1001")
	if !ok {
		t.Fatal("no gatekeeper generator registered for NV1001")
	}

	t.Run("generates NetworkPolicy (no ConstraintTemplate)", func(t *testing.T) {
		violations := []input.Violation{{RuleID: "NV1001", Severity: input.SeverityError, Namespace: "team-a"}}
		p, err := g.Generate(violations, "team-a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ConstraintTemplate != "" {
			t.Error("NV1001 should not produce a ConstraintTemplate")
		}
		if p.NetworkPolicy == "" {
			t.Fatal("NV1001 should produce a NetworkPolicy")
		}
		if !strings.Contains(p.NetworkPolicy, "NetworkPolicy") {
			t.Errorf("NetworkPolicy output missing 'NetworkPolicy': %s", p.NetworkPolicy)
		}
	})

	t.Run("RuleID returns NV1001", func(t *testing.T) {
		if g.RuleID() != "NV1001" {
			t.Errorf("want NV1001, got %s", g.RuleID())
		}
	})
}
