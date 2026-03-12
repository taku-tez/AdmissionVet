package policy_test

import (
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
)

type stubGenerator struct {
	ruleID string
}

func (g *stubGenerator) RuleID() string { return g.ruleID }
func (g *stubGenerator) Generate(_ []input.Violation, _ string) (*policy.GeneratedPolicy, error) {
	return &policy.GeneratedPolicy{RuleID: g.ruleID}, nil
}

func TestRegisterAndGet(t *testing.T) {
	// Use a unique engine name to avoid conflicts with init() registrations.
	engine := "test-engine-registry"

	g := &stubGenerator{ruleID: "TEST001"}
	policy.Register(engine, g)

	got, ok := policy.Get(engine, "TEST001")
	if !ok {
		t.Fatal("expected Get to return true")
	}
	if got.RuleID() != "TEST001" {
		t.Errorf("want TEST001, got %s", got.RuleID())
	}
}

func TestGet_UnknownEngine(t *testing.T) {
	_, ok := policy.Get("nonexistent-engine", "MV1001")
	if ok {
		t.Fatal("expected ok=false for unknown engine")
	}
}

func TestGet_UnknownRuleID(t *testing.T) {
	engine := "test-engine-getrule"
	policy.Register(engine, &stubGenerator{ruleID: "KNOWN001"})

	_, ok := policy.Get(engine, "UNKNOWN999")
	if ok {
		t.Fatal("expected ok=false for unknown rule ID")
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	engine := "test-engine-panic"
	policy.Register(engine, &stubGenerator{ruleID: "DUP001"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration, got none")
		}
	}()
	policy.Register(engine, &stubGenerator{ruleID: "DUP001"})
}
