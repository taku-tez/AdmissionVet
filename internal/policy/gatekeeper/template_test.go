package gatekeeper

import (
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/input"
)

func TestBuildConstraintTemplate(t *testing.T) {
	p := ConstraintTemplateParams{
		Name:        "mv1001",
		Kind:        "Mv1001",
		Description: "Prohibits privileged containers",
		Rego:        "package test\nviolation[{\"msg\": msg}] { msg := \"test\" }",
		MatchKinds:  WorkloadKinds,
		APIGroups:   "*",
	}
	got, err := BuildConstraintTemplate(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mustContain(t, got, "kind: ConstraintTemplate")
	mustContain(t, got, "name: mv1001")
	mustContain(t, got, "kind: Mv1001")
	mustContain(t, got, "Prohibits privileged containers")
	mustContain(t, got, "package test")
	mustContain(t, got, "target: admission.k8s.gatekeeper.sh")
}

func TestBuildConstraint(t *testing.T) {
	t.Run("without namespace", func(t *testing.T) {
		p := ConstraintParams{
			Kind:              "Mv1001",
			Name:              "mv1001",
			EnforcementAction: "deny",
			APIGroups:         "*",
			MatchKinds:        WorkloadKinds,
		}
		got, err := BuildConstraint(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, got, "kind: Mv1001")
		mustContain(t, got, "name: mv1001")
		mustContain(t, got, "enforcementAction: deny")
		if strings.Contains(got, "namespaces:") {
			t.Error("should not contain namespaces when not specified")
		}
	})

	t.Run("with namespace", func(t *testing.T) {
		p := ConstraintParams{
			Kind:              "Mv1001",
			Name:              "mv1001",
			EnforcementAction: "warn",
			APIGroups:         "*",
			MatchKinds:        WorkloadKinds,
			Namespaces:        []string{"staging"},
		}
		got, err := BuildConstraint(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, got, "namespaces:")
		mustContain(t, got, "staging")
		mustContain(t, got, "enforcementAction: warn")
	})
}

func TestEnforcementAction(t *testing.T) {
	t.Run("error violation → deny", func(t *testing.T) {
		violations := []input.Violation{
			{Severity: input.SeverityWarning},
			{Severity: input.SeverityError},
		}
		if got := EnforcementAction(violations); got != "deny" {
			t.Errorf("want deny, got %s", got)
		}
	})

	t.Run("warning only → warn", func(t *testing.T) {
		violations := []input.Violation{
			{Severity: input.SeverityWarning},
		}
		if got := EnforcementAction(violations); got != "warn" {
			t.Errorf("want warn, got %s", got)
		}
	})

	t.Run("empty violations → warn", func(t *testing.T) {
		if got := EnforcementAction(nil); got != "warn" {
			t.Errorf("want warn, got %s", got)
		}
	})
}

func TestRuleIDToKind(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"MV1001", "Mv1001"},
		{"RB1001", "Rb1001"},
		{"NV1001", "Nv1001"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := RuleIDToKind(tc.input); got != tc.want {
			t.Errorf("RuleIDToKind(%q): want %q, got %q", tc.input, tc.want, got)
		}
	}
}

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("output missing %q\nfull output:\n%s", substr, s)
	}
}
