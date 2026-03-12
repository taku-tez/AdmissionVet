// Package rbacvet provides Kyverno ClusterPolicy generators for RBACVet violations.
package rbacvet

import (
	"fmt"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	kyverno "github.com/AdmissionVet/admissionvet/internal/policy/kyverno"
)

func init() {
	policy.Register("kyverno", &rb1001{})
	policy.Register("kyverno", &rb1002{})
	policy.Register("kyverno", &rb1003{})
}

var rbacKinds = []string{"ClusterRole", "Role"}
var bindingKinds = []string{"ClusterRoleBinding", "RoleBinding"}

// ── RB1001: wildcard verb 禁止 ───────────────────────────────────────────────

type rb1001 struct{}

func (g *rb1001) RuleID() string { return "RB1001" }

func (g *rb1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "Wildcard verb '*' is not allowed in RBAC roles (RB1001). Use explicit verbs."
      deny:
        conditions:
          any:
            - key: "{{ request.object.rules[].verbs[] | contains(@, '*') }}"
              operator: Equals
              value: true`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "rb1001-no-wildcard-verbs",
		Description: "Prohibits wildcard verbs in RBAC roles (RB1001)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-wildcard-verbs",
				MatchKinds: rbacKinds,
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── RB1002: wildcard resource 禁止 ──────────────────────────────────────────

type rb1002 struct{}

func (g *rb1002) RuleID() string { return "RB1002" }

func (g *rb1002) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "Wildcard resource '*' is not allowed in RBAC roles (RB1002). Use explicit resources."
      deny:
        conditions:
          any:
            - key: "{{ request.object.rules[].resources[] | contains(@, '*') }}"
              operator: Equals
              value: true`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "rb1002-no-wildcard-resources",
		Description: "Prohibits wildcard resources in RBAC roles (RB1002)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-wildcard-resources",
				MatchKinds: rbacKinds,
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── RB1003: cluster-admin 付与禁止 ───────────────────────────────────────────

type rb1003 struct{}

func (g *rb1003) RuleID() string { return "RB1003" }

func (g *rb1003) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "Binding cluster-admin to non-system:masters subjects is not allowed (RB1003)."
      deny:
        conditions:
          all:
            - key: "{{ request.object.roleRef.name }}"
              operator: Equals
              value: cluster-admin
            - key: "{{ request.object.subjects[?(@.kind=='Group' && @.name=='system:masters')] | length(@) }}"
              operator: Equals
              value: 0`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "rb1003-no-cluster-admin",
		Description: "Prohibits granting cluster-admin to non-system:masters subjects (RB1003)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-cluster-admin-binding",
				MatchKinds: bindingKinds,
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}
