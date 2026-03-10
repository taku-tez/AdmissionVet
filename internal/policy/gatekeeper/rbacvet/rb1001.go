package rbacvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register(&rb1001{})
}

type rb1001 struct{}

func (g *rb1001) RuleID() string { return "RB1001" }

const rb1001Rego = `package admissionvet.rb1001

violation[{"msg": msg}] {
  input.review.object.kind == "ClusterRole"
  rule := input.review.object.rules[_]
  rule.verbs[_] == "*"
  msg := sprintf("ClusterRole '%v' uses wildcard verb '*' which grants excessive permissions (RB1001)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "Role"
  rule := input.review.object.rules[_]
  rule.verbs[_] == "*"
  msg := sprintf("Role '%v' uses wildcard verb '*' which grants excessive permissions (RB1001)", [input.review.object.metadata.name])
}`

func (g *rb1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "rb1001"
	kind := "Rb1001"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits wildcard verbs in RBAC roles (RB1001)",
		Rego:        rb1001Rego,
		MatchKinds:  gatekeeper.RBACKinds,
		APIGroups:   "rbac.authorization.k8s.io",
	})
	if err != nil {
		return nil, err
	}

	var nss []string
	if namespace != "" {
		nss = []string{namespace}
	}
	c, err := gatekeeper.BuildConstraint(gatekeeper.ConstraintParams{
		Kind:              kind,
		Name:              name,
		EnforcementAction: gatekeeper.EnforcementAction(violations),
		APIGroups:         "rbac.authorization.k8s.io",
		MatchKinds:        gatekeeper.RBACKinds,
		Namespaces:        nss,
	})
	if err != nil {
		return nil, err
	}

	return &policy.GeneratedPolicy{
		RuleID:             g.RuleID(),
		ConstraintTemplate: ct,
		Constraint:         c,
	}, nil
}
