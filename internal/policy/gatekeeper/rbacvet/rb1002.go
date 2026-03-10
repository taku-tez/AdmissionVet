package rbacvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register("gatekeeper", &rb1002{})
}

type rb1002 struct{}

func (g *rb1002) RuleID() string { return "RB1002" }

const rb1002Rego = `package admissionvet.rb1002

violation[{"msg": msg}] {
  input.review.object.kind == "ClusterRole"
  rule := input.review.object.rules[_]
  rule.resources[_] == "*"
  msg := sprintf("ClusterRole '%v' uses wildcard resource '*' which grants excessive permissions (RB1002)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "Role"
  rule := input.review.object.rules[_]
  rule.resources[_] == "*"
  msg := sprintf("Role '%v' uses wildcard resource '*' which grants excessive permissions (RB1002)", [input.review.object.metadata.name])
}`

func (g *rb1002) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "rb1002"
	kind := "Rb1002"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits wildcard resources in RBAC roles (RB1002)",
		Rego:        rb1002Rego,
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
