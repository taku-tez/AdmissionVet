package rbacvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register(&rbClusterAdmin{})
}

type rbClusterAdmin struct{}

func (g *rbClusterAdmin) RuleID() string { return "RB1003" }

const rbClusterAdminRego = `package admissionvet.rb1003

violation[{"msg": msg}] {
  input.review.object.kind == "ClusterRoleBinding"
  input.review.object.roleRef.name == "cluster-admin"
  subj := input.review.object.subjects[_]
  not is_system_masters(subj)
  msg := sprintf("ClusterRoleBinding '%v' grants cluster-admin to '%v' which is not system:masters (RB1003)", [
    input.review.object.metadata.name, subj.name])
}

is_system_masters(subj) {
  subj.kind == "Group"
  subj.name == "system:masters"
}`

func (g *rbClusterAdmin) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "rb1003"
	kind := "Rb1003"

	bindingKinds := []string{"ClusterRoleBinding", "RoleBinding"}

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits granting cluster-admin to non-system:masters subjects (RB1003)",
		Rego:        rbClusterAdminRego,
		MatchKinds:  bindingKinds,
		APIGroups:   "rbac.authorization.k8s.io",
	})
	if err != nil {
		return nil, err
	}

	c, err := gatekeeper.BuildConstraint(gatekeeper.ConstraintParams{
		Kind:              kind,
		Name:              name,
		EnforcementAction: gatekeeper.EnforcementAction(violations),
		APIGroups:         "rbac.authorization.k8s.io",
		MatchKinds:        bindingKinds,
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
