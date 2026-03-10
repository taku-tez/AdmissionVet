package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register(&mv1001{})
}

type mv1001 struct{}

func (g *mv1001) RuleID() string { return "MV1001" }

const mv1001Rego = `package admissionvet.mv1001

violation[{"msg": msg}] {
  c := input_containers[_]
  c.securityContext.privileged == true
  msg := sprintf("Container '%v' is running as privileged (MV1001)", [c.name])
}

input_containers[c] {
  c := input.review.object.spec.containers[_]
}
input_containers[c] {
  c := input.review.object.spec.initContainers[_]
}
input_containers[c] {
  c := input.review.object.spec.template.spec.containers[_]
}
input_containers[c] {
  c := input.review.object.spec.template.spec.initContainers[_]
}`

func (g *mv1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1001"
	kind := "Mv1001"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits privileged containers (MV1001)",
		Rego:        mv1001Rego,
		MatchKinds:  gatekeeper.WorkloadKinds,
		APIGroups:   "*",
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
		APIGroups:         "*",
		MatchKinds:        gatekeeper.WorkloadKinds,
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
