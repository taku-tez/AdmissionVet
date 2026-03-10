package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register("gatekeeper", &mv1007{})
}

type mv1007 struct{}

func (g *mv1007) RuleID() string { return "MV1007" }

const mv1007Rego = `package admissionvet.mv1007

violation[{"msg": msg}] {
  c := input_containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("Container '%v' does not set readOnlyRootFilesystem: true (MV1007)", [c.name])
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

func (g *mv1007) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1007"
	kind := "Mv1007"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Requires readOnlyRootFilesystem: true on all containers (MV1007)",
		Rego:        mv1007Rego,
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
