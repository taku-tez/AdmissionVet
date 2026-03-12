package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register("gatekeeper", &mv1006{})
}

type mv1006 struct{}

func (g *mv1006) RuleID() string { return "MV1006" }

const mv1006Rego = `package admissionvet.mv1006

violation[{"msg": msg}] {
  c := input_containers[_]
  # allowPrivilegeEscalation must be explicitly set to false.
  # If the field is absent or true, privilege escalation is possible.
  object.get(c, ["securityContext", "allowPrivilegeEscalation"], true) != false
  msg := sprintf("Container '%v' does not set allowPrivilegeEscalation: false (MV1006)", [c.name])
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

func (g *mv1006) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1006"
	kind := "Mv1006"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Requires allowPrivilegeEscalation: false on all containers (MV1006)",
		Rego:        mv1006Rego,
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
