package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register(&mv1002{})
}

type mv1002 struct{}

func (g *mv1002) RuleID() string { return "MV1002" }

const mv1002Rego = `package admissionvet.mv1002

violation[{"msg": msg}] {
  spec := input_pod_spec
  spec.hostPID == true
  msg := sprintf("Pod '%v' uses hostPID which is prohibited (MV1002)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  spec := input_pod_spec
  spec.hostIPC == true
  msg := sprintf("Pod '%v' uses hostIPC which is prohibited (MV1002)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  spec := input_pod_spec
  spec.hostNetwork == true
  msg := sprintf("Pod '%v' uses hostNetwork which is prohibited (MV1002)", [input.review.object.metadata.name])
}

input_pod_spec = spec {
  input.review.object.kind == "Pod"
  spec := input.review.object.spec
}

input_pod_spec = spec {
  input.review.object.kind != "Pod"
  spec := input.review.object.spec.template.spec
}`

func (g *mv1002) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1002"
	kind := "Mv1002"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits hostPID, hostIPC, and hostNetwork (MV1002)",
		Rego:        mv1002Rego,
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
