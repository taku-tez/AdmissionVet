package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register("gatekeeper", &mv1003{})
}

type mv1003 struct{}

func (g *mv1003) RuleID() string { return "MV1003" }

const mv1003Rego = `package admissionvet.mv1003

violation[{"msg": msg}] {
  vol := input_pod_spec.volumes[_]
  vol.hostPath
  msg := sprintf("Pod '%v' uses hostPath volume '%v' which is prohibited (MV1003)", [
    input.review.object.metadata.name, vol.name])
}

input_pod_spec = spec {
  input.review.object.kind == "Pod"
  spec := input.review.object.spec
}

input_pod_spec = spec {
  input.review.object.kind != "Pod"
  spec := input.review.object.spec.template.spec
}`

func (g *mv1003) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1003"
	kind := "Mv1003"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits hostPath volume mounts (MV1003)",
		Rego:        mv1003Rego,
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
