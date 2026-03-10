package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register(&mv2001{})
}

type mv2001 struct{}

func (g *mv2001) RuleID() string { return "MV2001" }

const mv2001Rego = `package admissionvet.mv2001

# Detects secret-like environment variable names that have literal values
# instead of using valueFrom.secretKeyRef or valueFrom.configMapKeyRef.
violation[{"msg": msg}] {
  c := input_containers[_]
  env := c.env[_]
  secret_like_name(env.name)
  env.value
  msg := sprintf("Container '%v' has env var '%v' with a literal value that looks like a secret (MV2001). Use secretKeyRef instead.", [c.name, env.name])
}

secret_like_name(name) {
  patterns := ["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "PASSWD", "PRIVATE", "API_KEY", "AUTH"]
  p := patterns[_]
  contains(upper(name), p)
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

func (g *mv2001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv2001"
	kind := "Mv2001"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits secret values written directly to env vars (MV2001)",
		Rego:        mv2001Rego,
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
