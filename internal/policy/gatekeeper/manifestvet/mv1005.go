package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register("gatekeeper", &mv1005{})
}

type mv1005 struct{}

func (g *mv1005) RuleID() string { return "MV1005" }

const mv1005Rego = `package admissionvet.mv1005

# Capabilities that pose significant security risk.
dangerous_caps := {
  "ALL", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
  "SYS_RAWIO", "SYS_BOOT", "NET_RAW", "IPC_LOCK",
  "AUDIT_WRITE", "AUDIT_CONTROL", "MAC_ADMIN", "MAC_OVERRIDE",
  "SETUID", "SETGID"
}

violation[{"msg": msg}] {
  c := input_containers[_]
  cap := c.securityContext.capabilities.add[_]
  dangerous_caps[upper(cap)]
  msg := sprintf("Container '%v' adds dangerous capability '%v' (MV1005)", [c.name, cap])
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

func (g *mv1005) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1005"
	kind := "Mv1005"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits dangerous Linux capabilities (MV1005)",
		Rego:        mv1005Rego,
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
