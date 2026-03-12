package manifestvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper"
)

func init() {
	policy.Register("gatekeeper", &mv1004{})
}

type mv1004 struct{}

func (g *mv1004) RuleID() string { return "MV1004" }

const mv1004Rego = `package admissionvet.mv1004

violation[{"msg": msg}] {
  c := input_containers[_]
  # runAsUser: 0 explicitly sets root
  object.get(c, ["securityContext", "runAsUser"], -1) == 0
  msg := sprintf("Container '%v' sets runAsUser: 0 (root) — MV1004", [c.name])
}

violation[{"msg": msg}] {
  c := input_containers[_]
  # runAsNonRoot: false explicitly permits root
  object.get(c, ["securityContext", "runAsNonRoot"], true) == false
  msg := sprintf("Container '%v' sets runAsNonRoot: false — MV1004", [c.name])
}

violation[{"msg": msg}] {
  # Pod-level runAsUser: 0 applies to all containers
  spec := input_pod_spec
  object.get(spec, ["securityContext", "runAsUser"], -1) == 0
  msg := sprintf("Pod '%v' sets pod-level runAsUser: 0 (root) — MV1004", [input.review.object.metadata.name])
}

input_pod_spec = spec {
  input.review.object.kind == "Pod"
  spec := input.review.object.spec
}

input_pod_spec = spec {
  kind := input.review.object.kind
  kind != "Pod"
  workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
  workload_kinds[kind]
  spec := input.review.object.spec.template.spec
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

func (g *mv1004) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	name := "mv1004"
	kind := "Mv1004"

	ct, err := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
		Name:        name,
		Kind:        kind,
		Description: "Prohibits containers from running as root (MV1004)",
		Rego:        mv1004Rego,
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
