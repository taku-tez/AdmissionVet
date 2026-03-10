package networkvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/policy/networkpolicy"
)

func init() {
	policy.Register("gatekeeper", &nv1001{})
}

type nv1001 struct{}

func (g *nv1001) RuleID() string { return "NV1001" }

// NV1001 generates a default-deny NetworkPolicy rather than a Gatekeeper
// ConstraintTemplate, because the goal is to create a missing NetworkPolicy,
// not to block admission of a resource.
func (g *nv1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	np := networkpolicy.GenerateDefaultDeny(namespace)
	return &policy.GeneratedPolicy{
		RuleID:        g.RuleID(),
		NetworkPolicy: np,
	}, nil
}
