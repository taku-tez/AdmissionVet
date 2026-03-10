// Package networkvet provides Kyverno ClusterPolicy generators for NetworkVet violations.
package networkvet

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	kyverno "github.com/AdmissionVet/admissionvet/internal/policy/kyverno"
	"github.com/AdmissionVet/admissionvet/internal/policy/networkpolicy"
)

func init() {
	policy.Register("kyverno", &nv1001{})
}

// nv1001 generates:
//  1. A Kyverno `generate` rule that auto-creates a default-deny NetworkPolicy
//     whenever a new Namespace is created.
//  2. A standalone default-deny NetworkPolicy YAML for immediate application.
type nv1001 struct{}

func (g *nv1001) RuleID() string { return "NV1001" }

func (g *nv1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	// Kyverno generate rule: creates a default-deny NetworkPolicy in each new Namespace.
	body := `    generate:
      apiVersion: networking.k8s.io/v1
      kind: NetworkPolicy
      name: default-deny-all
      namespace: "{{request.object.metadata.name}}"
      synchronize: true
      data:
        spec:
          podSelector: {}
          policyTypes:
            - Ingress
            - Egress`

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "nv1001-default-deny-netpol",
		Description: "Auto-generates default-deny NetworkPolicy when a Namespace is created (NV1001)",
		Rules: []kyverno.Rule{
			{
				Name:       "generate-default-deny-netpol",
				MatchKinds: []string{"Namespace"},
				Type:       kyverno.RuleTypeGenerate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	// Also provide a standalone NetworkPolicy for the specified namespace (or a placeholder).
	np := networkpolicy.GenerateDefaultDeny(namespace)

	return &policy.GeneratedPolicy{
		RuleID:        g.RuleID(),
		ClusterPolicy: cp,
		NetworkPolicy: np,
	}, nil
}
