// Package imagepolicy provides a Kyverno verify-images rule generator
// for Cosign signature verification.
package imagepolicy

import (
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	kyverno "github.com/AdmissionVet/admissionvet/internal/policy/kyverno"
)

func init() {
	policy.Register("kyverno", &iv1001{})
}

// iv1001 generates a Kyverno verify-images rule that enforces Cosign image signing.
type iv1001 struct{}

func (g *iv1001) RuleID() string { return "IV1001" }

func (g *iv1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	var nss []string
	if namespace != "" {
		nss = []string{namespace}
	}

	body := `    verifyImages:
      - imageReferences:
          - "*"
        attestors:
          - entries:
              - keyless:
                  subject: "*"
                  issuer: "https://accounts.google.com"
                  rekor:
                    url: https://rekor.sigstore.dev`

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "iv1001-verify-image-signatures",
		Description: "Verifies that all container images are signed with Cosign (IV1001)",
		Rules: []kyverno.Rule{
			{
				Name:       "verify-image-signatures",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: nss,
				Type:       kyverno.RuleTypeVerifyImages,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}
