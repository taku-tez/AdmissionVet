package policy

import "github.com/AdmissionVet/admissionvet/internal/input"

// GeneratedPolicy holds all the Kubernetes resources generated for a single rule.
type GeneratedPolicy struct {
	RuleID             string
	ConstraintTemplate string // ConstraintTemplate YAML
	Constraint         string // Constraint instance YAML
	NetworkPolicy      string // NetworkPolicy YAML (NetworkVet rules only)
}

// Generator generates admission control policies for a specific rule ID.
type Generator interface {
	RuleID() string
	Generate(violations []input.Violation, namespace string) (*GeneratedPolicy, error)
}
