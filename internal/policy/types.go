// Package policy defines the Generator interface and GeneratedPolicy type used by all
// rule implementations.
//
// Each rule is implemented as a Generator that self-registers via init():
//
//	func init() { policy.Register("gatekeeper", &mv1001{}) }
//
// cmd/generators.go blank-imports all generator packages to trigger registration before
// any CLI command runs.
//
// Engines: "gatekeeper" (ConstraintTemplate + Constraint) and "kyverno" (ClusterPolicy).
package policy

import "github.com/AdmissionVet/admissionvet/internal/input"

// GeneratedPolicy holds all the Kubernetes resources generated for a single rule.
type GeneratedPolicy struct {
	RuleID             string
	ConstraintTemplate string // ConstraintTemplate YAML (Gatekeeper)
	Constraint         string // Constraint instance YAML (Gatekeeper)
	ClusterPolicy      string // Kyverno ClusterPolicy YAML
	NetworkPolicy      string // NetworkPolicy YAML (NetworkVet rules only)
}

// Generator generates admission control policies for a specific rule ID.
type Generator interface {
	RuleID() string
	Generate(violations []input.Violation, namespace string) (*GeneratedPolicy, error)
}
