package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AdmissionVet/admissionvet/internal/policy"
)

// WriteYAML writes each GeneratedPolicy as YAML files under outputDir.
// Creates a flat structure with separate files per resource type.
func WriteYAML(policies []*policy.GeneratedPolicy, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	for _, p := range policies {
		ruleID := strings.ToLower(p.RuleID)

		if p.ConstraintTemplate != "" {
			path := filepath.Join(outputDir, ruleID+"-constrainttemplate.yaml")
			if err := os.WriteFile(path, []byte(p.ConstraintTemplate), 0o644); err != nil {
				return fmt.Errorf("writing ConstraintTemplate for %s: %w", p.RuleID, err)
			}
			fmt.Printf("  wrote %s\n", path)
		}

		if p.Constraint != "" {
			path := filepath.Join(outputDir, ruleID+"-constraint.yaml")
			if err := os.WriteFile(path, []byte(p.Constraint), 0o644); err != nil {
				return fmt.Errorf("writing Constraint for %s: %w", p.RuleID, err)
			}
			fmt.Printf("  wrote %s\n", path)
		}

		if p.ClusterPolicy != "" {
			path := filepath.Join(outputDir, ruleID+"-clusterpolicy.yaml")
			if err := os.WriteFile(path, []byte(p.ClusterPolicy), 0o644); err != nil {
				return fmt.Errorf("writing ClusterPolicy for %s: %w", p.RuleID, err)
			}
			fmt.Printf("  wrote %s\n", path)
		}

		if p.NetworkPolicy != "" {
			path := filepath.Join(outputDir, ruleID+"-networkpolicy.yaml")
			if err := os.WriteFile(path, []byte(p.NetworkPolicy), 0o644); err != nil {
				return fmt.Errorf("writing NetworkPolicy for %s: %w", p.RuleID, err)
			}
			fmt.Printf("  wrote %s\n", path)
		}
	}

	return nil
}
