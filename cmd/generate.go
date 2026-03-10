package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/output"
	"github.com/AdmissionVet/admissionvet/internal/policy"

	// Register all Gatekeeper generators via side-effect imports.
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/manifestvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/networkvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/rbacvet"
)

// NewGenerateCommand returns the `admissionvet generate` cobra command.
func NewGenerateCommand() *cobra.Command {
	var (
		fromFile  string
		engine    string
		severity  string
		namespace string
		outputDir string
		format    string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate admission control policies from scan results",
		Long: `Generate OPA/Gatekeeper ConstraintTemplates (and NetworkPolicies)
from scan result JSON produced by ManifestVet, RBACVet, or NetworkVet.

Example:
  admissionvet generate --from results.json --engine gatekeeper
  admissionvet generate --from results.json --severity error --namespace team-a --format helm`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(fromFile, engine, severity, namespace, outputDir, format)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to scan results JSON (required)")
	cmd.Flags().StringVar(&engine, "engine", "gatekeeper", "Policy engine: gatekeeper")
	cmd.Flags().StringVar(&severity, "severity", "", "Minimum severity to include: error|warning|info")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Limit policies to this namespace")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Output directory")
	cmd.Flags().StringVar(&format, "format", "yaml", "Output format: yaml|helm|kustomize")
	cmd.MarkFlagRequired("from")

	return cmd
}

func runGenerate(fromFile, engine, severity, namespace, outputDir, format string) error {
	if engine != "gatekeeper" {
		return fmt.Errorf("unsupported engine %q: only 'gatekeeper' is supported in v0.1.0", engine)
	}

	// Load scan results.
	result, err := input.LoadFromFile(fromFile)
	if err != nil {
		return err
	}

	// Apply filters.
	violations := result.Violations
	if severity != "" {
		violations = input.FilterBySeverity(violations, input.Severity(severity))
	}
	if namespace != "" {
		violations = input.FilterByNamespace(violations, namespace)
	}

	if len(violations) == 0 {
		fmt.Println("No violations matched the given filters. Nothing to generate.")
		return nil
	}

	// Collect unique rule IDs.
	ruleIDs := input.UniqueRuleIDs(violations)

	// Group violations by rule ID.
	byRule := make(map[string][]input.Violation)
	for _, v := range violations {
		byRule[v.RuleID] = append(byRule[v.RuleID], v)
	}

	// Generate policies.
	var policies []*policy.GeneratedPolicy
	var skipped []string

	for _, ruleID := range ruleIDs {
		gen, ok := policy.Get(ruleID)
		if !ok {
			skipped = append(skipped, ruleID)
			continue
		}
		p, err := gen.Generate(byRule[ruleID], namespace)
		if err != nil {
			return fmt.Errorf("generating policy for %s: %w", ruleID, err)
		}
		policies = append(policies, p)
	}

	if len(skipped) > 0 {
		fmt.Printf("Warning: no generator found for rule IDs: %v (skipped)\n", skipped)
	}

	if len(policies) == 0 {
		fmt.Println("No policies generated.")
		return nil
	}

	fmt.Printf("Generating %d policies (format: %s) → %s/\n", len(policies), format, outputDir)

	// Write output.
	switch format {
	case "yaml":
		return output.WriteYAML(policies, outputDir)
	case "helm":
		return output.WriteHelm(policies, outputDir)
	case "kustomize":
		return output.WriteKustomize(policies, outputDir)
	default:
		return fmt.Errorf("unsupported format %q: use yaml|helm|kustomize", format)
	}
}
