package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/exceptions"
	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/registry"
)

// NewGenerateCommand returns the `admissionvet generate` cobra command.
func NewGenerateCommand() *cobra.Command {
	var (
		fromFile       string
		engine         string
		severity       string
		namespace      string
		outputDir      string
		format         string
		diff           bool
		exceptionsFile string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate admission control policies from scan results",
		Long: `Generate OPA/Gatekeeper or Kyverno policies from scan result JSON
produced by ManifestVet, RBACVet, NetworkVet, or Trivy k8s.

Examples:
  admissionvet generate --from results.json --engine gatekeeper
  admissionvet generate --from results.json --engine kyverno --format yaml
  admissionvet generate --from results.json --engine kyverno --diff --output existing/
  admissionvet generate --from results.json --severity error --namespace team-a --format helm
  admissionvet generate --from trivy.json --engine kyverno --exceptions exceptions.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(fromFile, engine, severity, namespace, outputDir, format, exceptionsFile, diff)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to scan results JSON (required)")
	cmd.Flags().StringVar(&engine, "engine", "gatekeeper", "Policy engine: gatekeeper|kyverno")
	cmd.Flags().StringVar(&severity, "severity", "", "Minimum severity to include: error|warning|info")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Limit policies to this namespace")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Output directory")
	cmd.Flags().StringVar(&format, "format", "yaml", "Output format: yaml|helm|kustomize")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show diff against existing policies in output directory")
	cmd.Flags().StringVar(&exceptionsFile, "exceptions", "", "Path to exceptions YAML file")
	cmd.MarkFlagRequired("from")

	return cmd
}

func runGenerate(fromFile, engine, severity, namespace, outputDir, format, exceptionsFile string, diff bool) error {
	if err := validateEngine(engine); err != nil {
		return err
	}

	_ = registry.RegisterAll("") // load custom rules (best-effort)

	result, err := input.LoadFromFile(fromFile)
	if err != nil {
		return err
	}

	excList, err := exceptions.LoadFromFile(exceptionsFile)
	if err != nil {
		return fmt.Errorf("loading exceptions: %w", err)
	}

	violations := result.Violations
	if severity != "" {
		violations = input.FilterBySeverity(violations, input.Severity(severity))
	}
	if namespace != "" {
		violations = input.FilterByNamespace(violations, namespace)
	}
	violations = exceptions.Filter(violations, excList, func(v input.Violation) (string, string, string) {
		return v.RuleID, v.Namespace, v.Resource
	})

	if len(violations) == 0 {
		fmt.Println("No violations matched the given filters. Nothing to generate.")
		return nil
	}

	ruleIDs := input.UniqueRuleIDs(violations)
	byRule := make(map[string][]input.Violation)
	for _, v := range violations {
		byRule[v.RuleID] = append(byRule[v.RuleID], v)
	}

	policies, skipped, err := generatePolicies(engine, ruleIDs, byRule, namespace)
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		fmt.Printf("Warning: no generator found for rule IDs: %v (skipped)\n", skipped)
	}
	if len(policies) == 0 {
		fmt.Println("No policies generated.")
		return nil
	}

	if diff {
		return showDiff(policies, outputDir)
	}

	fmt.Printf("Generating %d policies [engine=%s format=%s] → %s/\n", len(policies), engine, format, outputDir)
	return writePolicies(policies, format, outputDir, engine, fromFile)
}

// showDiff prints a line-level diff between generated policies and existing files.
func showDiff(policies []*policy.GeneratedPolicy, outputDir string) error {
	type fileContent struct {
		path    string
		content string
	}

	var files []fileContent
	for _, p := range policies {
		ruleID := strings.ToLower(p.RuleID)
		if p.ConstraintTemplate != "" {
			files = append(files, fileContent{ruleID + "-constrainttemplate.yaml", p.ConstraintTemplate})
		}
		if p.Constraint != "" {
			files = append(files, fileContent{ruleID + "-constraint.yaml", p.Constraint})
		}
		if p.ClusterPolicy != "" {
			files = append(files, fileContent{ruleID + "-clusterpolicy.yaml", p.ClusterPolicy})
		}
		if p.NetworkPolicy != "" {
			files = append(files, fileContent{ruleID + "-networkpolicy.yaml", p.NetworkPolicy})
		}
	}

	hasDiff := false
	for _, f := range files {
		path := outputDir + "/" + f.path
		existing, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("[NEW] %s\n", f.path)
			hasDiff = true
			continue
		}
		if string(existing) != f.content {
			fmt.Printf("[CHANGED] %s\n", f.path)
			printLineDiff(string(existing), f.content)
			hasDiff = true
		}
	}

	if !hasDiff {
		fmt.Println("No differences found. Policies are up to date.")
	}
	return nil
}

func printLineDiff(oldContent, newContent string) {
	oldLines := strings.Split(oldContent, "\n")
	newLines := strings.Split(newContent, "\n")

	n := max(len(oldLines), len(newLines))

	for i := range n {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}
		if oldLine != newLine {
			if oldLine != "" {
				fmt.Printf("  - %s\n", oldLine)
			}
			if newLine != "" {
				fmt.Printf("  + %s\n", newLine)
			}
		}
	}
}
