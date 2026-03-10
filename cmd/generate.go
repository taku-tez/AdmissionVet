package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/output"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/registry"
	"github.com/AdmissionVet/admissionvet/internal/versions"

	// Register all Gatekeeper generators via side-effect imports.
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/manifestvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/networkvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/rbacvet"

	// Register all Kyverno generators via side-effect imports.
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/imagepolicy"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/manifestvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/networkvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/rbacvet"
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
		diff      bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate admission control policies from scan results",
		Long: `Generate OPA/Gatekeeper or Kyverno policies from scan result JSON
produced by ManifestVet, RBACVet, or NetworkVet.

Examples:
  admissionvet generate --from results.json --engine gatekeeper
  admissionvet generate --from results.json --engine kyverno --format yaml
  admissionvet generate --from results.json --engine kyverno --diff --output existing/
  admissionvet generate --from results.json --severity error --namespace team-a --format helm`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(fromFile, engine, severity, namespace, outputDir, format, diff)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to scan results JSON (required)")
	cmd.Flags().StringVar(&engine, "engine", "gatekeeper", "Policy engine: gatekeeper|kyverno")
	cmd.Flags().StringVar(&severity, "severity", "", "Minimum severity to include: error|warning|info")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Limit policies to this namespace")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Output directory")
	cmd.Flags().StringVar(&format, "format", "yaml", "Output format: yaml|helm|kustomize")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show diff against existing policies in output directory")
	cmd.MarkFlagRequired("from")

	return cmd
}

func runGenerate(fromFile, engine, severity, namespace, outputDir, format string, diff bool) error {
	if engine != "gatekeeper" && engine != "kyverno" {
		return fmt.Errorf("unsupported engine %q: use gatekeeper or kyverno", engine)
	}

	// Load custom rules from the registry (silently ignore errors).
	_ = registry.RegisterAll("")

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
		gen, ok := policy.Get(engine, ruleID)
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

	// Diff mode: compare with existing files.
	if diff {
		return showDiff(policies, outputDir)
	}

	fmt.Printf("Generating %d policies [engine=%s format=%s] → %s/\n", len(policies), engine, format, outputDir)

	// Stash current state before overwriting (for rollback).
	if h, err := versions.Load(outputDir); err == nil && len(h.Entries) > 0 {
		_ = versions.Stash(outputDir, h.Entries[len(h.Entries)-1].Version)
	}

	// Write output.
	var writeErr error
	switch format {
	case "yaml":
		writeErr = output.WriteYAML(policies, outputDir)
	case "helm":
		writeErr = output.WriteHelm(policies, outputDir)
	case "kustomize":
		writeErr = output.WriteKustomize(policies, outputDir)
	default:
		return fmt.Errorf("unsupported format %q: use yaml|helm|kustomize", format)
	}
	if writeErr != nil {
		return writeErr
	}

	// Record this generation in version history.
	if entry, err := versions.Record(outputDir, engine, fromFile); err == nil {
		fmt.Printf("  versioned as v%d\n", entry.Version)
	}
	return nil
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

func printLineDiff(old, new string) {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")

	maxOld := len(oldLines)
	maxNew := len(newLines)
	max := maxOld
	if maxNew > max {
		max = maxNew
	}

	for i := 0; i < max; i++ {
		var oldLine, newLine string
		if i < maxOld {
			oldLine = oldLines[i]
		}
		if i < maxNew {
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
