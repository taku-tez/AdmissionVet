package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/library"
	"github.com/AdmissionVet/admissionvet/internal/registry"
)

// NewListPoliciesCommand returns the `admissionvet list-policies` command.
func NewListPoliciesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list-policies",
		Short: "List available built-in policy presets",
		Long: `Displays all built-in policy presets with their descriptions and rule coverage.

Use 'admissionvet apply --preset <name>' to generate and output a preset.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListPolicies()
		},
	}
}

func runListPolicies() error {
	presets := library.All()

	fmt.Printf("Available policy presets (%d):\n\n", len(presets))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PRESET\tTAGS\tRULES\tDESCRIPTION")
	fmt.Fprintln(w, "------\t----\t-----\t-----------")
	for _, p := range presets {
		ruleIDs := make([]string, len(p.Violations))
		for i, v := range p.Violations {
			ruleIDs[i] = v.RuleID
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			p.Name,
			strings.Join(p.Tags, ","),
			strings.Join(ruleIDs, " "),
			p.Description,
		)
	}
	w.Flush()

	fmt.Printf("\nUsage:\n")
	fmt.Printf("  admissionvet apply --preset baseline --engine gatekeeper\n")
	fmt.Printf("  admissionvet apply --preset pci-dss  --engine kyverno --format helm\n")
	return nil
}

// NewApplyCommand returns the `admissionvet apply` command.
func NewApplyCommand() *cobra.Command {
	var (
		preset    string
		engine    string
		namespace string
		outputDir string
		format    string
	)

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Generate and output a built-in policy preset",
		Long: `Generates all policies for a named preset and writes them to the output directory.

Examples:
  admissionvet apply --preset baseline --engine gatekeeper
  admissionvet apply --preset gke-standard --engine kyverno --format helm --output ./policies
  admissionvet apply --preset pci-dss --engine kyverno --namespace payment`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(preset, engine, namespace, outputDir, format)
		},
	}

	cmd.Flags().StringVar(&preset, "preset", "", "Preset name: baseline|restricted|gke-standard|eks-standard|pci-dss (required)")
	cmd.Flags().StringVar(&engine, "engine", "gatekeeper", "Policy engine: gatekeeper|kyverno")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Limit policies to this namespace")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Output directory")
	cmd.Flags().StringVar(&format, "format", "yaml", "Output format: yaml|helm|kustomize")
	cmd.MarkFlagRequired("preset")

	return cmd
}

func runApply(presetName, engine, namespace, outputDir, format string) error {
	if err := validateEngine(engine); err != nil {
		return err
	}
	_ = registry.RegisterAll("") // load custom rules (best-effort)

	p := library.Get(presetName)
	if p == nil {
		var names []string
		for _, pr := range library.All() {
			names = append(names, pr.Name)
		}
		return fmt.Errorf("unknown preset %q. Available: %s", presetName, strings.Join(names, ", "))
	}

	ruleIDs := input.UniqueRuleIDs(p.Violations)
	byRule := make(map[string][]input.Violation)
	for _, v := range p.Violations {
		byRule[v.RuleID] = append(byRule[v.RuleID], v)
	}

	policies, skipped, err := generatePolicies(engine, ruleIDs, byRule, namespace)
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		fmt.Printf("Warning: no generator found for: %v (skipped)\n", skipped)
	}
	if len(policies) == 0 {
		fmt.Println("No policies generated.")
		return nil
	}

	fmt.Printf("Applying preset '%s' [engine=%s format=%s] — %d policies → %s/\n",
		p.Name, engine, format, len(policies), outputDir)
	return writePolicies(policies, format, outputDir, engine, "preset:"+presetName)
}
