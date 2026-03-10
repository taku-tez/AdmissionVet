package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/registry"
)

// NewRegistryCommand returns the `admissionvet registry` command group.
func NewRegistryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Manage the organization custom policy registry",
		Long: `The registry stores custom policy rules in ~/.admissionvet/registry/.
Rules are YAML files that define additional generators for 'generate' and 'apply'.

Custom rule YAML format:
  rule_id: CUSTOM001
  engine: kyverno          # or gatekeeper
  description: "My custom rule"
  match_kinds: [Pod, Deployment]
  severity: error
  validate_action: Enforce
  validate_message: "My message"
  validate_pattern: |
    spec:
      containers:
        - imagePullPolicy: Always`,
	}
	cmd.AddCommand(newRegistryAddCommand())
	cmd.AddCommand(newRegistryListCommand())
	cmd.AddCommand(newRegistryRemoveCommand())
	return cmd
}

func newRegistryAddCommand() *cobra.Command {
	var ruleFile string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a custom rule to the registry",
		Example: `  admissionvet registry add --file my-rule.yaml
  admissionvet registry add -f custom/require-labels.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryAdd(ruleFile)
		},
	}
	cmd.Flags().StringVarP(&ruleFile, "file", "f", "", "Path to the custom rule YAML file (required)")
	cmd.MarkFlagRequired("file")
	return cmd
}

func runRegistryAdd(ruleFile string) error {
	if err := registry.Add(ruleFile, ""); err != nil {
		return err
	}
	fmt.Printf("Custom rule added to registry from %s\n", ruleFile)
	fmt.Printf("It will be available in 'admissionvet generate' and 'admissionvet apply'.\n")
	return nil
}

func newRegistryListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List custom rules in the registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryList()
		},
	}
}

func runRegistryList() error {
	rules, err := registry.LoadAll("")
	if err != nil {
		return err
	}

	if len(rules) == 0 {
		fmt.Println("No custom rules in registry.")
		fmt.Printf("Add rules with: admissionvet registry add --file rule.yaml\n")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RULE ID\tENGINE\tKINDS\tDESCRIPTION")
	fmt.Fprintln(w, "-------\t------\t-----\t-----------")
	for _, r := range rules {
		kinds := ""
		for i, k := range r.MatchKinds {
			if i > 0 {
				kinds += ","
			}
			kinds += k
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.RuleID, r.Engine, kinds, r.Description)
	}
	w.Flush()
	return nil
}

func newRegistryRemoveCommand() *cobra.Command {
	var ruleID string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a custom rule from the registry",
		Example: `  admissionvet registry remove --rule-id CUSTOM001`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryRemove(ruleID)
		},
	}
	cmd.Flags().StringVar(&ruleID, "rule-id", "", "Rule ID to remove (required)")
	cmd.MarkFlagRequired("rule-id")
	return cmd
}

func runRegistryRemove(ruleID string) error {
	if err := registry.Remove(ruleID, ""); err != nil {
		return err
	}
	fmt.Printf("Custom rule %s removed from registry.\n", ruleID)
	return nil
}
