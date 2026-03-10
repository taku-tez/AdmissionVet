package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/dryrun"
)

// NewDryrunCommand returns the `admissionvet dryrun` command.
func NewDryrunCommand() *cobra.Command {
	var (
		manifestPaths []string
		policyPaths   []string
	)

	cmd := &cobra.Command{
		Use:   "dryrun",
		Short: "Simulate policy enforcement against existing manifests",
		Long: `Evaluates existing Kubernetes resources against generated policies
WITHOUT applying anything to the cluster.

Shows which resources would be blocked or warned, grouped by namespace,
to help plan a phased rollout (warn → enforce).

Examples:
  admissionvet dryrun --manifest deployment.yaml --policy output/mv1001-constraint.yaml
  admissionvet dryrun --manifest manifests/ --policy output/
  admissionvet dryrun --manifest k8s/ --policy output/ --policy extra-policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDryrun(manifestPaths, policyPaths)
		},
	}

	cmd.Flags().StringArrayVarP(&manifestPaths, "manifest", "m", nil, "Manifest file or directory (repeatable, required)")
	cmd.Flags().StringArrayVarP(&policyPaths, "policy", "p", nil, "Policy file or directory (repeatable, required)")
	cmd.MarkFlagRequired("manifest")
	cmd.MarkFlagRequired("policy")

	return cmd
}

func runDryrun(manifestArgs, policyArgs []string) error {
	// Expand directories to file lists.
	manifestFiles, err := expandPaths(manifestArgs)
	if err != nil {
		return fmt.Errorf("expanding manifest paths: %w", err)
	}
	policyFiles, err := expandPaths(policyArgs)
	if err != nil {
		return fmt.Errorf("expanding policy paths: %w", err)
	}

	if len(manifestFiles) == 0 {
		return fmt.Errorf("no manifest YAML files found")
	}
	if len(policyFiles) == 0 {
		return fmt.Errorf("no policy YAML files found")
	}

	fmt.Printf("Simulating %d policies against %d manifest files...\n\n",
		len(policyFiles), len(manifestFiles))

	result, err := dryrun.RunFromFiles(manifestFiles, policyFiles)
	if err != nil {
		return err
	}

	fmt.Printf("Resources scanned : %d\n", result.TotalResources)
	fmt.Printf("Policies evaluated: %d\n", result.TotalPolicies)
	fmt.Printf("Would block       : %d resource(s)\n\n", result.BlockCount())

	if len(result.Hits) == 0 {
		fmt.Println("All resources comply with the evaluated policies.")
		return nil
	}

	// Group by namespace.
	summary := result.Summary()
	namespaces := sortedKeys(summary)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, ns := range namespaces {
		hits := summary[ns]
		fmt.Fprintf(w, "\nNamespace: %s (%d hit(s))\n", ns, len(hits))
		fmt.Fprintln(w, "  ACTION\tKIND\tNAME\tPOLICY\tMESSAGE")
		fmt.Fprintln(w, "  ------\t----\t----\t------\t-------")
		for _, h := range hits {
			action := strings.ToUpper(h.Action)
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				action, h.Resource.Kind, h.Resource.Name, h.Policy, h.Message)
		}
	}
	w.Flush()

	// Migration plan suggestion.
	fmt.Printf("\n--- Migration Plan ---\n")
	fmt.Printf("Step 1: Apply policies in 'warn' mode first:\n")
	fmt.Printf("        (Set enforcementAction: warn in Constraint, or validationFailureAction: Audit in ClusterPolicy)\n")
	fmt.Printf("Step 2: Fix the %d resource(s) listed above.\n", result.BlockCount())
	fmt.Printf("Step 3: Switch to 'enforce' mode:\n")
	fmt.Printf("        (Set enforcementAction: deny in Constraint, or validationFailureAction: Enforce in ClusterPolicy)\n")

	return nil
}

// expandPaths resolves a list of file/directory paths into a flat list of YAML file paths.
func expandPaths(args []string) ([]string, error) {
	var files []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("cannot access %s: %w", arg, err)
		}
		if info.IsDir() {
			entries, err := os.ReadDir(arg)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
					files = append(files, arg+"/"+name)
				}
			}
		} else {
			files = append(files, arg)
		}
	}
	return files, nil
}

func sortedKeys(m map[string][]dryrun.PolicyHit) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple sort.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
