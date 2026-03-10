package cmd

import (
	"fmt"
	"os"
	"sort"
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

	summary := result.Summary()
	namespaces := make([]string, 0, len(summary))
	for ns := range summary {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, ns := range namespaces {
		hits := summary[ns]
		fmt.Fprintf(w, "\nNamespace: %s (%d hit(s))\n", ns, len(hits))
		fmt.Fprintln(w, "  ACTION\tKIND\tNAME\tPOLICY\tMESSAGE")
		fmt.Fprintln(w, "  ------\t----\t----\t------\t-------")
		for _, h := range hits {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				strings.ToUpper(h.Action), h.Resource.Kind, h.Resource.Name, h.Policy, h.Message)
		}
	}
	w.Flush()

	if len(result.RolloutImpacts) > 0 {
		fmt.Printf("\n--- Rollout Impact ---\n")
		fmt.Printf("The following Deployments/StatefulSets would fail to roll out:\n\n")
		w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w2, "KIND\tNAMESPACE\tNAME\tREPLICAS\tBLOCKED BY")
		fmt.Fprintln(w2, "----\t---------\t----\t--------\t----------")
		for _, impact := range result.RolloutImpacts {
			seen := make(map[string]bool)
			var pnames []string
			for _, h := range impact.PolicyHits {
				if !seen[h.Policy] {
					seen[h.Policy] = true
					pnames = append(pnames, h.Policy)
				}
			}
			sort.Strings(pnames)
			fmt.Fprintf(w2, "%s\t%s\t%s\t%d\t%s\n",
				impact.Resource.Kind,
				impact.Resource.Namespace,
				impact.Resource.Name,
				impact.Replicas,
				strings.Join(pnames, ", "),
			)
		}
		w2.Flush()
	}

	fmt.Printf("\n--- Migration Plan ---\n")
	fmt.Printf("Step 1: Apply policies in 'warn' mode first:\n")
	fmt.Printf("        (Set enforcementAction: warn in Constraint, or validationFailureAction: Audit in ClusterPolicy)\n")
	fmt.Printf("Step 2: Fix the %d resource(s) listed above.\n", result.BlockCount())
	fmt.Printf("Step 3: Switch to 'enforce' mode:\n")
	fmt.Printf("        (Set enforcementAction: deny in Constraint, or validationFailureAction: Enforce in ClusterPolicy)\n")

	return nil
}
