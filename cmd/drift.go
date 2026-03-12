package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/audit"
)

// NewDriftCommand returns the `admissionvet drift` command.
func NewDriftCommand() *cobra.Command {
	var (
		outputDir  string
		engine     string
		kubeconfig string
		context    string
	)

	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Detect drift between generated policies and deployed cluster state",
		Long: `Compares policies in the local output directory against what is currently
deployed in the cluster, and reports any differences.

New:     Policy is generated locally but not yet deployed.
Changed: Policy exists in both but the specs differ.
Missing: Policy is in the cluster but not in the local output directory.

Examples:
  admissionvet drift --output output/ --engine gatekeeper
  admissionvet drift --output output/ --engine kyverno --kubeconfig ~/.kube/prod.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDrift(outputDir, engine, audit.Options{
				Kubeconfig: kubeconfig,
				Context:    context,
			})
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Directory containing generated policies")
	cmd.Flags().StringVar(&engine, "engine", "gatekeeper", "Policy engine: gatekeeper|kyverno")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&context, "context", "", "Kubeconfig context to use")

	return cmd
}

func runDrift(outputDir, engine string, opts audit.Options) error {
	if err := validateEngine(engine); err != nil {
		return err
	}

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return fmt.Errorf("output directory %q does not exist — run 'admissionvet generate' first", outputDir)
	}

	fmt.Fprintf(os.Stderr, "Checking drift: %s (engine=%s)...\n\n", outputDir, engine)

	result, err := audit.CheckDrift(outputDir, engine, opts)
	if err != nil {
		return err
	}

	if len(result.Findings) == 0 {
		fmt.Println("No drift detected. Deployed policies match the local output directory.")
		return nil
	}

	var newCount, changedCount, missingCount int
	for _, f := range result.Findings {
		switch f.Status {
		case audit.DriftStatusNew:
			newCount++
		case audit.DriftStatusChanged:
			changedCount++
		case audit.DriftStatusMissing:
			missingCount++
		}
	}
	fmt.Printf("Drift detected: %d new, %d changed, %d missing\n\n",
		newCount, changedCount, missingCount)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tPOLICY\tMESSAGE")
	fmt.Fprintln(w, "------\t------\t-------")
	for _, f := range result.Findings {
		fmt.Fprintf(w, "%s\t%s\t%s\n",
			statusIcon(f.Status), f.PolicyName, f.Message)
	}
	w.Flush()

	fmt.Println()
	fmt.Println("To apply missing/changed policies, run: kubectl apply -f " + outputDir + "/")

	return nil
}

func statusIcon(s audit.DriftStatus) string {
	switch s {
	case audit.DriftStatusNew:
		return "[NEW]"
	case audit.DriftStatusChanged:
		return "[CHANGED]"
	case audit.DriftStatusMissing:
		return "[MISSING]"
	}
	return string(s)
}
