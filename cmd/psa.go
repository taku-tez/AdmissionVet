package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/psa"
)

// NewPSACommand returns the `admissionvet psa` command group.
func NewPSACommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "psa",
		Short: "Pod Security Admission (PSA) simulation and gap analysis",
	}
	cmd.AddCommand(newPSASimulateCommand())
	return cmd
}

func newPSASimulateCommand() *cobra.Command {
	var (
		fromFile  string
		level     string
		namespace string
	)

	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate PSA enforcement against existing workloads",
		Long: `Check whether existing workloads comply with a given PSA level
(baseline or restricted) BEFORE applying it, to identify blockers.

PSA Levels:
  baseline   — Minimal restrictions (no privileged, no hostPID/IPC/Network, no dangerous caps)
  restricted — Maximum restrictions (baseline + no privilege escalation, runAsNonRoot, drop ALL caps, seccomp)

Examples:
  admissionvet psa simulate --from deployment.yaml --level restricted
  admissionvet psa simulate --from manifests/ --level baseline --namespace team-1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPSASimulate(fromFile, psa.Level(level), namespace)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to manifest YAML file or directory (required)")
	cmd.Flags().StringVar(&level, "level", "baseline", "PSA level to simulate: baseline|restricted")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Only simulate resources in this namespace")
	cmd.MarkFlagRequired("from")

	return cmd
}

func runPSASimulate(fromFile string, level psa.Level, namespace string) error {
	if level != psa.LevelBaseline && level != psa.LevelRestricted {
		return fmt.Errorf("unsupported level %q: use baseline or restricted", level)
	}

	files, err := expandPaths([]string{fromFile})
	if err != nil {
		return err
	}

	var violations []psa.Violation
	for _, f := range files {
		v, err := psa.SimulateFile(f, level, namespace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", f, err)
			continue
		}
		violations = append(violations, v...)
	}

	fmt.Printf("PSA Simulation — level: %s\n\n", level)

	if len(violations) == 0 {
		fmt.Printf("All workloads comply with PSA level '%s'.\n", level)
		fmt.Printf("Safe to apply: kubectl label namespace <ns> pod-security.kubernetes.io/enforce=%s\n", level)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RULE\tRESOURCE\tMESSAGE")
	fmt.Fprintln(w, "----\t--------\t-------")
	for _, v := range violations {
		fmt.Fprintf(w, "%s\t%s\t%s\n", v.RuleID, v.Resource, v.Message)
	}
	w.Flush()

	recommended := psa.RecommendLevel(violations)
	fmt.Printf("\n%d violation(s) found.\n", len(violations))
	fmt.Printf("Recommended PSA level for current workloads: %s\n", recommended)
	fmt.Printf("\nFix the violations above, then apply:\n")
	fmt.Printf("  kubectl label namespace <ns> pod-security.kubernetes.io/enforce=%s\n", level)

	return fmt.Errorf("PSA simulation found %d violation(s)", len(violations))
}
