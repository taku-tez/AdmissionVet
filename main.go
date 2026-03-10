package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/cmd"
)

var rootCmd = &cobra.Command{
	Use:   "admissionvet",
	Short: "AdmissionVet — shift Kubernetes security from detection to prevention",
	Long: `AdmissionVet generates and validates Kubernetes admission control policies
from existing scan violations, enabling real-time blocking via OPA/Gatekeeper
or Kyverno admission webhooks.

Commands:
  generate      Generate policies from scan result JSON
  apply         Generate policies from a built-in preset
  list-policies List available built-in policy presets
  webhook       Validate and test webhook configurations
  psa           Pod Security Admission simulation
  dryrun        Simulate policy enforcement against existing manifests`,
}

func main() {
	rootCmd.AddCommand(cmd.NewGenerateCommand())
	rootCmd.AddCommand(cmd.NewApplyCommand())
	rootCmd.AddCommand(cmd.NewListPoliciesCommand())
	rootCmd.AddCommand(cmd.NewWebhookCommand())
	rootCmd.AddCommand(cmd.NewPSACommand())
	rootCmd.AddCommand(cmd.NewDryrunCommand())
	rootCmd.AddCommand(cmd.NewVersionCommand())
	rootCmd.AddCommand(cmd.NewRegistryCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
