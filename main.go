package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/cmd"
)

var rootCmd = &cobra.Command{
	Use:   "admissionvet",
	Short: "AdmissionVet — shift from detection to prevention",
	Long: `AdmissionVet generates Kubernetes admission control policies
from existing scan violations, enabling real-time blocking via
OPA/Gatekeeper or Kyverno admission webhooks.`,
}

func main() {
	rootCmd.AddCommand(cmd.NewGenerateCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
