package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/webhook"
)

// NewWebhookCommand returns the `admissionvet webhook` command group.
func NewWebhookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Validate and test Kubernetes admission webhook configurations",
	}
	cmd.AddCommand(newWebhookValidateCommand())
	cmd.AddCommand(newWebhookTestCommand())
	return cmd
}

func newWebhookValidateCommand() *cobra.Command {
	var (
		fromFile string
		cluster  bool
		severity string
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Detect misconfigurations in ValidatingWebhookConfiguration and MutatingWebhookConfiguration",
		Long: `Checks webhook configurations for:
  AV3001 failurePolicy: Ignore  — webhook bypass risk
  AV3002 timeoutSeconds < 10   — false failure risk under load
  AV3003 missing kube-system exclusion in namespaceSelector
  AV3004 reinvocationPolicy: IfNeeded without idempotency guarantee (Mutating)
  AV3005 TLS certificate expiry

Examples:
  admissionvet webhook validate --from webhook.yaml
  admissionvet webhook validate --cluster
  admissionvet webhook validate --cluster --severity error`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebhookValidate(fromFile, cluster, severity)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to webhook configuration YAML")
	cmd.Flags().BoolVar(&cluster, "cluster", false, "Fetch configurations from the current cluster via kubectl")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter findings: error|warning|info")

	return cmd
}

func runWebhookValidate(fromFile string, cluster bool, severity string) error {
	var findings []webhook.Finding
	var err error

	switch {
	case cluster:
		fmt.Println("Fetching webhook configurations from cluster...")
		findings, err = webhook.ValidateCluster()
	case fromFile != "":
		findings, err = webhook.ValidateFile(fromFile)
	default:
		return fmt.Errorf("specify --from <file> or --cluster")
	}
	if err != nil {
		return err
	}

	// Filter by severity.
	if severity != "" {
		findings = filterFindings(findings, webhook.Severity(severity))
	}

	if len(findings) == 0 {
		fmt.Println("No issues found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RULE\tSEVERITY\tWEBHOOK\tMESSAGE")
	fmt.Fprintln(w, "----\t--------\t-------\t-------")
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.RuleID, f.Severity, f.Webhook, f.Message)
	}
	w.Flush()

	errCount := countBySeverity(findings, webhook.SeverityError)
	warnCount := countBySeverity(findings, webhook.SeverityWarning)
	fmt.Printf("\n%d error(s), %d warning(s)\n", errCount, warnCount)

	if errCount > 0 {
		os.Exit(1)
	}
	return nil
}

func newWebhookTestCommand() *cobra.Command {
	var fromFile string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test webhook endpoint reachability and measure response time",
		Long: `Attempts a TLS connection to each webhook service endpoint and
reports reachability and response time.

Example:
  admissionvet webhook test --from webhook.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebhookTest(fromFile)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to webhook configuration YAML (required)")
	cmd.MarkFlagRequired("from")

	return cmd
}

func runWebhookTest(fromFile string) error {
	results, err := webhook.TestWebhookReachability(fromFile)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		fmt.Println("No webhook endpoints found to test.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "WEBHOOK\tURL\tREACHABLE\tRESPONSE TIME\tERROR")
	fmt.Fprintln(w, "-------\t---\t---------\t-------------\t-----")
	for _, r := range results {
		reachable := "YES"
		if !r.Reachable {
			reachable = "NO"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.Webhook, r.URL, reachable, r.ResponseTime.Round(1*1000000), r.Error)
	}
	w.Flush()
	return nil
}

func filterFindings(findings []webhook.Finding, minSev webhook.Severity) []webhook.Finding {
	rank := map[webhook.Severity]int{
		webhook.SeverityError:   3,
		webhook.SeverityWarning: 2,
		webhook.SeverityInfo:    1,
	}
	min := rank[minSev]
	var result []webhook.Finding
	for _, f := range findings {
		if rank[f.Severity] >= min {
			result = append(result, f)
		}
	}
	return result
}

func countBySeverity(findings []webhook.Finding, sev webhook.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}
