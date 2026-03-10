package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

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
		output   string
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
  admissionvet webhook validate --cluster --severity high
  admissionvet webhook validate --cluster --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebhookValidate(fromFile, cluster, severity, output)
		},
	}

	cmd.Flags().StringVarP(&fromFile, "from", "f", "", "Path to webhook configuration YAML")
	cmd.Flags().BoolVar(&cluster, "cluster", false, "Fetch configurations from the current cluster via kubectl")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter findings: critical|high|medium|low|info")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "Output format: text|json")

	return cmd
}

func runWebhookValidate(fromFile string, cluster bool, severity string, output string) error {
	var findings []webhook.Finding
	var err error

	switch {
	case cluster:
		if output != "json" {
			fmt.Fprintln(os.Stderr, "Fetching webhook configurations from cluster...")
		}
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

	if strings.ToLower(output) == "json" {
		return writeWebhookJSON(findings)
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

	criticalCount := countBySeverity(findings, webhook.SeverityCritical)
	highCount := countBySeverity(findings, webhook.SeverityHigh)
	mediumCount := countBySeverity(findings, webhook.SeverityMedium)
	lowCount := countBySeverity(findings, webhook.SeverityLow)
	infoCount := countBySeverity(findings, webhook.SeverityInfo)
	fmt.Printf("\ncritical: %d, high: %d, medium: %d, low: %d, info: %d\n",
		criticalCount, highCount, mediumCount, lowCount, infoCount)

	if criticalCount > 0 || highCount > 0 {
		os.Exit(1)
	}
	return nil
}

type jsonWebhookFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Webhook  string `json:"webhook"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
}

type jsonWebhookOutput struct {
	Summary struct {
		Total    int `json:"total"`
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Info     int `json:"info"`
	} `json:"summary"`
	Findings []jsonWebhookFinding `json:"findings"`
}

func writeWebhookJSON(findings []webhook.Finding) error {
	out := jsonWebhookOutput{}
	out.Findings = make([]jsonWebhookFinding, 0, len(findings))
	for _, f := range findings {
		out.Findings = append(out.Findings, jsonWebhookFinding{
			RuleID:   f.RuleID,
			Severity: string(f.Severity),
			Webhook:  f.Webhook,
			Kind:     f.Kind,
			Message:  f.Message,
		})
		out.Summary.Total++
		switch f.Severity {
		case webhook.SeverityCritical:
			out.Summary.Critical++
		case webhook.SeverityHigh:
			out.Summary.High++
		case webhook.SeverityMedium:
			out.Summary.Medium++
		case webhook.SeverityLow:
			out.Summary.Low++
		case webhook.SeverityInfo:
			out.Summary.Info++
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
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
			r.Webhook, r.URL, reachable, r.ResponseTime.Round(time.Millisecond), r.Error)
	}
	w.Flush()
	return nil
}

func filterFindings(findings []webhook.Finding, minSev webhook.Severity) []webhook.Finding {
	rank := map[webhook.Severity]int{
		webhook.SeverityCritical: 5,
		webhook.SeverityHigh:     4,
		webhook.SeverityMedium:   3,
		webhook.SeverityLow:      2,
		webhook.SeverityInfo:     1,
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
