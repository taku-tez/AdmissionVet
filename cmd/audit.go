package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/audit"
	"github.com/AdmissionVet/admissionvet/internal/exceptions"
)

// NewAuditCommand returns the `admissionvet audit` command.
func NewAuditCommand() *cobra.Command {
	var (
		kubeconfig     string
		context        string
		namespace      string
		outputFmt      string
		exceptionsFile string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit live cluster resources for security violations",
		Long: `Connects to a running Kubernetes cluster and checks live resources
against known security rules (MV1001–MV2001, RB1001–RB1003, NV1001).

Unlike dryrun (which checks manifests against policies), audit directly inspects
what is actually running and reports violations without requiring policy files.

Examples:
  admissionvet audit
  admissionvet audit --namespace production
  admissionvet audit --kubeconfig ~/.kube/prod.yaml --context prod-cluster
  admissionvet audit --output json
  admissionvet audit --exceptions exceptions.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(audit.Options{
				Kubeconfig: kubeconfig,
				Context:    context,
				Namespace:  namespace,
			}, outputFmt, exceptionsFile)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	cmd.Flags().StringVar(&context, "context", "", "Kubeconfig context to use (default: current context)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Limit audit to this namespace (default: all namespaces)")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table|json")
	cmd.Flags().StringVar(&exceptionsFile, "exceptions", "", "Path to exceptions YAML file")

	return cmd
}

func runAudit(opts audit.Options, outputFmt, exceptionsFile string) error {
	scope := "all namespaces"
	if opts.Namespace != "" {
		scope = "namespace: " + opts.Namespace
	}
	fmt.Fprintf(os.Stderr, "Auditing cluster (%s)...\n\n", scope)

	excList, err := exceptions.LoadFromFile(exceptionsFile)
	if err != nil {
		return fmt.Errorf("loading exceptions: %w", err)
	}

	result, err := audit.Run(opts)
	if err != nil {
		return err
	}

	result.Findings = exceptions.Filter(result.Findings, excList, func(f audit.Finding) (string, string, string) {
		return f.RuleID, f.Namespace, f.Kind + "/" + f.Name
	})

	switch outputFmt {
	case "json":
		return printAuditJSON(result)
	default:
		return printAuditTable(result)
	}
}

func printAuditTable(result *audit.Result) error {
	fmt.Printf("Resources scanned: %d\n", result.TotalResources)
	fmt.Printf("Findings        : %d\n\n", len(result.Findings))

	if len(result.Findings) == 0 {
		fmt.Println("No violations found. Cluster resources comply with all checked rules.")
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
		findings := summary[ns]
		fmt.Fprintf(w, "Namespace: %s (%d finding(s))\n", ns, len(findings))
		fmt.Fprintln(w, "  SEVERITY\tRULE\tKIND\tNAME\tMESSAGE")
		fmt.Fprintln(w, "  --------\t----\t----\t----\t-------")
		for _, f := range findings {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				strings.ToUpper(string(f.Severity)),
				f.RuleID, f.Kind, f.Name, f.Message)
		}
		fmt.Fprintln(w)
	}
	w.Flush()

	// Summary by rule.
	byRule := make(map[string]int)
	for _, f := range result.Findings {
		byRule[f.RuleID]++
	}
	ruleIDs := make([]string, 0, len(byRule))
	for id := range byRule {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	fmt.Println("--- Summary by Rule ---")
	w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w2, "RULE\tCOUNT")
	for _, id := range ruleIDs {
		fmt.Fprintf(w2, "%s\t%d\n", id, byRule[id])
	}
	w2.Flush()

	if anyErrors(result.Findings) {
		os.Exit(1)
	}
	return nil
}

type auditJSONOutput struct {
	TotalResources int             `json:"total_resources"`
	TotalFindings  int             `json:"total_findings"`
	Findings       []audit.Finding `json:"findings"`
}

func printAuditJSON(result *audit.Result) error {
	out := auditJSONOutput{
		TotalResources: result.TotalResources,
		TotalFindings:  len(result.Findings),
		Findings:       result.Findings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func anyErrors(findings []audit.Finding) bool {
	for _, f := range findings {
		if f.Severity == audit.SeverityError {
			return true
		}
	}
	return false
}
