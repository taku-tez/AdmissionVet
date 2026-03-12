// Package audit fetches live Kubernetes resources and checks them against
// known security rules, reporting real violations in the running cluster.
package audit

// Severity of an audit finding.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Finding represents a single security issue found in a live cluster resource.
type Finding struct {
	Namespace string
	Kind      string
	Name      string
	RuleID    string
	Severity  Severity
	Message   string
}

// Result is the full output of a cluster audit.
type Result struct {
	TotalResources int
	Findings       []Finding
}

// Summary returns findings grouped by namespace.
func (r *Result) Summary() map[string][]Finding {
	m := make(map[string][]Finding)
	for _, f := range r.Findings {
		ns := f.Namespace
		if ns == "" {
			ns = "(cluster-scoped)"
		}
		m[ns] = append(m[ns], f)
	}
	return m
}

// Options controls how the audit runs.
type Options struct {
	Kubeconfig string // path to kubeconfig; empty = default
	Context    string // kubeconfig context to use; empty = current
	Namespace  string // limit to this namespace; empty = all namespaces
}
