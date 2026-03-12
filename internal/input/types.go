// Package input provides the core data types and loaders for security scan results.
//
// It auto-detects three input formats:
//   - Native AdmissionVet JSON ({"violations": [...]})
//   - Trivy k8s JSON ({"ArtifactType": "kubernetes", "Resources": [...]})
//   - K8sVet unified JSON ({"results": [...]})
//
// Rule IDs from Trivy (KSV*) and K8sVet are normalised to AdmissionVet's canonical
// format (MV*, RB*, NV*) automatically by LoadFromFile.
package input

// Severity represents the severity level of a violation.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// severityRank maps Severity to an integer for comparison.
var severityRank = map[Severity]int{
	SeverityError:   3,
	SeverityWarning: 2,
	SeverityInfo:    1,
}

// Violation represents a single policy violation from a scan result.
type Violation struct {
	RuleID    string   `json:"rule_id"`
	Severity  Severity `json:"severity"`
	Resource  string   `json:"resource"`
	Namespace string   `json:"namespace,omitempty"`
	Message   string   `json:"message"`
}

// ScanResult is the top-level structure of a scan result JSON file.
type ScanResult struct {
	Violations []Violation `json:"violations"`
}

// FilterBySeverity returns violations at or above the given minimum severity.
// If minSeverity is empty, all violations are returned.
func FilterBySeverity(violations []Violation, minSeverity Severity) []Violation {
	if minSeverity == "" {
		return violations
	}
	minRank, ok := severityRank[minSeverity]
	if !ok {
		return violations
	}
	var result []Violation
	for _, v := range violations {
		if severityRank[v.Severity] >= minRank {
			result = append(result, v)
		}
	}
	return result
}

// FilterByNamespace returns violations matching the given namespace.
// If namespace is empty, all violations are returned.
func FilterByNamespace(violations []Violation, namespace string) []Violation {
	if namespace == "" {
		return violations
	}
	var result []Violation
	for _, v := range violations {
		if v.Namespace == namespace {
			result = append(result, v)
		}
	}
	return result
}

// UniqueRuleIDs returns a deduplicated list of rule IDs from violations,
// preserving the order of first occurrence.
func UniqueRuleIDs(violations []Violation) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, v := range violations {
		if !seen[v.RuleID] {
			seen[v.RuleID] = true
			ids = append(ids, v.RuleID)
		}
	}
	return ids
}
