// Package exceptions provides loading and matching of policy exception rules.
// An exception suppresses a finding for a specific combination of rule, namespace,
// and/or resource — preventing false positives for known acceptable configurations.
package exceptions

import "strings"

// Exception defines a single suppression rule.
type Exception struct {
	// RuleID is the AdmissionVet rule to suppress (e.g. "MV1001").
	// If empty, matches any rule.
	RuleID string `yaml:"ruleID"`

	// Namespace is the Kubernetes namespace to suppress the rule in.
	// If empty, matches any namespace.
	Namespace string `yaml:"namespace"`

	// Resource is the resource name or "Kind/Name" to suppress.
	// If empty, matches any resource.
	Resource string `yaml:"resource"`

	// Reason documents why this exception exists.
	Reason string `yaml:"reason"`
}

// ExceptionList is the top-level structure of an exceptions YAML file.
type ExceptionList struct {
	Exceptions []Exception `yaml:"exceptions"`
}

// Matches returns true if this exception applies to the given combination of
// ruleID, namespace, and resource. Empty fields act as wildcards.
// Comparisons are case-insensitive to tolerate mixed-case resource names.
func (e Exception) Matches(ruleID, namespace, resource string) bool {
	if e.RuleID != "" && !strings.EqualFold(e.RuleID, ruleID) {
		return false
	}
	if e.Namespace != "" && !strings.EqualFold(e.Namespace, namespace) {
		return false
	}
	if e.Resource != "" && !strings.EqualFold(e.Resource, resource) {
		return false
	}
	return true
}
