// Package kyverno provides builders for Kyverno ClusterPolicy YAML resources.
package kyverno

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/AdmissionVet/admissionvet/internal/input"
)

// WorkloadKinds are the Kubernetes kinds that run workloads.
var WorkloadKinds = []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

// RuleType represents the type of a Kyverno rule.
type RuleType string

const (
	RuleTypeValidate     RuleType = "validate"
	RuleTypeMutate       RuleType = "mutate"
	RuleTypeGenerate     RuleType = "generate"
	RuleTypeVerifyImages RuleType = "verify-images"
)

// PolicyParams holds all data needed to render a Kyverno ClusterPolicy.
type PolicyParams struct {
	Name        string
	Description string
	Rules       []Rule
}

// Rule represents a single Kyverno rule within a ClusterPolicy.
type Rule struct {
	Name        string
	MatchKinds  []string
	MatchGroups []string
	Namespaces  []string // optional namespace filter
	Type        RuleType
	Body        string // pre-rendered YAML body for the rule type block
}

const clusterPolicyTmpl = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: {{ .Name }}
  annotations:
    policies.kyverno.io/description: {{ .Description }}
spec:
  rules:
{{ range .Rules }}  - name: {{ .Name }}
    match:
      any:
        - resources:
            kinds:
{{ matchKinds .MatchKinds }}{{ if .Namespaces }}            namespaces:
{{ namespaceList .Namespaces }}{{ end }}{{ .Body }}
{{ end }}`

var funcMap = template.FuncMap{
	"matchKinds": func(kinds []string) string {
		var sb strings.Builder
		for _, k := range kinds {
			sb.WriteString(fmt.Sprintf("              - %s\n", k))
		}
		return sb.String()
	},
	"namespaceList": func(nss []string) string {
		var sb strings.Builder
		for _, ns := range nss {
			sb.WriteString(fmt.Sprintf("              - %s\n", ns))
		}
		return sb.String()
	},
}

var cpTmpl = template.Must(template.New("cp").Funcs(funcMap).Parse(clusterPolicyTmpl))

// BuildClusterPolicy renders a Kyverno ClusterPolicy YAML string.
func BuildClusterPolicy(p PolicyParams) (string, error) {
	var sb strings.Builder
	if err := cpTmpl.Execute(&sb, p); err != nil {
		return "", fmt.Errorf("rendering ClusterPolicy: %w", err)
	}
	return sb.String(), nil
}

// ValidationAction returns "Enforce" for error-severity violations, "Audit" otherwise.
func ValidationAction(violations []input.Violation) string {
	for _, v := range violations {
		if v.Severity == input.SeverityError {
			return "Enforce"
		}
	}
	return "Audit"
}
