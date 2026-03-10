package gatekeeper

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/AdmissionVet/admissionvet/internal/input"
)

// WorkloadKinds are the Kubernetes kinds that run workloads (have pod specs).
var WorkloadKinds = []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

// RBACKinds are the Kubernetes RBAC kinds.
var RBACKinds = []string{"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"}

// ConstraintTemplateParams holds the data for rendering a ConstraintTemplate.
type ConstraintTemplateParams struct {
	Name        string   // lowercase rule ID (e.g. "mv1001")
	Kind        string   // PascalCase kind (e.g. "Mv1001")
	Description string
	Rego        string
	MatchKinds  []string
	APIGroups   string
}

const constraintTemplateTmpl = `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: {{ .Name }}
  annotations:
    description: {{ .Description }}
spec:
  crd:
    spec:
      names:
        kind: {{ .Kind }}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
{{ indentRego .Rego 8 }}
`

const constraintTmpl = `apiVersion: constraints.gatekeeper.sh/v1beta1
kind: {{ .Kind }}
metadata:
  name: {{ .Name }}
spec:
  enforcementAction: {{ .EnforcementAction }}
  match:
    kinds:
      - apiGroups: ["{{ .APIGroups }}"]
        kinds:
{{ matchKinds .MatchKinds }}
{{ if .Namespaces }}    namespaces:
{{ namespacesYAML .Namespaces }}{{ end }}
`

// ConstraintParams holds data for rendering a Constraint instance.
type ConstraintParams struct {
	Kind              string
	Name              string
	EnforcementAction string // "deny" or "warn"
	APIGroups         string
	MatchKinds        []string
	Namespaces        []string
}

var funcMap = template.FuncMap{
	"indentRego": func(rego string, spaces int) string {
		indent := strings.Repeat(" ", spaces)
		lines := strings.Split(rego, "\n")
		var sb strings.Builder
		for i, line := range lines {
			if i == len(lines)-1 && line == "" {
				break
			}
			if line == "" {
				sb.WriteString("\n")
			} else {
				sb.WriteString(indent + line + "\n")
			}
		}
		return strings.TrimRight(sb.String(), "\n")
	},
	"matchKinds": func(kinds []string) string {
		var sb strings.Builder
		for _, k := range kinds {
			sb.WriteString(fmt.Sprintf("          - %s\n", k))
		}
		return strings.TrimRight(sb.String(), "\n")
	},
	"namespacesYAML": func(nss []string) string {
		var sb strings.Builder
		for _, ns := range nss {
			sb.WriteString(fmt.Sprintf("      - %s\n", ns))
		}
		return sb.String()
	},
}

var ctTmpl = template.Must(template.New("ct").Funcs(funcMap).Parse(constraintTemplateTmpl))
var cTmpl = template.Must(template.New("c").Funcs(funcMap).Parse(constraintTmpl))

// BuildConstraintTemplate renders a ConstraintTemplate YAML string.
func BuildConstraintTemplate(p ConstraintTemplateParams) (string, error) {
	var sb strings.Builder
	if err := ctTmpl.Execute(&sb, p); err != nil {
		return "", fmt.Errorf("rendering ConstraintTemplate: %w", err)
	}
	return sb.String(), nil
}

// BuildConstraint renders a Constraint instance YAML string.
func BuildConstraint(p ConstraintParams) (string, error) {
	var sb strings.Builder
	if err := cTmpl.Execute(&sb, p); err != nil {
		return "", fmt.Errorf("rendering Constraint: %w", err)
	}
	return strings.TrimRight(sb.String(), "\n") + "\n", nil
}

// RuleIDToKind converts a rule ID like "MV1001" to PascalCase "Mv1001".
func RuleIDToKind(ruleID string) string {
	if len(ruleID) == 0 {
		return ruleID
	}
	return strings.ToUpper(ruleID[:1]) + strings.ToLower(ruleID[1:])
}

// EnforcementAction returns "deny" for error-severity violations, "warn" otherwise.
func EnforcementAction(violations []input.Violation) string {
	for _, v := range violations {
		if v.Severity == input.SeverityError {
			return "deny"
		}
	}
	return "warn"
}
