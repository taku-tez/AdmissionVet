// Package registry manages user-defined custom policy rules.
// Custom rules are stored as YAML files in ~/.admissionvet/registry/
// and are loaded at startup alongside built-in generators.
package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	kyverno "github.com/AdmissionVet/admissionvet/internal/policy/kyverno"
)

// defaultRegistryDir is the directory where custom rule YAML files are stored.
func defaultRegistryDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".admissionvet", "registry")
}

// CustomRule defines the YAML format for a user-defined policy rule.
// Note: sigs.k8s.io/yaml converts to JSON internally, so json tags are used.
type CustomRule struct {
	// RuleID is the unique identifier (e.g. "CUSTOM001").
	RuleID string `json:"rule_id" yaml:"rule_id"`
	// Engine is "gatekeeper" or "kyverno".
	Engine string `json:"engine" yaml:"engine"`
	// Description is a human-readable description.
	Description string `json:"description" yaml:"description"`
	// MatchKinds lists the Kubernetes kinds this rule applies to.
	MatchKinds []string `json:"match_kinds" yaml:"match_kinds"`
	// Severity is the default enforcement severity.
	Severity string `json:"severity" yaml:"severity"`

	// For Gatekeeper: the full Rego policy text.
	Rego string `json:"rego,omitempty" yaml:"rego,omitempty"`
	// For Kyverno validate rules: the pattern block YAML.
	ValidateAction  string `json:"validate_action,omitempty" yaml:"validate_action,omitempty"`
	ValidateMessage string `json:"validate_message,omitempty" yaml:"validate_message,omitempty"`
	ValidatePattern string `json:"validate_pattern,omitempty" yaml:"validate_pattern,omitempty"`
	// For Kyverno mutate rules: the patchStrategicMerge block YAML.
	MutatePatch string `json:"mutate_patch,omitempty" yaml:"mutate_patch,omitempty"`
}

// LoadAll reads all custom rule YAML files from the registry directory.
func LoadAll(dir string) ([]CustomRule, error) {
	if dir == "" {
		dir = defaultRegistryDir()
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil // empty registry is fine
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading registry directory %s: %w", dir, err)
	}

	var rules []CustomRule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		var r CustomRule
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", e.Name(), err)
		}
		if r.RuleID == "" || r.Engine == "" {
			continue // skip invalid entries
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// RegisterAll loads all custom rules and registers them in the policy registry.
func RegisterAll(dir string) error {
	rules, err := LoadAll(dir)
	if err != nil {
		return err
	}
	for _, r := range rules {
		gen := newCustomGenerator(r)
		// Skip if already registered (built-in takes precedence).
		if _, exists := policy.Get(r.Engine, r.RuleID); exists {
			continue
		}
		policy.Register(r.Engine, gen)
	}
	return nil
}

// Add installs a custom rule file into the registry directory.
func Add(ruleFile, dir string) error {
	if dir == "" {
		dir = defaultRegistryDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating registry directory: %w", err)
	}

	data, err := os.ReadFile(ruleFile)
	if err != nil {
		return fmt.Errorf("reading rule file: %w", err)
	}

	var r CustomRule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("parsing rule file: %w", err)
	}
	if r.RuleID == "" {
		return fmt.Errorf("rule_id is required in the rule file")
	}
	if r.Engine == "" {
		return fmt.Errorf("engine is required in the rule file (gatekeeper|kyverno)")
	}

	dest := filepath.Join(dir, strings.ToLower(r.RuleID)+".yaml")
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("writing rule to registry: %w", err)
	}
	return nil
}

// Remove deletes a custom rule from the registry by rule ID.
func Remove(ruleID, dir string) error {
	if dir == "" {
		dir = defaultRegistryDir()
	}
	path := filepath.Join(dir, strings.ToLower(ruleID)+".yaml")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rule %s not found in registry", ruleID)
		}
		return err
	}
	return nil
}

// ── customGenerator implements policy.Generator for a CustomRule ─────────────

type customGenerator struct {
	rule CustomRule
}

func newCustomGenerator(r CustomRule) *customGenerator {
	return &customGenerator{rule: r}
}

func (g *customGenerator) RuleID() string { return g.rule.RuleID }

func (g *customGenerator) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	switch g.rule.Engine {
	case "gatekeeper":
		return g.generateGatekeeper(violations, namespace)
	case "kyverno":
		return g.generateKyverno(violations, namespace)
	default:
		return nil, fmt.Errorf("unsupported engine %q for custom rule %s", g.rule.Engine, g.rule.RuleID)
	}
}

func (g *customGenerator) generateGatekeeper(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	// Import the gatekeeper package locally to avoid circular deps.
	name := strings.ToLower(g.rule.RuleID)
	kind := strings.ToUpper(g.rule.RuleID[:1]) + strings.ToLower(g.rule.RuleID[1:])

	ctYAML := fmt.Sprintf(`apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: %s
  annotations:
    description: %s (custom rule)
spec:
  crd:
    spec:
      names:
        kind: %s
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
%s
`, name, g.rule.Description, kind, indentRego(g.rule.Rego, 8))

	enforcementAction := "warn"
	for _, v := range violations {
		if v.Severity == input.SeverityError {
			enforcementAction = "deny"
			break
		}
	}

	nsField := ""
	if namespace != "" {
		nsField = fmt.Sprintf("    namespaces:\n      - %s\n", namespace)
	}

	cYAML := fmt.Sprintf(`apiVersion: constraints.gatekeeper.sh/v1beta1
kind: %s
metadata:
  name: %s
spec:
  enforcementAction: %s
  match:
    kinds:
      - apiGroups: ["*"]
        kinds:
%s%s`, kind, name, enforcementAction, kindsYAML(g.rule.MatchKinds), nsField)

	return &policy.GeneratedPolicy{
		RuleID:             g.rule.RuleID,
		ConstraintTemplate: ctYAML,
		Constraint:         cYAML,
	}, nil
}

func (g *customGenerator) generateKyverno(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := "Audit"
	for _, v := range violations {
		if v.Severity == input.SeverityError {
			action = "Enforce"
			break
		}
	}

	name := strings.ToLower(strings.ReplaceAll(g.rule.RuleID, "_", "-"))

	var nss []string
	if namespace != "" {
		nss = []string{namespace}
	}

	var body string
	if g.rule.ValidatePattern != "" {
		body = fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "%s"
      pattern:
%s`, action, g.rule.ValidateMessage, indent(g.rule.ValidatePattern, 8))
	} else if g.rule.MutatePatch != "" {
		body = fmt.Sprintf(`    mutate:
      patchStrategicMerge:
%s`, indent(g.rule.MutatePatch, 8))
	} else {
		return nil, fmt.Errorf("custom kyverno rule %s must specify validate_pattern or mutate_patch", g.rule.RuleID)
	}

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        name + "-custom",
		Description: g.rule.Description + " (custom rule)",
		Rules: []kyverno.Rule{
			{
				Name:       "custom-" + name,
				MatchKinds: g.rule.MatchKinds,
				Namespaces: nss,
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.rule.RuleID, ClusterPolicy: cp}, nil
}

func indentRego(rego string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	var sb strings.Builder
	for _, line := range strings.Split(rego, "\n") {
		if line == "" {
			sb.WriteString("\n")
		} else {
			sb.WriteString(prefix + line + "\n")
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func indent(text string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		sb.WriteString(prefix + line + "\n")
	}
	return sb.String()
}

func kindsYAML(kinds []string) string {
	var sb strings.Builder
	for _, k := range kinds {
		sb.WriteString(fmt.Sprintf("          - %s\n", k))
	}
	return sb.String()
}
