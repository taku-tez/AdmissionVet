// Package dryrun simulates policy enforcement against existing manifests without
// applying anything to the cluster.
package dryrun

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// ResourceSummary describes a single workload resource.
type ResourceSummary struct {
	Kind      string
	Name      string
	Namespace string
}

// PolicyHit records a policy that would block or warn about a resource.
type PolicyHit struct {
	Resource ResourceSummary
	Policy   string // policy name (e.g. "mv1001-no-privileged")
	Action   string // "block" or "warn"
	Message  string
}

// SimulationResult is the full output of a dry-run simulation.
type SimulationResult struct {
	TotalResources int
	TotalPolicies  int
	Hits           []PolicyHit
}

// Summary returns a grouped summary by namespace.
func (r *SimulationResult) Summary() map[string][]PolicyHit {
	m := make(map[string][]PolicyHit)
	for _, h := range r.Hits {
		ns := h.Resource.Namespace
		if ns == "" {
			ns = "default"
		}
		m[ns] = append(m[ns], h)
	}
	return m
}

// BlockCount returns the number of resources that would be blocked.
func (r *SimulationResult) BlockCount() int {
	seen := make(map[string]bool)
	for _, h := range r.Hits {
		if h.Action == "block" {
			key := fmt.Sprintf("%s/%s/%s", h.Resource.Namespace, h.Resource.Kind, h.Resource.Name)
			seen[key] = true
		}
	}
	return len(seen)
}

// RunFromFiles runs a dry-run simulation of policies against manifest files.
// policyPaths: YAML files containing Gatekeeper ConstraintTemplates/Constraints or Kyverno ClusterPolicies.
// manifestPaths: YAML files containing workload resources.
func RunFromFiles(manifestPaths, policyPaths []string) (*SimulationResult, error) {
	// Parse policies.
	var policyNames []string
	var policyRules []policyRule
	for _, path := range policyPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading policy %s: %w", path, err)
		}
		rules, names, err := parsePolicies(data)
		if err != nil {
			return nil, fmt.Errorf("parsing policy %s: %w", path, err)
		}
		policyNames = append(policyNames, names...)
		policyRules = append(policyRules, rules...)
	}

	// Parse manifests.
	var resources []resourceObject
	for _, path := range manifestPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading manifest %s: %w", path, err)
		}
		objs, err := parseResources(data)
		if err != nil {
			return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
		}
		resources = append(resources, objs...)
	}

	result := &SimulationResult{
		TotalResources: len(resources),
		TotalPolicies:  len(policyNames),
	}

	// Evaluate each resource against each policy rule.
	for _, res := range resources {
		for _, rule := range policyRules {
			if !rule.matches(res) {
				continue
			}
			hit, ok := rule.evaluate(res)
			if ok {
				result.Hits = append(result.Hits, hit)
			}
		}
	}

	return result, nil
}

// ── Internal types for policy parsing ───────────────────────────────────────

type policyRule struct {
	PolicyName  string
	RuleName    string
	Action      string // "block" or "warn"
	Checks      []checkFunc
	MatchKinds  []string
}

type checkFunc func(obj resourceObject) (bool, string)

type resourceObject struct {
	Kind      string                 `yaml:"kind"`
	Metadata  map[string]interface{} `yaml:"metadata"`
	Spec      map[string]interface{} `yaml:"spec"`
}

func (r resourceObject) name() string {
	if n, ok := r.Metadata["name"].(string); ok {
		return n
	}
	return ""
}

func (r resourceObject) namespace() string {
	if n, ok := r.Metadata["namespace"].(string); ok {
		return n
	}
	return ""
}

func (rule *policyRule) matches(obj resourceObject) bool {
	if len(rule.MatchKinds) == 0 {
		return true
	}
	for _, k := range rule.MatchKinds {
		if strings.EqualFold(k, obj.Kind) {
			return true
		}
	}
	return false
}

func (rule *policyRule) evaluate(obj resourceObject) (PolicyHit, bool) {
	for _, check := range rule.Checks {
		violated, msg := check(obj)
		if violated {
			return PolicyHit{
				Resource: ResourceSummary{
					Kind:      obj.Kind,
					Name:      obj.name(),
					Namespace: obj.namespace(),
				},
				Policy:  rule.PolicyName,
				Action:  rule.Action,
				Message: msg,
			}, true
		}
	}
	return PolicyHit{}, false
}

// parsePolicies extracts policy rules from YAML documents.
// Supports Gatekeeper Constraint and Kyverno ClusterPolicy.
func parsePolicies(data []byte) ([]policyRule, []string, error) {
	var rules []policyRule
	var names []string

	docs := bytes.Split(data, []byte("\n---"))
	for _, raw := range docs {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}

		var obj struct {
			Kind     string                 `yaml:"kind"`
			Metadata map[string]interface{} `yaml:"metadata"`
			Spec     map[string]interface{} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(raw, &obj); err != nil {
			continue
		}

		name := ""
		if n, ok := obj.Metadata["name"].(string); ok {
			name = n
		}

		switch obj.Kind {
		case "ClusterPolicy", "Policy":
			// Kyverno — extract validate rules and map to built-in checks.
			r := kyvernoRulesFromSpec(name, obj.Spec)
			rules = append(rules, r...)
			if len(r) > 0 {
				names = append(names, name)
			}

		default:
			// Gatekeeper Constraint — identify by CRD kind matching our rule IDs.
			if r, ok := gatekeeperRuleFromKind(name, obj.Kind, obj.Spec); ok {
				rules = append(rules, r)
				names = append(names, name)
			}
		}
	}

	return rules, names, nil
}

// kyvernoRulesFromSpec maps known Kyverno ClusterPolicy names to built-in checks.
func kyvernoRulesFromSpec(policyName string, spec map[string]interface{}) []policyRule {
	return mapPolicyNameToRules(policyName, "block")
}

// gatekeeperRuleFromKind maps Gatekeeper Constraint kinds to built-in checks.
func gatekeeperRuleFromKind(name, kind string, spec map[string]interface{}) (policyRule, bool) {
	action := "block"
	if ea, ok := nestedString(spec, "enforcementAction"); ok && ea == "warn" {
		action = "warn"
	}
	rules := mapPolicyNameToRules(name, action)
	if len(rules) == 0 {
		return policyRule{}, false
	}
	return rules[0], true
}

// mapPolicyNameToRules maps known policy/constraint names to built-in check functions.
func mapPolicyNameToRules(name, action string) []policyRule {
	workloadKinds := []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

	type entry struct {
		nameFragment string
		checks       []checkFunc
	}

	entries := []entry{
		{
			nameFragment: "mv1001",
			checks: []checkFunc{func(obj resourceObject) (bool, string) {
				return checkPrivileged(obj)
			}},
		},
		{
			nameFragment: "mv1002",
			checks: []checkFunc{func(obj resourceObject) (bool, string) {
				return checkHostNamespaces(obj)
			}},
		},
		{
			nameFragment: "mv1003",
			checks: []checkFunc{func(obj resourceObject) (bool, string) {
				return checkHostPath(obj)
			}},
		},
		{
			nameFragment: "mv1007",
			checks: []checkFunc{func(obj resourceObject) (bool, string) {
				return checkReadOnlyRootFS(obj)
			}},
		},
		{
			nameFragment: "rb1001",
			checks: []checkFunc{func(obj resourceObject) (bool, string) {
				return checkWildcardVerb(obj)
			}},
		},
		{
			nameFragment: "rb1002",
			checks: []checkFunc{func(obj resourceObject) (bool, string) {
				return checkWildcardResource(obj)
			}},
		},
	}

	lower := strings.ToLower(name)
	for _, e := range entries {
		if strings.Contains(lower, e.nameFragment) {
			return []policyRule{{
				PolicyName: name,
				Action:     action,
				Checks:     e.checks,
				MatchKinds: workloadKinds,
			}}
		}
	}
	return nil
}

// ── Check functions ──────────────────────────────────────────────────────────

func checkPrivileged(obj resourceObject) (bool, string) {
	containers := extractContainers(obj)
	for _, c := range containers {
		if sc, ok := c["securityContext"].(map[string]interface{}); ok {
			if priv, ok := sc["privileged"].(bool); ok && priv {
				name, _ := c["name"].(string)
				return true, fmt.Sprintf("container '%s' is privileged", name)
			}
		}
	}
	return false, ""
}

func checkHostNamespaces(obj resourceObject) (bool, string) {
	spec := getPodSpec(obj)
	if hostPID, ok := spec["hostPID"].(bool); ok && hostPID {
		return true, "uses hostPID: true"
	}
	if hostIPC, ok := spec["hostIPC"].(bool); ok && hostIPC {
		return true, "uses hostIPC: true"
	}
	if hostNet, ok := spec["hostNetwork"].(bool); ok && hostNet {
		return true, "uses hostNetwork: true"
	}
	return false, ""
}

func checkHostPath(obj resourceObject) (bool, string) {
	spec := getPodSpec(obj)
	volumes, _ := spec["volumes"].([]interface{})
	for _, vol := range volumes {
		v, ok := vol.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasHP := v["hostPath"]; hasHP {
			name, _ := v["name"].(string)
			return true, fmt.Sprintf("volume '%s' uses hostPath", name)
		}
	}
	return false, ""
}

func checkReadOnlyRootFS(obj resourceObject) (bool, string) {
	for _, c := range extractContainers(obj) {
		sc, _ := c["securityContext"].(map[string]interface{})
		if sc == nil {
			name, _ := c["name"].(string)
			return true, fmt.Sprintf("container '%s' missing readOnlyRootFilesystem", name)
		}
		if rofs, ok := sc["readOnlyRootFilesystem"].(bool); !ok || !rofs {
			name, _ := c["name"].(string)
			return true, fmt.Sprintf("container '%s' readOnlyRootFilesystem is not true", name)
		}
	}
	return false, ""
}

func checkWildcardVerb(obj resourceObject) (bool, string) {
	if obj.Kind != "ClusterRole" && obj.Kind != "Role" {
		return false, ""
	}
	rules, _ := obj.Spec["rules"].([]interface{})
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		verbs, _ := rule["verbs"].([]interface{})
		for _, v := range verbs {
			if s, ok := v.(string); ok && s == "*" {
				return true, "uses wildcard verb '*'"
			}
		}
	}
	return false, ""
}

func checkWildcardResource(obj resourceObject) (bool, string) {
	if obj.Kind != "ClusterRole" && obj.Kind != "Role" {
		return false, ""
	}
	rules, _ := obj.Spec["rules"].([]interface{})
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		resources, _ := rule["resources"].([]interface{})
		for _, res := range resources {
			if s, ok := res.(string); ok && s == "*" {
				return true, "uses wildcard resource '*'"
			}
		}
	}
	return false, ""
}

func getPodSpec(obj resourceObject) map[string]interface{} {
	if obj.Kind == "Pod" {
		return obj.Spec
	}
	if tmpl, ok := obj.Spec["template"].(map[string]interface{}); ok {
		if spec, ok := tmpl["spec"].(map[string]interface{}); ok {
			return spec
		}
	}
	return nil
}

func extractContainers(obj resourceObject) []map[string]interface{} {
	spec := getPodSpec(obj)
	var result []map[string]interface{}
	for _, key := range []string{"containers", "initContainers"} {
		cs, _ := spec[key].([]interface{})
		for _, c := range cs {
			if m, ok := c.(map[string]interface{}); ok {
				result = append(result, m)
			}
		}
	}
	return result
}

func parseResources(data []byte) ([]resourceObject, error) {
	var resources []resourceObject
	docs := bytes.Split(data, []byte("\n---"))
	for _, raw := range docs {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var obj resourceObject
		if err := yaml.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if obj.Kind != "" {
			resources = append(resources, obj)
		}
	}
	return resources, nil
}

func nestedString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
