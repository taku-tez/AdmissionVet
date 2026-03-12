package audit

import (
	"bytes"
	"fmt"

	"sigs.k8s.io/yaml"
)

// Run fetches live cluster resources and checks them against known security rules.
func Run(opts Options) (*Result, error) {
	result := &Result{}
	var allFindings []Finding

	// ── Workload checks (MV1001–MV2001) ─────────────────────────────────────
	workloadKinds := "pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs"
	workloadYAML, err := kubectlGet(opts, workloadKinds, false)
	if err != nil {
		return nil, fmt.Errorf("fetching workloads: %w", err)
	}
	workloads, err := parseList(workloadYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing workloads: %w", err)
	}
	result.TotalResources += len(workloads)
	for _, obj := range workloads {
		for _, check := range workloadChecks {
			if ruleID, severity, msg := check(obj); ruleID != "" {
				allFindings = append(allFindings, Finding{
					Namespace: obj.namespace(),
					Kind:      obj.Kind,
					Name:      obj.name(),
					RuleID:    ruleID,
					Severity:  severity,
					Message:   msg,
				})
			}
		}
	}

	// ── RBAC checks (RB1001–RB1002: roles) ──────────────────────────────────
	rbacYAML, err := kubectlGet(opts, "clusterroles,roles", true)
	if err != nil {
		return nil, fmt.Errorf("fetching RBAC roles: %w", err)
	}
	roles, err := parseList(rbacYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing RBAC roles: %w", err)
	}
	result.TotalResources += len(roles)
	for _, obj := range roles {
		for _, check := range rbacChecks {
			if ruleID, severity, msg := check(obj); ruleID != "" {
				allFindings = append(allFindings, Finding{
					Namespace: obj.namespace(),
					Kind:      obj.Kind,
					Name:      obj.name(),
					RuleID:    ruleID,
					Severity:  severity,
					Message:   msg,
				})
			}
		}
	}

	// ── RB1003: ClusterRoleBindings ──────────────────────────────────────────
	crbYAML, err := kubectlGet(opts, "clusterrolebindings", true)
	if err != nil {
		return nil, fmt.Errorf("fetching ClusterRoleBindings: %w", err)
	}
	crbs, err := parseList(crbYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing ClusterRoleBindings: %w", err)
	}
	result.TotalResources += len(crbs)
	for _, obj := range crbs {
		for _, check := range clusterRoleBindingChecks {
			if ruleID, severity, msg := check(obj); ruleID != "" {
				allFindings = append(allFindings, Finding{
					Namespace: obj.namespace(),
					Kind:      obj.Kind,
					Name:      obj.name(),
					RuleID:    ruleID,
					Severity:  severity,
					Message:   msg,
				})
			}
		}
	}

	// ── NV1001: namespaces missing default-deny NetworkPolicy ────────────────
	nvFindings, nsCount, err := checkNetworkPolicies(opts)
	if err != nil {
		return nil, fmt.Errorf("fetching NetworkPolicies: %w", err)
	}
	result.TotalResources += nsCount
	allFindings = append(allFindings, nvFindings...)

	result.Findings = allFindings
	return result, nil
}

// checkNetworkPolicies returns NV1001 findings for namespaces missing
// a default-deny-all NetworkPolicy.
func checkNetworkPolicies(opts Options) ([]Finding, int, error) {
	// Fetch all namespaces.
	nsYAML, err := kubectlGet(opts, "namespaces", true)
	if err != nil {
		return nil, 0, err
	}
	namespaces, err := parseList(nsYAML)
	if err != nil {
		return nil, 0, err
	}

	// Fetch all NetworkPolicies.
	npYAML, err := kubectlGet(opts, "networkpolicies", true)
	if err != nil {
		return nil, 0, err
	}
	nps, err := parseList(npYAML)
	if err != nil {
		return nil, 0, err
	}

	// Index namespaces that have a default-deny policy.
	// A default-deny policy selects all pods (empty podSelector) and allows no traffic.
	defaultDeny := make(map[string]bool)
	for _, np := range nps {
		spec := np.Spec
		ps, _ := spec["podSelector"].(map[string]any)
		if len(ps) != 0 {
			// Scoped to specific pods only — not a namespace-wide default-deny.
			continue
		}

		// Check ingress: either absent, or an explicit empty slice ([]interface{}{}).
		ingressVal, hasIngress := spec["ingress"]
		ingressDenied := !hasIngress || isEmptySlice(ingressVal)

		// Check egress: either absent, or an explicit empty slice.
		egressVal, hasEgress := spec["egress"]
		egressDenied := !hasEgress || isEmptySlice(egressVal)

		if ingressDenied && egressDenied {
			defaultDeny[np.namespace()] = true
		}
	}

	// Skip system namespaces.
	systemNamespaces := map[string]bool{
		"kube-system":          true,
		"kube-public":          true,
		"kube-node-lease":      true,
		"local-path-storage":   true,
	}

	var findings []Finding
	for _, ns := range namespaces {
		name := ns.name()
		if systemNamespaces[name] {
			continue
		}
		if !defaultDeny[name] {
			findings = append(findings, Finding{
				Namespace: name,
				Kind:      "Namespace",
				Name:      name,
				RuleID:    "NV1001",
				Severity:  SeverityError,
				Message:   fmt.Sprintf("namespace '%s' has no default-deny NetworkPolicy", name),
			})
		}
	}

	return findings, len(namespaces), nil
}

// isEmptySlice returns true if v is a nil or zero-length slice.
func isEmptySlice(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.([]any)
	return ok && len(s) == 0
}

// parseList parses a kubectl YAML List response into individual resource objects.
func parseList(data []byte) ([]resourceObject, error) {
	// kubectl returns a List or individual items.
	var list struct {
		Kind  string           `yaml:"kind"`
		Items []resourceObject `yaml:"items"`
	}

	// Try parsing as a List first.
	if err := yaml.Unmarshal(data, &list); err == nil && list.Kind == "List" || list.Kind != "" {
		if len(list.Items) > 0 {
			return list.Items, nil
		}
	}

	// Fall back to parsing multiple YAML documents.
	// Normalize: strip a leading "---\n" so files starting with a separator
	// don't lose their first document.
	var objects []resourceObject
	data = bytes.TrimPrefix(data, []byte("---\n"))
	for _, raw := range bytes.Split(data, []byte("\n---")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var obj resourceObject
		if err := yaml.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if obj.Kind != "" && obj.Kind != "List" {
			objects = append(objects, obj)
		}
	}
	return objects, nil
}
