package audit

import (
	"fmt"
	"strings"
)

// resourceObject is a minimal parsed Kubernetes resource.
type resourceObject struct {
	Kind     string         `yaml:"kind"`
	Metadata map[string]any `yaml:"metadata"`
	Spec     map[string]any `yaml:"spec"`
	// RBAC resources: rules/roleRef/subjects are top-level fields (not under spec).
	Rules    []any          `yaml:"rules"`
	RoleRef  map[string]any `yaml:"roleRef"`
	Subjects []any          `yaml:"subjects"`
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

// checkFunc returns (ruleID, severity, message) or empty strings if no violation.
type checkFunc func(obj resourceObject) (ruleID string, severity Severity, message string)

// workloadChecks are run against Pods, Deployments, StatefulSets, DaemonSets, etc.
var workloadChecks = []checkFunc{
	checkPrivileged,
	checkHostNamespaces,
	checkHostPath,
	checkReadOnlyRootFS,
	checkSecretEnvVars,
	checkRunAsRoot,
	checkDangerousCapabilities,
	checkAllowPrivilegeEscalation,
}

// rbacChecks are run against ClusterRoles and Roles.
var rbacChecks = []checkFunc{
	checkWildcardVerb,
	checkWildcardResource,
}

// clusterRoleBindingChecks are run against ClusterRoleBindings.
var clusterRoleBindingChecks = []checkFunc{
	checkClusterAdmin,
}

// ── Check implementations ────────────────────────────────────────────────────

func checkPrivileged(obj resourceObject) (string, Severity, string) {
	for _, c := range extractContainers(obj) {
		if sc, ok := c["securityContext"].(map[string]any); ok {
			if priv, ok := sc["privileged"].(bool); ok && priv {
				name, _ := c["name"].(string)
				return "MV1001", SeverityError,
					fmt.Sprintf("container '%s' is running as privileged", name)
			}
		}
	}
	return "", "", ""
}

func checkHostNamespaces(obj resourceObject) (string, Severity, string) {
	spec := getPodSpec(obj)
	if spec == nil {
		return "", "", ""
	}
	if v, ok := spec["hostPID"].(bool); ok && v {
		return "MV1002", SeverityError, "uses hostPID: true"
	}
	if v, ok := spec["hostIPC"].(bool); ok && v {
		return "MV1002", SeverityError, "uses hostIPC: true"
	}
	if v, ok := spec["hostNetwork"].(bool); ok && v {
		return "MV1002", SeverityError, "uses hostNetwork: true"
	}
	return "", "", ""
}

func checkHostPath(obj resourceObject) (string, Severity, string) {
	spec := getPodSpec(obj)
	if spec == nil {
		return "", "", ""
	}
	volumes, _ := spec["volumes"].([]any)
	for _, vol := range volumes {
		v, ok := vol.(map[string]any)
		if !ok {
			continue
		}
		if _, hasHP := v["hostPath"]; hasHP {
			volName, _ := v["name"].(string)
			return "MV1003", SeverityError,
				fmt.Sprintf("volume '%s' uses hostPath", volName)
		}
	}
	return "", "", ""
}

func checkReadOnlyRootFS(obj resourceObject) (string, Severity, string) {
	for _, c := range extractContainers(obj) {
		sc, _ := c["securityContext"].(map[string]any)
		if sc == nil {
			name, _ := c["name"].(string)
			return "MV1007", SeverityWarning,
				fmt.Sprintf("container '%s' missing readOnlyRootFilesystem", name)
		}
		if rofs, ok := sc["readOnlyRootFilesystem"].(bool); !ok || !rofs {
			name, _ := c["name"].(string)
			return "MV1007", SeverityWarning,
				fmt.Sprintf("container '%s' readOnlyRootFilesystem is not true", name)
		}
	}
	return "", "", ""
}

// secretPatterns lists name fragments that suggest an env var holds a secret.
var secretPatterns = []string{
	"PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "PASSWD", "PRIVATE", "API_KEY", "AUTH",
}

func checkSecretEnvVars(obj resourceObject) (string, Severity, string) {
	for _, c := range extractContainers(obj) {
		envs, _ := c["env"].([]any)
		for _, e := range envs {
			env, ok := e.(map[string]any)
			if !ok {
				continue
			}
			name, _ := env["name"].(string)
			value, hasValue := env["value"].(string)
			if !hasValue || value == "" {
				continue
			}
			upper := strings.ToUpper(name)
			for _, pattern := range secretPatterns {
				if strings.Contains(upper, pattern) {
					cname, _ := c["name"].(string)
					return "MV2001", SeverityError,
						fmt.Sprintf("container '%s' env var '%s' has a literal value that looks like a secret", cname, name)
				}
			}
		}
	}
	return "", "", ""
}

func checkWildcardVerb(obj resourceObject) (string, Severity, string) {
	// rules is a top-level field in ClusterRole/Role, not under spec.
	for _, r := range obj.Rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		verbs, _ := rule["verbs"].([]any)
		for _, v := range verbs {
			if s, ok := v.(string); ok && s == "*" {
				return "RB1001", SeverityError,
					fmt.Sprintf("%s '%s' uses wildcard verb '*'", obj.Kind, obj.name())
			}
		}
	}
	return "", "", ""
}

func checkWildcardResource(obj resourceObject) (string, Severity, string) {
	// rules is a top-level field in ClusterRole/Role, not under spec.
	for _, r := range obj.Rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		resources, _ := rule["resources"].([]any)
		for _, res := range resources {
			if s, ok := res.(string); ok && s == "*" {
				return "RB1002", SeverityError,
					fmt.Sprintf("%s '%s' uses wildcard resource '*'", obj.Kind, obj.name())
			}
		}
	}
	return "", "", ""
}

func checkClusterAdmin(obj resourceObject) (string, Severity, string) {
	// roleRef and subjects are top-level fields in ClusterRoleBinding/RoleBinding, not under spec.
	roleRef := obj.RoleRef
	refName, _ := roleRef["name"].(string)
	if refName != "cluster-admin" {
		return "", "", ""
	}
	for _, s := range obj.Subjects {
		subj, ok := s.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := subj["kind"].(string)
		name, _ := subj["name"].(string)
		if kind == "Group" && name == "system:masters" {
			continue
		}
		return "RB1003", SeverityError,
			fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin to %s '%s'", obj.name(), kind, name)
	}
	return "", "", ""
}

// ── MV1004: root ユーザー実行禁止 ────────────────────────────────────────────

func checkRunAsRoot(obj resourceObject) (string, Severity, string) {
	// Check pod-level securityContext first.
	podSpec := getPodSpec(obj)
	if podSpec != nil {
		if podSC, ok := podSpec["securityContext"].(map[string]any); ok {
			if uid, ok := podSC["runAsUser"].(float64); ok && uid == 0 {
				return "MV1004", SeverityError,
					fmt.Sprintf("%s '%s' sets pod-level runAsUser: 0 (root)", obj.Kind, obj.name())
			}
			if nonRoot, ok := podSC["runAsNonRoot"].(bool); ok && !nonRoot {
				return "MV1004", SeverityError,
					fmt.Sprintf("%s '%s' sets pod-level runAsNonRoot: false", obj.Kind, obj.name())
			}
		}
	}
	// Check container-level securityContext.
	for _, c := range extractContainers(obj) {
		sc, _ := c["securityContext"].(map[string]any)
		if sc == nil {
			continue
		}
		if uid, ok := sc["runAsUser"].(float64); ok && uid == 0 {
			name, _ := c["name"].(string)
			return "MV1004", SeverityError,
				fmt.Sprintf("container '%s' sets runAsUser: 0 (root)", name)
		}
		if nonRoot, ok := sc["runAsNonRoot"].(bool); ok && !nonRoot {
			name, _ := c["name"].(string)
			return "MV1004", SeverityError,
				fmt.Sprintf("container '%s' sets runAsNonRoot: false", name)
		}
	}
	return "", "", ""
}

// ── MV1005: 危険 Linux Capability 禁止 ───────────────────────────────────────

// dangerousCapabilities is the block-list of Linux capabilities that pose
// significant security risk when added to containers.
var dangerousCapabilities = map[string]bool{
	"ALL":           true,
	"NET_ADMIN":     true,
	"SYS_ADMIN":     true,
	"SYS_PTRACE":    true,
	"SYS_MODULE":    true,
	"SYS_RAWIO":     true,
	"SYS_BOOT":      true,
	"NET_RAW":       true,
	"IPC_LOCK":      true,
	"AUDIT_WRITE":   true,
	"AUDIT_CONTROL": true,
	"MAC_ADMIN":     true,
	"MAC_OVERRIDE":  true,
	"SETUID":        true,
	"SETGID":        true,
}

func checkDangerousCapabilities(obj resourceObject) (string, Severity, string) {
	for _, c := range extractContainers(obj) {
		sc, _ := c["securityContext"].(map[string]any)
		if sc == nil {
			continue
		}
		caps, _ := sc["capabilities"].(map[string]any)
		if caps == nil {
			continue
		}
		add, _ := caps["add"].([]any)
		for _, cap := range add {
			capStr, ok := cap.(string)
			if !ok {
				continue
			}
			if dangerousCapabilities[strings.ToUpper(capStr)] {
				name, _ := c["name"].(string)
				return "MV1005", SeverityError,
					fmt.Sprintf("container '%s' adds dangerous capability '%s'", name, capStr)
			}
		}
	}
	return "", "", ""
}

// ── MV1006: allowPrivilegeEscalation を false に強制 ─────────────────────────

func checkAllowPrivilegeEscalation(obj resourceObject) (string, Severity, string) {
	for _, c := range extractContainers(obj) {
		sc, _ := c["securityContext"].(map[string]any)
		if sc == nil {
			name, _ := c["name"].(string)
			return "MV1006", SeverityWarning,
				fmt.Sprintf("container '%s' missing allowPrivilegeEscalation: false", name)
		}
		ape, ok := sc["allowPrivilegeEscalation"].(bool)
		if !ok {
			name, _ := c["name"].(string)
			return "MV1006", SeverityWarning,
				fmt.Sprintf("container '%s' missing allowPrivilegeEscalation: false", name)
		}
		if ape {
			name, _ := c["name"].(string)
			return "MV1006", SeverityError,
				fmt.Sprintf("container '%s' sets allowPrivilegeEscalation: true", name)
		}
	}
	return "", "", ""
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func getPodSpec(obj resourceObject) map[string]any {
	if obj.Kind == "Pod" {
		return obj.Spec
	}
	if tmpl, ok := obj.Spec["template"].(map[string]any); ok {
		if spec, ok := tmpl["spec"].(map[string]any); ok {
			return spec
		}
	}
	return nil
}

func extractContainers(obj resourceObject) []map[string]any {
	spec := getPodSpec(obj)
	if spec == nil {
		return nil
	}
	var result []map[string]any
	for _, key := range []string{"containers", "initContainers"} {
		cs, _ := spec[key].([]any)
		for _, c := range cs {
			if m, ok := c.(map[string]any); ok {
				result = append(result, m)
			}
		}
	}
	return result
}
