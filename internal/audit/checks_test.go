package audit

import (
	"testing"
)

// helpers to build test resourceObjects
func podWith(spec map[string]any) resourceObject {
	return resourceObject{
		Kind:     "Pod",
		Metadata: map[string]any{"name": "test-pod", "namespace": "default"},
		Spec:     spec,
	}
}

func deploymentWith(spec map[string]any) resourceObject {
	return resourceObject{
		Kind:     "Deployment",
		Metadata: map[string]any{"name": "test-deploy", "namespace": "default"},
		Spec:     spec,
	}
}

func clusterRoleWith(rules []any) resourceObject {
	return resourceObject{
		Kind:     "ClusterRole",
		Metadata: map[string]any{"name": "test-role"},
		Rules:    rules,
	}
}

// ── checkPrivileged ──────────────────────────────────────────────────────────

func TestCheckPrivileged_Detects(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"privileged": true},
			},
		},
	})
	ruleID, severity, msg := checkPrivileged(obj)
	if ruleID != "MV1001" {
		t.Errorf("want MV1001, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

func TestCheckPrivileged_Clean(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"privileged": false},
			},
		},
	})
	ruleID, _, _ := checkPrivileged(obj)
	if ruleID != "" {
		t.Errorf("expected no violation, got %s", ruleID)
	}
}

// ── checkHostNamespaces ──────────────────────────────────────────────────────

func TestCheckHostNamespaces_HostPID(t *testing.T) {
	obj := podWith(map[string]any{"hostPID": true})
	ruleID, _, _ := checkHostNamespaces(obj)
	if ruleID != "MV1002" {
		t.Errorf("want MV1002, got %s", ruleID)
	}
}

func TestCheckHostNamespaces_HostNetwork(t *testing.T) {
	obj := podWith(map[string]any{"hostNetwork": true})
	ruleID, _, _ := checkHostNamespaces(obj)
	if ruleID != "MV1002" {
		t.Errorf("want MV1002, got %s", ruleID)
	}
}

func TestCheckHostNamespaces_Clean(t *testing.T) {
	obj := podWith(map[string]any{})
	ruleID, _, _ := checkHostNamespaces(obj)
	if ruleID != "" {
		t.Errorf("expected no violation, got %s", ruleID)
	}
}

// ── checkHostPath ────────────────────────────────────────────────────────────

func TestCheckHostPath_Detects(t *testing.T) {
	obj := podWith(map[string]any{
		"volumes": []any{
			map[string]any{"name": "logs", "hostPath": map[string]any{"path": "/var/log"}},
		},
		"containers": []any{},
	})
	ruleID, severity, _ := checkHostPath(obj)
	if ruleID != "MV1003" {
		t.Errorf("want MV1003, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
}

func TestCheckHostPath_Clean(t *testing.T) {
	obj := podWith(map[string]any{
		"volumes": []any{
			map[string]any{"name": "data", "emptyDir": map[string]any{}},
		},
	})
	ruleID, _, _ := checkHostPath(obj)
	if ruleID != "" {
		t.Errorf("expected no violation, got %s", ruleID)
	}
}

// ── checkReadOnlyRootFS ──────────────────────────────────────────────────────

func TestCheckReadOnlyRootFS_Missing(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{"name": "app"}, // no securityContext
		},
	})
	ruleID, severity, _ := checkReadOnlyRootFS(obj)
	if ruleID != "MV1007" {
		t.Errorf("want MV1007, got %s", ruleID)
	}
	if severity != SeverityWarning {
		t.Errorf("want warning, got %s", severity)
	}
}

func TestCheckReadOnlyRootFS_False(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"readOnlyRootFilesystem": false},
			},
		},
	})
	ruleID, _, _ := checkReadOnlyRootFS(obj)
	if ruleID != "MV1007" {
		t.Errorf("want MV1007, got %s", ruleID)
	}
}

func TestCheckReadOnlyRootFS_True(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"readOnlyRootFilesystem": true},
			},
		},
	})
	ruleID, _, _ := checkReadOnlyRootFS(obj)
	if ruleID != "" {
		t.Errorf("expected no violation, got %s", ruleID)
	}
}

// ── checkSecretEnvVars ───────────────────────────────────────────────────────

func TestCheckSecretEnvVars_Detects(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"env": []any{
					map[string]any{"name": "DB_PASSWORD", "value": "secret123"},
				},
			},
		},
	})
	ruleID, severity, _ := checkSecretEnvVars(obj)
	if ruleID != "MV2001" {
		t.Errorf("want MV2001, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
}

func TestCheckSecretEnvVars_SecretRef_NoViolation(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"env": []any{
					map[string]any{
						"name": "DB_PASSWORD",
						"valueFrom": map[string]any{
							"secretKeyRef": map[string]any{"name": "db-secret", "key": "password"},
						},
					},
				},
			},
		},
	})
	ruleID, _, _ := checkSecretEnvVars(obj)
	if ruleID != "" {
		t.Errorf("expected no violation for secretKeyRef, got %s", ruleID)
	}
}

// ── checkWildcardVerb ────────────────────────────────────────────────────────

func TestCheckWildcardVerb_Detects(t *testing.T) {
	obj := clusterRoleWith([]any{
		map[string]any{"verbs": []any{"*"}, "resources": []any{"pods"}},
	})
	ruleID, severity, _ := checkWildcardVerb(obj)
	if ruleID != "RB1001" {
		t.Errorf("want RB1001, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
}

func TestCheckWildcardVerb_Clean(t *testing.T) {
	obj := clusterRoleWith([]any{
		map[string]any{"verbs": []any{"get", "list"}, "resources": []any{"pods"}},
	})
	ruleID, _, _ := checkWildcardVerb(obj)
	if ruleID != "" {
		t.Errorf("expected no violation, got %s", ruleID)
	}
}

// ── checkWildcardResource ────────────────────────────────────────────────────

func TestCheckWildcardResource_Detects(t *testing.T) {
	obj := clusterRoleWith([]any{
		map[string]any{"verbs": []any{"get"}, "resources": []any{"*"}},
	})
	ruleID, _, _ := checkWildcardResource(obj)
	if ruleID != "RB1002" {
		t.Errorf("want RB1002, got %s", ruleID)
	}
}

// ── checkClusterAdmin ────────────────────────────────────────────────────────

func TestCheckClusterAdmin_Detects(t *testing.T) {
	obj := resourceObject{
		Kind:     "ClusterRoleBinding",
		Metadata: map[string]any{"name": "bad-binding"},
		RoleRef:  map[string]any{"name": "cluster-admin", "kind": "ClusterRole"},
		Subjects: []any{map[string]any{"kind": "User", "name": "alice"}},
	}
	ruleID, severity, _ := checkClusterAdmin(obj)
	if ruleID != "RB1003" {
		t.Errorf("want RB1003, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
}

func TestCheckClusterAdmin_SystemMasters_NoViolation(t *testing.T) {
	obj := resourceObject{
		Kind:     "ClusterRoleBinding",
		Metadata: map[string]any{"name": "system-masters"},
		RoleRef:  map[string]any{"name": "cluster-admin", "kind": "ClusterRole"},
		Subjects: []any{map[string]any{"kind": "Group", "name": "system:masters"}},
	}
	ruleID, _, _ := checkClusterAdmin(obj)
	if ruleID != "" {
		t.Errorf("expected no violation for system:masters, got %s", ruleID)
	}
}

// ── Deployment (non-Pod) ─────────────────────────────────────────────────────

func TestCheckPrivileged_Deployment(t *testing.T) {
	obj := deploymentWith(map[string]any{
		"template": map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name":            "app",
						"securityContext": map[string]any{"privileged": true},
					},
				},
			},
		},
	})
	ruleID, _, _ := checkPrivileged(obj)
	if ruleID != "MV1001" {
		t.Errorf("want MV1001 for Deployment, got %s", ruleID)
	}
}

// ── checkRunAsRoot (MV1004) ──────────────────────────────────────────────────

func TestCheckRunAsRoot_RunAsUserZero(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"runAsUser": float64(0)},
			},
		},
	})
	ruleID, severity, _ := checkRunAsRoot(obj)
	if ruleID != "MV1004" {
		t.Errorf("want MV1004, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
}

func TestCheckRunAsRoot_RunAsNonRootFalse(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"runAsNonRoot": false},
			},
		},
	})
	ruleID, _, _ := checkRunAsRoot(obj)
	if ruleID != "MV1004" {
		t.Errorf("want MV1004, got %s", ruleID)
	}
}

func TestCheckRunAsRoot_PodLevelRunAsUserZero(t *testing.T) {
	obj := podWith(map[string]any{
		"securityContext": map[string]any{"runAsUser": float64(0)},
		"containers":      []any{map[string]any{"name": "app"}},
	})
	ruleID, _, _ := checkRunAsRoot(obj)
	if ruleID != "MV1004" {
		t.Errorf("want MV1004 for pod-level runAsUser:0, got %s", ruleID)
	}
}

func TestCheckRunAsRoot_SafeUser(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"runAsUser": float64(1000), "runAsNonRoot": true},
			},
		},
	})
	ruleID, _, _ := checkRunAsRoot(obj)
	if ruleID != "" {
		t.Errorf("want no violation for runAsUser:1000, got %s", ruleID)
	}
}

func TestCheckRunAsRoot_NoSecurityContext_NoViolation(t *testing.T) {
	// Missing securityContext is not a MV1004 violation (MV1006 covers that).
	obj := podWith(map[string]any{
		"containers": []any{map[string]any{"name": "app"}},
	})
	ruleID, _, _ := checkRunAsRoot(obj)
	if ruleID != "" {
		t.Errorf("want no MV1004 for missing securityContext, got %s", ruleID)
	}
}

// ── checkDangerousCapabilities (MV1005) ──────────────────────────────────────

func TestCheckDangerousCapabilities_SysAdmin(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{"add": []any{"SYS_ADMIN"}},
				},
			},
		},
	})
	ruleID, severity, _ := checkDangerousCapabilities(obj)
	if ruleID != "MV1005" {
		t.Errorf("want MV1005, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error, got %s", severity)
	}
}

func TestCheckDangerousCapabilities_All(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{"add": []any{"ALL"}},
				},
			},
		},
	})
	ruleID, _, _ := checkDangerousCapabilities(obj)
	if ruleID != "MV1005" {
		t.Errorf("want MV1005 for ALL capability, got %s", ruleID)
	}
}

func TestCheckDangerousCapabilities_SafeCapability(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{"add": []any{"NET_BIND_SERVICE"}},
				},
			},
		},
	})
	ruleID, _, _ := checkDangerousCapabilities(obj)
	if ruleID != "" {
		t.Errorf("want no violation for NET_BIND_SERVICE, got %s", ruleID)
	}
}

func TestCheckDangerousCapabilities_CaseInsensitive(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{"add": []any{"net_admin"}},
				},
			},
		},
	})
	ruleID, _, _ := checkDangerousCapabilities(obj)
	if ruleID != "MV1005" {
		t.Errorf("want MV1005 for lowercase net_admin, got %s", ruleID)
	}
}

func TestCheckDangerousCapabilities_NoCaps_NoViolation(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{"drop": []any{"ALL"}},
				},
			},
		},
	})
	ruleID, _, _ := checkDangerousCapabilities(obj)
	if ruleID != "" {
		t.Errorf("want no violation for drop-only, got %s", ruleID)
	}
}

// ── checkAllowPrivilegeEscalation (MV1006) ───────────────────────────────────

func TestCheckAllowPrivilegeEscalation_True(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"allowPrivilegeEscalation": true},
			},
		},
	})
	ruleID, severity, _ := checkAllowPrivilegeEscalation(obj)
	if ruleID != "MV1006" {
		t.Errorf("want MV1006, got %s", ruleID)
	}
	if severity != SeverityError {
		t.Errorf("want error for explicit true, got %s", severity)
	}
}

func TestCheckAllowPrivilegeEscalation_Missing(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"readOnlyRootFilesystem": true},
			},
		},
	})
	ruleID, severity, _ := checkAllowPrivilegeEscalation(obj)
	if ruleID != "MV1006" {
		t.Errorf("want MV1006 when field missing, got %s", ruleID)
	}
	if severity != SeverityWarning {
		t.Errorf("want warning for missing field, got %s", severity)
	}
}

func TestCheckAllowPrivilegeEscalation_MissingSecurityContext(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{map[string]any{"name": "app"}},
	})
	ruleID, severity, _ := checkAllowPrivilegeEscalation(obj)
	if ruleID != "MV1006" {
		t.Errorf("want MV1006 for missing securityContext, got %s", ruleID)
	}
	if severity != SeverityWarning {
		t.Errorf("want warning for missing securityContext, got %s", severity)
	}
}

func TestCheckAllowPrivilegeEscalation_False_Clean(t *testing.T) {
	obj := podWith(map[string]any{
		"containers": []any{
			map[string]any{
				"name":            "app",
				"securityContext": map[string]any{"allowPrivilegeEscalation": false},
			},
		},
	})
	ruleID, _, _ := checkAllowPrivilegeEscalation(obj)
	if ruleID != "" {
		t.Errorf("want no violation for false, got %s", ruleID)
	}
}

// ── Result.Summary ───────────────────────────────────────────────────────────

func TestResult_Summary(t *testing.T) {
	result := &Result{
		Findings: []Finding{
			{Namespace: "default", RuleID: "MV1001"},
			{Namespace: "default", RuleID: "RB1001"},
			{Namespace: "prod", RuleID: "NV1001"},
			{Namespace: "", RuleID: "RB1003"}, // cluster-scoped
		},
	}
	summary := result.Summary()
	if len(summary["default"]) != 2 {
		t.Errorf("want 2 in default, got %d", len(summary["default"]))
	}
	if len(summary["prod"]) != 1 {
		t.Errorf("want 1 in prod, got %d", len(summary["prod"]))
	}
	if len(summary["(cluster-scoped)"]) != 1 {
		t.Errorf("want 1 cluster-scoped, got %d", len(summary["(cluster-scoped)"]))
	}
}
