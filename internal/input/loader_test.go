package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile_NativeFormat(t *testing.T) {
	json := `{
		"violations": [
			{"rule_id": "MV1001", "severity": "error", "resource": "Deployment/nginx", "namespace": "default", "message": "privileged"},
			{"rule_id": "MV1007", "severity": "warning", "resource": "Deployment/api", "namespace": "production", "message": "no readOnly"}
		]
	}`
	path := writeTempFile(t, json)

	result, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 2 {
		t.Fatalf("want 2 violations, got %d", len(result.Violations))
	}
	if result.Violations[0].RuleID != "MV1001" {
		t.Errorf("want MV1001, got %s", result.Violations[0].RuleID)
	}
	if result.Violations[1].Namespace != "production" {
		t.Errorf("want production, got %s", result.Violations[1].Namespace)
	}
}

func TestLoadFromFile_K8sVetFormat(t *testing.T) {
	json := `{
		"summary": {"total": 2, "errors": 2, "warnings": 0},
		"results": [
			{
				"file": "deploy.yaml",
				"resource": "Deployment/nginx",
				"issues": [
					{"id": "mv1003", "severity": "error", "message": "privileged", "namespace": "default"},
					{"id": "rb1001", "severity": "error", "message": "wildcard verb", "namespace": ""}
				]
			}
		]
	}`
	path := writeTempFile(t, json)

	result, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 2 {
		t.Fatalf("want 2 violations, got %d", len(result.Violations))
	}
	// mv1003 → MV1001 via normalizeRuleID
	if result.Violations[0].RuleID != "MV1001" {
		t.Errorf("want MV1001 (normalized from mv1003), got %s", result.Violations[0].RuleID)
	}
	// rb1001 → RB1001
	if result.Violations[1].RuleID != "RB1001" {
		t.Errorf("want RB1001, got %s", result.Violations[1].RuleID)
	}
}

func TestLoadFromFile_EmptyViolations(t *testing.T) {
	json := `{"violations": []}`
	path := writeTempFile(t, json)

	result, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Fatalf("want 0 violations, got %d", len(result.Violations))
	}
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	path := writeTempFile(t, `not json`)

	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadFromFile_MissingFile(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadFromFile_TrivyFormat(t *testing.T) {
	path := writeTempFile(t, `{
		"SchemaVersion": 2,
		"ArtifactType": "kubernetes",
		"Resources": [
			{
				"Namespace": "default",
				"Kind": "Deployment",
				"Name": "nginx",
				"Results": [
					{
						"Target": "Deployment/nginx",
						"Misconfigurations": [
							{
								"ID": "KSV001",
								"Title": "Privilege escalation",
								"Message": "Container 'nginx' should not allow privilege escalation",
								"Severity": "HIGH",
								"Status": "FAIL"
							},
							{
								"ID": "KSV014",
								"Title": "Root file system is not read-only",
								"Message": "Container 'nginx' should set readOnlyRootFilesystem",
								"Severity": "LOW",
								"Status": "FAIL"
							},
							{
								"ID": "KSV014",
								"Title": "Root file system is not read-only",
								"Message": "PASS item should be ignored",
								"Severity": "LOW",
								"Status": "PASS"
							}
						]
					}
				]
			},
			{
				"Namespace": "",
				"Kind": "ClusterRole",
				"Name": "developer",
				"Results": [
					{
						"Target": "ClusterRole/developer",
						"Misconfigurations": [
							{
								"ID": "KSV041",
								"Title": "Wildcard verb",
								"Message": "ClusterRole 'developer' uses wildcard verb",
								"Severity": "HIGH",
								"Status": "FAIL"
							}
						]
					}
				]
			}
		]
	}`)

	result, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 FAIL items (PASS is skipped): KSV001→MV1001, KSV014→MV1007, KSV041→RB1001
	if len(result.Violations) != 3 {
		t.Fatalf("want 3 violations, got %d: %+v", len(result.Violations), result.Violations)
	}

	// KSV001 → MV1001
	if result.Violations[0].RuleID != "MV1001" {
		t.Errorf("want MV1001 (from KSV001), got %s", result.Violations[0].RuleID)
	}
	// HIGH → error
	if result.Violations[0].Severity != SeverityError {
		t.Errorf("want error (from HIGH), got %s", result.Violations[0].Severity)
	}
	if result.Violations[0].Namespace != "default" {
		t.Errorf("want default namespace, got %s", result.Violations[0].Namespace)
	}

	// KSV014 → MV1007, LOW → info
	if result.Violations[1].RuleID != "MV1007" {
		t.Errorf("want MV1007 (from KSV014), got %s", result.Violations[1].RuleID)
	}
	if result.Violations[1].Severity != SeverityInfo {
		t.Errorf("want info (from LOW), got %s", result.Violations[1].Severity)
	}

	// KSV041 → RB1001
	if result.Violations[2].RuleID != "RB1001" {
		t.Errorf("want RB1001 (from KSV041), got %s", result.Violations[2].RuleID)
	}
}

func TestLoadFromFile_Trivy_UnknownKSV(t *testing.T) {
	path := writeTempFile(t, `{
		"SchemaVersion": 2,
		"ArtifactType": "kubernetes",
		"Resources": [
			{
				"Namespace": "default",
				"Kind": "Pod",
				"Name": "test",
				"Results": [
					{
						"Target": "Pod/test",
						"Misconfigurations": [
							{
								"ID": "KSV999",
								"Message": "Unknown check",
								"Severity": "MEDIUM",
								"Status": "FAIL"
							}
						]
					}
				]
			}
		]
	}`)

	result, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("want 1, got %d", len(result.Violations))
	}
	// Unknown KSV → K_KSV999
	if result.Violations[0].RuleID != "K_KSV999" {
		t.Errorf("want K_KSV999, got %s", result.Violations[0].RuleID)
	}
}

func TestLoadFromFile_Trivy_FromFixture(t *testing.T) {
	result, err := LoadFromFile("../../testdata/results_trivy.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) == 0 {
		t.Fatal("expected violations from trivy fixture")
	}
	// Verify rule ID mapping from fixture
	ruleIDs := make(map[string]bool)
	for _, v := range result.Violations {
		ruleIDs[v.RuleID] = true
	}
	for _, expected := range []string{"MV1001", "MV1007", "MV1002", "MV1003", "RB1001"} {
		if !ruleIDs[expected] {
			t.Errorf("expected rule %s in trivy fixture output, got rules: %v", expected, ruleIDs)
		}
	}
}

func TestNormalizeRuleID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"mv1003", "MV1001"},
		{"mv1004", "MV1002"},
		{"mv1005", "MV1002"},
		{"mv1006", "MV1002"},
		{"mv1010", "MV1007"},
		{"rb1001", "RB1001"},
		{"rb1002", "RB1002"},
		{"MV1001", "MV1001"}, // already normalized
		{"CUSTOM001", "CUSTOM001"},
	}
	for _, tc := range tests {
		got := normalizeRuleID(tc.input)
		if got != tc.want {
			t.Errorf("normalizeRuleID(%q): want %s, got %s", tc.input, tc.want, got)
		}
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}
