package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLocalPolicies_Gatekeeper(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "mv1001-constrainttemplate.yaml", `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: mv1001
spec:
  crd:
    spec:
      names:
        kind: Mv1001
`)
	writeFile(t, dir, "mv1001-constraint.yaml", `apiVersion: constraints.gatekeeper.sh/v1beta1
kind: Mv1001
metadata:
  name: mv1001
spec:
  enforcementAction: deny
`)
	// This file should be ignored for gatekeeper engine.
	writeFile(t, dir, "mv1001-clusterpolicy.yaml", `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: mv1001-no-privileged
spec: {}
`)

	policies, err := loadLocalPolicies(dir, "gatekeeper")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := policies["mv1001"]; !ok {
		t.Error("expected mv1001 constrainttemplate to be loaded")
	}
	if _, ok := policies["mv1001-no-privileged"]; ok {
		t.Error("kyverno clusterpolicy should not be loaded for gatekeeper engine")
	}
}

func TestLoadLocalPolicies_Kyverno(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "mv1001-clusterpolicy.yaml", `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: mv1001-no-privileged
spec:
  rules: []
`)

	policies, err := loadLocalPolicies(dir, "kyverno")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := policies["mv1001-no-privileged"]; !ok {
		t.Error("expected mv1001-no-privileged to be loaded for kyverno engine")
	}
}

func TestLoadLocalPolicies_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	policies, err := loadLocalPolicies(dir, "gatekeeper")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("want 0 policies, got %d", len(policies))
	}
}

func TestLoadLocalPolicies_NonExistentDir(t *testing.T) {
	_, err := loadLocalPolicies("/nonexistent/dir", "gatekeeper")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestExtractPolicyName(t *testing.T) {
	yaml := []byte(`apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: mv1001
spec:
  crd:
    spec:
      names:
        kind: Mv1001
`)
	name := extractPolicyName(yaml)
	if name != "mv1001" {
		t.Errorf("want mv1001, got %s", name)
	}
}

func TestSpecsEqual(t *testing.T) {
	a := []byte("key: value\n")
	b := []byte("key: value\n")
	c := []byte("key: different\n")

	if !specsEqual(a, b) {
		t.Error("identical specs should be equal")
	}
	if specsEqual(a, c) {
		t.Error("different specs should not be equal")
	}
}

func TestMatchesEngine(t *testing.T) {
	tests := []struct {
		filename string
		engine   string
		want     bool
	}{
		{"mv1001-constrainttemplate.yaml", "gatekeeper", true},
		{"mv1001-constraint.yaml", "gatekeeper", true},
		{"mv1001-clusterpolicy.yaml", "gatekeeper", false},
		{"mv1001-clusterpolicy.yaml", "kyverno", true},
		{"nv1001-networkpolicy.yaml", "kyverno", true},
		{"mv1001-constrainttemplate.yaml", "kyverno", false},
	}
	for _, tc := range tests {
		got := matchesEngine(tc.filename, tc.engine)
		if got != tc.want {
			t.Errorf("matchesEngine(%q, %q): want %v, got %v", tc.filename, tc.engine, tc.want, got)
		}
	}
}

func TestDriftResult_NoDrift(t *testing.T) {
	// DriftResult with no findings should have empty findings slice.
	result := &DriftResult{Engine: "gatekeeper"}
	if len(result.Findings) != 0 {
		t.Errorf("want 0 findings, got %d", len(result.Findings))
	}
}

func TestDriftResult_Summary(t *testing.T) {
	result := &DriftResult{
		Engine: "gatekeeper",
		Findings: []DriftFinding{
			{PolicyName: "mv1001", Status: DriftStatusNew, Message: "not deployed"},
			{PolicyName: "mv1002", Status: DriftStatusChanged, Message: "spec differs"},
			{PolicyName: "mv1003", Status: DriftStatusMissing, Message: "not local"},
			{PolicyName: "mv1004", Status: DriftStatusNew, Message: "not deployed"},
		},
	}
	s := result.Summary()
	if s.Total != 4 {
		t.Errorf("want Total=4, got %d", s.Total)
	}
	if s.New != 2 {
		t.Errorf("want New=2, got %d", s.New)
	}
	if s.Changed != 1 {
		t.Errorf("want Changed=1, got %d", s.Changed)
	}
	if s.Missing != 1 {
		t.Errorf("want Missing=1, got %d", s.Missing)
	}
}

func TestDriftFinding_JSONTags(t *testing.T) {
	import_json := func(f DriftFinding) map[string]any {
		// We test the JSON shape by encoding and checking field names.
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		return m
	}
	f := DriftFinding{
		PolicyName: "mv1001-constraint",
		Status:     DriftStatusChanged,
		Message:    "spec differs",
	}
	m := import_json(f)
	for _, key := range []string{"policy_name", "status", "message"} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
	if m["policy_name"] != "mv1001-constraint" {
		t.Errorf("policy_name: got %v", m["policy_name"])
	}
	if m["status"] != "changed" {
		t.Errorf("status: got %v", m["status"])
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}
