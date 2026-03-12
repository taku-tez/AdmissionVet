package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AdmissionVet/admissionvet/internal/policy"
)

func TestWriteYAML_GatekeeperPolicy(t *testing.T) {
	dir := t.TempDir()
	policies := []*policy.GeneratedPolicy{
		{
			RuleID:             "MV1001",
			ConstraintTemplate: "apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\n",
			Constraint:         "apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: Mv1001\n",
		},
	}
	if err := WriteYAML(policies, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctPath := filepath.Join(dir, "mv1001-constrainttemplate.yaml")
	cPath := filepath.Join(dir, "mv1001-constraint.yaml")

	assertFileContains(t, ctPath, "ConstraintTemplate")
	assertFileContains(t, cPath, "Mv1001")
}

func TestWriteYAML_KyvernoPolicy(t *testing.T) {
	dir := t.TempDir()
	policies := []*policy.GeneratedPolicy{
		{
			RuleID:        "MV1001",
			ClusterPolicy: "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n",
		},
	}
	if err := WriteYAML(policies, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cpPath := filepath.Join(dir, "mv1001-clusterpolicy.yaml")
	assertFileContains(t, cpPath, "ClusterPolicy")
}

func TestWriteYAML_NetworkPolicy(t *testing.T) {
	dir := t.TempDir()
	policies := []*policy.GeneratedPolicy{
		{
			RuleID:        "NV1001",
			NetworkPolicy: "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n",
		},
	}
	if err := WriteYAML(policies, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	npPath := filepath.Join(dir, "nv1001-networkpolicy.yaml")
	assertFileContains(t, npPath, "NetworkPolicy")
}

func TestWriteYAML_CreatesOutputDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "output")
	policies := []*policy.GeneratedPolicy{
		{RuleID: "MV1001", ClusterPolicy: "kind: ClusterPolicy\n"},
	}
	if err := WriteYAML(policies, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("output directory was not created")
	}
}

func TestWriteYAML_EmptyPolicies(t *testing.T) {
	dir := t.TempDir()
	if err := WriteYAML(nil, dir); err != nil {
		t.Fatalf("unexpected error for empty policies: %v", err)
	}
}

func TestWriteYAML_RuleIDIsLowercased(t *testing.T) {
	dir := t.TempDir()
	policies := []*policy.GeneratedPolicy{
		{RuleID: "MV1001", ClusterPolicy: "kind: ClusterPolicy\n"},
	}
	if err := WriteYAML(policies, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Filename should use lowercase rule ID.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "MV1001") {
			t.Errorf("filename should be lowercase, got %s", e.Name())
		}
	}
}

func assertFileContains(t *testing.T, path, substr string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if !strings.Contains(string(data), substr) {
		t.Errorf("file %s missing %q\ncontent:\n%s", path, substr, string(data))
	}
}
