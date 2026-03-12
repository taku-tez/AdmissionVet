package exceptions

import (
	"os"
	"path/filepath"
	"testing"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	return path
}

const exampleExceptions = `exceptions:
  - ruleID: MV1001
    namespace: kube-system
    reason: "CNI requires privileged"
  - ruleID: MV1007
    resource: "Deployment/legacy-app"
    reason: "Legacy app, pending migration"
  - namespace: sandbox
    reason: "Sandbox namespace, all rules suppressed"
`

func TestLoadFromFile(t *testing.T) {
	path := writeYAML(t, exampleExceptions)
	list, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Exceptions) != 3 {
		t.Fatalf("want 3 exceptions, got %d", len(list.Exceptions))
	}
	if list.Exceptions[0].RuleID != "MV1001" {
		t.Errorf("want MV1001, got %s", list.Exceptions[0].RuleID)
	}
	if list.Exceptions[0].Namespace != "kube-system" {
		t.Errorf("want kube-system, got %s", list.Exceptions[0].Namespace)
	}
	if list.Exceptions[0].Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestLoadFromFile_EmptyPath(t *testing.T) {
	list, err := LoadFromFile("")
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	if len(list.Exceptions) != 0 {
		t.Errorf("want 0 exceptions, got %d", len(list.Exceptions))
	}
}

func TestLoadFromFile_MissingFile(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/exceptions.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	path := writeYAML(t, ": invalid: yaml: [")
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// ── Exception.Matches ────────────────────────────────────────────────────────

func TestExceptionMatches(t *testing.T) {
	tests := []struct {
		name      string
		ex        Exception
		ruleID    string
		namespace string
		resource  string
		want      bool
	}{
		{
			name:      "exact match all fields",
			ex:        Exception{RuleID: "MV1001", Namespace: "kube-system"},
			ruleID:    "MV1001",
			namespace: "kube-system",
			want:      true,
		},
		{
			name:      "ruleID mismatch",
			ex:        Exception{RuleID: "MV1001", Namespace: "kube-system"},
			ruleID:    "MV1002",
			namespace: "kube-system",
			want:      false,
		},
		{
			name:      "namespace mismatch",
			ex:        Exception{RuleID: "MV1001", Namespace: "kube-system"},
			ruleID:    "MV1001",
			namespace: "production",
			want:      false,
		},
		{
			name:      "wildcard ruleID (empty) matches any rule",
			ex:        Exception{Namespace: "sandbox"},
			ruleID:    "RB1003",
			namespace: "sandbox",
			want:      true,
		},
		{
			name:      "wildcard namespace (empty) matches any namespace",
			ex:        Exception{RuleID: "MV1001"},
			ruleID:    "MV1001",
			namespace: "production",
			want:      true,
		},
		{
			name:     "resource match",
			ex:       Exception{RuleID: "MV1007", Resource: "Deployment/legacy-app"},
			ruleID:   "MV1007",
			resource: "Deployment/legacy-app",
			want:     true,
		},
		{
			name:     "resource mismatch",
			ex:       Exception{RuleID: "MV1007", Resource: "Deployment/legacy-app"},
			ruleID:   "MV1007",
			resource: "Deployment/other-app",
			want:     false,
		},
		{
			name:   "all empty fields matches everything",
			ex:     Exception{},
			ruleID: "MV1001", namespace: "prod", resource: "Deployment/app",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ex.Matches(tc.ruleID, tc.namespace, tc.resource)
			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

// ── Filter (generic) ─────────────────────────────────────────────────────────

type testItem struct {
	ruleID    string
	namespace string
	resource  string
}

func TestFilter(t *testing.T) {
	items := []testItem{
		{ruleID: "MV1001", namespace: "kube-system", resource: "DaemonSet/cni"},
		{ruleID: "MV1001", namespace: "default", resource: "Deployment/app"},
		{ruleID: "MV1007", namespace: "default", resource: "Deployment/legacy-app"},
		{ruleID: "RB1001", namespace: "", resource: "ClusterRole/dev"},
	}

	list := &ExceptionList{
		Exceptions: []Exception{
			{RuleID: "MV1001", Namespace: "kube-system"}, // suppress CNI
			{RuleID: "MV1007", Resource: "Deployment/legacy-app"},
		},
	}

	key := func(i testItem) (string, string, string) { return i.ruleID, i.namespace, i.resource }
	got := Filter(items, list, key)

	if len(got) != 2 {
		t.Fatalf("want 2 items after filtering, got %d", len(got))
	}
	// Should keep: MV1001/default, RB1001
	if got[0].ruleID != "MV1001" || got[0].namespace != "default" {
		t.Errorf("unexpected first item: %+v", got[0])
	}
	if got[1].ruleID != "RB1001" {
		t.Errorf("unexpected second item: %+v", got[1])
	}
}

func TestFilter_NilList(t *testing.T) {
	items := []testItem{{ruleID: "MV1001"}, {ruleID: "RB1001"}}
	key := func(i testItem) (string, string, string) { return i.ruleID, i.namespace, i.resource }
	got := Filter(items, nil, key)
	if len(got) != 2 {
		t.Fatalf("nil list should return all items, got %d", len(got))
	}
}

func TestFilter_EmptyList(t *testing.T) {
	items := []testItem{{ruleID: "MV1001"}}
	key := func(i testItem) (string, string, string) { return i.ruleID, i.namespace, i.resource }
	got := Filter(items, &ExceptionList{}, key)
	if len(got) != 1 {
		t.Fatalf("empty exception list should return all items, got %d", len(got))
	}
}
