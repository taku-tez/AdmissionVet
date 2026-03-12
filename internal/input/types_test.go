package input

import (
	"testing"
)

func TestFilterBySeverity(t *testing.T) {
	violations := []Violation{
		{RuleID: "MV1001", Severity: SeverityError},
		{RuleID: "MV1002", Severity: SeverityWarning},
		{RuleID: "MV1003", Severity: SeverityInfo},
	}

	t.Run("empty minSeverity returns all", func(t *testing.T) {
		got := FilterBySeverity(violations, "")
		if len(got) != 3 {
			t.Fatalf("want 3, got %d", len(got))
		}
	})

	t.Run("error filters to error only", func(t *testing.T) {
		got := FilterBySeverity(violations, SeverityError)
		if len(got) != 1 || got[0].RuleID != "MV1001" {
			t.Fatalf("want [MV1001], got %v", got)
		}
	})

	t.Run("warning includes warning and error", func(t *testing.T) {
		got := FilterBySeverity(violations, SeverityWarning)
		if len(got) != 2 {
			t.Fatalf("want 2, got %d", len(got))
		}
	})

	t.Run("info returns all", func(t *testing.T) {
		got := FilterBySeverity(violations, SeverityInfo)
		if len(got) != 3 {
			t.Fatalf("want 3, got %d", len(got))
		}
	})

	t.Run("unknown severity returns all", func(t *testing.T) {
		got := FilterBySeverity(violations, "unknown")
		if len(got) != 3 {
			t.Fatalf("want 3, got %d", len(got))
		}
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		got := FilterBySeverity(nil, SeverityError)
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
	})
}

func TestFilterByNamespace(t *testing.T) {
	violations := []Violation{
		{RuleID: "MV1001", Namespace: "default"},
		{RuleID: "MV1002", Namespace: "production"},
		{RuleID: "MV1003", Namespace: ""},
	}

	t.Run("empty namespace returns all", func(t *testing.T) {
		got := FilterByNamespace(violations, "")
		if len(got) != 3 {
			t.Fatalf("want 3, got %d", len(got))
		}
	})

	t.Run("filters to matching namespace", func(t *testing.T) {
		got := FilterByNamespace(violations, "default")
		if len(got) != 1 || got[0].RuleID != "MV1001" {
			t.Fatalf("want [MV1001], got %v", got)
		}
	})

	t.Run("no match returns empty", func(t *testing.T) {
		got := FilterByNamespace(violations, "staging")
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
	})
}

func TestUniqueRuleIDs(t *testing.T) {
	t.Run("deduplicates preserving order", func(t *testing.T) {
		violations := []Violation{
			{RuleID: "MV1001"},
			{RuleID: "MV1002"},
			{RuleID: "MV1001"}, // duplicate
			{RuleID: "RB1001"},
		}
		got := UniqueRuleIDs(violations)
		want := []string{"MV1001", "MV1002", "RB1001"}
		if len(got) != len(want) {
			t.Fatalf("want %v, got %v", want, got)
		}
		for i, id := range want {
			if got[i] != id {
				t.Errorf("index %d: want %s, got %s", i, id, got[i])
			}
		}
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		got := UniqueRuleIDs(nil)
		if len(got) != 0 {
			t.Fatalf("want empty, got %v", got)
		}
	})

	t.Run("all unique returns same order", func(t *testing.T) {
		violations := []Violation{
			{RuleID: "RB1001"},
			{RuleID: "NV1001"},
		}
		got := UniqueRuleIDs(violations)
		if len(got) != 2 || got[0] != "RB1001" || got[1] != "NV1001" {
			t.Fatalf("want [RB1001 NV1001], got %v", got)
		}
	})
}
