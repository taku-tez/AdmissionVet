package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/output"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	"github.com/AdmissionVet/admissionvet/internal/versions"
)

// validateEngine returns an error if engine is not "gatekeeper" or "kyverno".
func validateEngine(engine string) error {
	if engine != "gatekeeper" && engine != "kyverno" {
		return fmt.Errorf("unsupported engine %q: use gatekeeper or kyverno", engine)
	}
	return nil
}

// generatePolicies runs each generator for the given rule IDs and returns the
// generated policies together with any skipped rule IDs.
func generatePolicies(
	engine string,
	ruleIDs []string,
	byRule map[string][]input.Violation,
	namespace string,
) ([]*policy.GeneratedPolicy, []string, error) {
	var policies []*policy.GeneratedPolicy
	var skipped []string

	for _, ruleID := range ruleIDs {
		gen, ok := policy.Get(engine, ruleID)
		if !ok {
			skipped = append(skipped, ruleID)
			continue
		}
		p, err := gen.Generate(byRule[ruleID], namespace)
		if err != nil {
			return nil, nil, fmt.Errorf("generating policy for %s: %w", ruleID, err)
		}
		policies = append(policies, p)
	}
	return policies, skipped, nil
}

// writePolicies stashes the current output, writes policies in the chosen
// format, and records a new version entry.
func writePolicies(
	policies []*policy.GeneratedPolicy,
	format, outputDir, engine, source string,
) error {
	// Stash current state before overwriting (enables rollback).
	if h, err := versions.Load(outputDir); err == nil && len(h.Entries) > 0 {
		_ = versions.Stash(outputDir, h.Entries[len(h.Entries)-1].Version)
	}

	var err error
	switch format {
	case "yaml":
		err = output.WriteYAML(policies, outputDir)
	case "helm":
		err = output.WriteHelm(policies, outputDir)
	case "kustomize":
		err = output.WriteKustomize(policies, outputDir)
	default:
		return fmt.Errorf("unsupported format %q: use yaml|helm|kustomize", format)
	}
	if err != nil {
		return err
	}

	if entry, err := versions.Record(outputDir, engine, source); err == nil {
		fmt.Printf("  versioned as v%d\n", entry.Version)
	}
	return nil
}

// expandPaths resolves a list of file or directory paths into a flat list of
// YAML file paths (.yaml / .yml). Directories are not traversed recursively.
func expandPaths(args []string) ([]string, error) {
	var files []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("cannot access %s: %w", arg, err)
		}
		if !info.IsDir() {
			files = append(files, arg)
			continue
		}
		entries, err := os.ReadDir(arg)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				files = append(files, arg+"/"+name)
			}
		}
	}
	return files, nil
}
