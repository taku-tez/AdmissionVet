package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AdmissionVet/admissionvet/internal/policy"
)

// WriteKustomize writes a Kustomize overlay structure under outputDir/kustomize/.
func WriteKustomize(policies []*policy.GeneratedPolicy, outputDir string) error {
	baseDir := filepath.Join(outputDir, "kustomize", "base")
	overlayDir := filepath.Join(outputDir, "kustomize", "overlays", "production")

	for _, dir := range []string{baseDir, overlayDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating kustomize directory %s: %w", dir, err)
		}
	}

	var resources []string

	for _, p := range policies {
		ruleID := strings.ToLower(p.RuleID)

		if p.ConstraintTemplate != "" {
			fname := ruleID + "-constrainttemplate.yaml"
			path := filepath.Join(baseDir, fname)
			if err := os.WriteFile(path, []byte(p.ConstraintTemplate), 0o644); err != nil {
				return fmt.Errorf("writing CT for %s: %w", p.RuleID, err)
			}
			resources = append(resources, fname)
			fmt.Printf("  wrote %s\n", path)
		}

		if p.Constraint != "" {
			fname := ruleID + "-constraint.yaml"
			path := filepath.Join(baseDir, fname)
			if err := os.WriteFile(path, []byte(p.Constraint), 0o644); err != nil {
				return fmt.Errorf("writing Constraint for %s: %w", p.RuleID, err)
			}
			resources = append(resources, fname)
			fmt.Printf("  wrote %s\n", path)
		}

		if p.NetworkPolicy != "" {
			fname := ruleID + "-networkpolicy.yaml"
			path := filepath.Join(baseDir, fname)
			if err := os.WriteFile(path, []byte(p.NetworkPolicy), 0o644); err != nil {
				return fmt.Errorf("writing NetworkPolicy for %s: %w", p.RuleID, err)
			}
			resources = append(resources, fname)
			fmt.Printf("  wrote %s\n", path)
		}
	}

	// Write base kustomization.yaml
	baseKustomization := buildKustomizationYAML(resources)
	basePath := filepath.Join(baseDir, "kustomization.yaml")
	if err := os.WriteFile(basePath, []byte(baseKustomization), 0o644); err != nil {
		return fmt.Errorf("writing base kustomization.yaml: %w", err)
	}
	fmt.Printf("  wrote %s\n", basePath)

	// Write production overlay kustomization.yaml
	overlayKustomization := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n\nbases:\n  - ../../base\n"
	overlayPath := filepath.Join(overlayDir, "kustomization.yaml")
	if err := os.WriteFile(overlayPath, []byte(overlayKustomization), 0o644); err != nil {
		return fmt.Errorf("writing overlay kustomization.yaml: %w", err)
	}
	fmt.Printf("  wrote %s\n", overlayPath)

	return nil
}

func buildKustomizationYAML(resources []string) string {
	var sb strings.Builder
	sb.WriteString("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n\nresources:\n")
	for _, r := range resources {
		sb.WriteString(fmt.Sprintf("  - %s\n", r))
	}
	return sb.String()
}
