package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// DriftFinding describes a policy that differs between the generated output
// directory and what is currently deployed in the cluster.
type DriftFinding struct {
	PolicyName string      `json:"policy_name"`
	Kind       string      `json:"kind,omitempty"` // ConstraintTemplate, Constraint, ClusterPolicy, NetworkPolicy
	Status     DriftStatus `json:"status"`
	Message    string      `json:"message"`
}

// DriftStatus describes the type of drift.
type DriftStatus string

const (
	DriftStatusNew     DriftStatus = "new"     // present locally, not in cluster
	DriftStatusMissing DriftStatus = "missing" // in cluster, not locally
	DriftStatusChanged DriftStatus = "changed" // present in both but different spec
)

// DriftSummary holds per-status counts for a drift result.
type DriftSummary struct {
	Total   int `json:"total"`
	New     int `json:"new"`
	Changed int `json:"changed"`
	Missing int `json:"missing"`
}

// DriftResult is the full output of a drift check.
type DriftResult struct {
	Engine   string        `json:"engine"`
	Findings []DriftFinding `json:"findings"`
}

// Summary returns per-status counts for the result.
func (r *DriftResult) Summary() DriftSummary {
	s := DriftSummary{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Status {
		case DriftStatusNew:
			s.New++
		case DriftStatusChanged:
			s.Changed++
		case DriftStatusMissing:
			s.Missing++
		}
	}
	return s
}

// CheckDrift compares policies in outputDir against what is deployed in the cluster.
// engine is "gatekeeper" or "kyverno".
func CheckDrift(outputDir, engine string, opts Options) (*DriftResult, error) {
	result := &DriftResult{Engine: engine}

	// Load generated policies from outputDir.
	local, err := loadLocalPolicies(outputDir, engine)
	if err != nil {
		return nil, fmt.Errorf("loading local policies: %w", err)
	}

	// Fetch deployed policies from the cluster.
	deployed, err := fetchDeployedPolicies(engine, opts)
	if err != nil {
		return nil, fmt.Errorf("fetching deployed policies: %w", err)
	}

	// Compare local vs deployed.
	for name, localSpec := range local {
		deployedSpec, exists := deployed[name]
		if !exists {
			result.Findings = append(result.Findings, DriftFinding{
				PolicyName: name,
				Status:     DriftStatusNew,
				Message:    "policy is generated locally but not deployed to the cluster",
			})
			continue
		}
		if !specsEqual(localSpec, deployedSpec) {
			result.Findings = append(result.Findings, DriftFinding{
				PolicyName: name,
				Status:     DriftStatusChanged,
				Message:    "policy spec differs between local and cluster",
			})
		}
	}

	// Check for policies in cluster that don't exist locally.
	for name := range deployed {
		if _, exists := local[name]; !exists {
			result.Findings = append(result.Findings, DriftFinding{
				PolicyName: name,
				Status:     DriftStatusMissing,
				Message:    "policy is deployed in cluster but not present in output directory",
			})
		}
	}

	return result, nil
}

// loadLocalPolicies reads generated YAML files from outputDir and returns
// a map of policy name → raw spec bytes.
func loadLocalPolicies(outputDir, engine string) (map[string][]byte, error) {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, err
	}

	policies := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		if !matchesEngine(name, engine) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outputDir, name))
		if err != nil {
			return nil, err
		}
		policyName := extractPolicyName(data)
		if policyName != "" {
			policies[policyName] = extractSpec(data)
		}
	}
	return policies, nil
}

// matchesEngine returns true if a filename belongs to the given engine's output.
func matchesEngine(filename, engine string) bool {
	switch engine {
	case "gatekeeper":
		return strings.Contains(filename, "constrainttemplate") ||
			strings.Contains(filename, "constraint")
	case "kyverno":
		return strings.Contains(filename, "clusterpolicy") ||
			strings.Contains(filename, "networkpolicy")
	}
	return true
}

// fetchDeployedPolicies fetches the deployed policies from the cluster via kubectl.
func fetchDeployedPolicies(engine string, opts Options) (map[string][]byte, error) {
	var resource string
	switch engine {
	case "gatekeeper":
		resource = "constrainttemplates"
	case "kyverno":
		resource = "clusterpolicies"
	default:
		return nil, fmt.Errorf("unsupported engine: %s", engine)
	}

	data, err := kubectlGet(opts, resource, true)
	if err != nil {
		// If the CRD doesn't exist, treat as empty (engine not installed).
		if strings.Contains(err.Error(), "no matches for kind") ||
			strings.Contains(err.Error(), "server doesn't have a resource type") {
			return make(map[string][]byte), nil
		}
		return nil, err
	}

	var list struct {
		Items []struct {
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec map[string]any `yaml:"spec"`
		} `yaml:"items"`
	}
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	policies := make(map[string][]byte)
	for _, item := range list.Items {
		specBytes, err := yaml.Marshal(item.Spec)
		if err != nil {
			continue
		}
		policies[item.Metadata.Name] = specBytes
	}
	return policies, nil
}

// extractPolicyName reads the metadata.name from a YAML document.
func extractPolicyName(data []byte) string {
	var obj struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &obj); err != nil {
		return ""
	}
	return obj.Metadata.Name
}

// extractSpec reads the spec section from a YAML document as raw bytes.
func extractSpec(data []byte) []byte {
	var obj struct {
		Spec map[string]any `yaml:"spec"`
	}
	if err := yaml.Unmarshal(data, &obj); err != nil {
		return data
	}
	specBytes, err := yaml.Marshal(obj.Spec)
	if err != nil {
		return data
	}
	return specBytes
}

// specsEqual compares two spec byte slices after normalizing whitespace.
func specsEqual(a, b []byte) bool {
	return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
}
