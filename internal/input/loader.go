package input

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadFromFile reads and parses a scan result JSON file.
// Supports both AdmissionVet native format and K8sVet unified scan output.
func LoadFromFile(path string) (*ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scan results: %w", err)
	}

	// Try native format first.
	var result ScanResult
	if err := json.Unmarshal(data, &result); err == nil && len(result.Violations) > 0 {
		return &result, nil
	}

	// Try K8sVet unified output format.
	if k8svet, err := parseK8sVetFormat(data); err == nil && len(k8svet.Violations) > 0 {
		return k8svet, nil
	}

	// Fall back to native format even if empty (valid empty result).
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing scan results JSON: %w", err)
	}
	return &result, nil
}

// k8sVetOutput is the unified scan output format from K8sVet.
// K8sVet aggregates ManifestVet, RBACVet, NetworkVet results.
type k8sVetOutput struct {
	Summary struct {
		Total    int `json:"total"`
		Errors   int `json:"errors"`
		Warnings int `json:"warnings"`
	} `json:"summary"`
	Results []k8sVetResult `json:"results"`
}

type k8sVetResult struct {
	File     string          `json:"file"`
	Resource string          `json:"resource"`
	Issues   []k8sVetIssue  `json:"issues"`
}

type k8sVetIssue struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Namespace string `json:"namespace"`
}

// parseK8sVetFormat converts K8sVet's unified output into AdmissionVet's ScanResult.
func parseK8sVetFormat(data []byte) (*ScanResult, error) {
	var k8s k8sVetOutput
	if err := json.Unmarshal(data, &k8s); err != nil {
		return nil, err
	}
	if len(k8s.Results) == 0 {
		return nil, fmt.Errorf("no K8sVet results found")
	}

	var violations []Violation
	for _, r := range k8s.Results {
		for _, issue := range r.Issues {
			// Normalize K8sVet rule IDs to AdmissionVet format.
			ruleID := normalizeRuleID(issue.ID)
			violations = append(violations, Violation{
				RuleID:    ruleID,
				Severity:  Severity(strings.ToLower(issue.Severity)),
				Resource:  r.Resource,
				Namespace: issue.Namespace,
				Message:   issue.Message,
			})
		}
	}

	return &ScanResult{Violations: violations}, nil
}

// normalizeRuleID maps K8sVet rule IDs to AdmissionVet's format.
// K8sVet may use lowercase or different conventions.
var ruleIDMap = map[string]string{
	// ManifestVet aliases
	"mv1003": "MV1001", // privileged — K8sVet uses mv1003 for this
	"mv1004": "MV1002", // hostPID
	"mv1005": "MV1002", // hostIPC
	"mv1006": "MV1002", // hostNetwork
	"mv1010": "MV1007", // readOnlyRootFilesystem
	// RBACVet aliases
	"rb1001": "RB1001",
	"rb1002": "RB1002",
	// Pass through already-normalized IDs
}

func normalizeRuleID(id string) string {
	if mapped, ok := ruleIDMap[strings.ToLower(id)]; ok {
		return mapped
	}
	return strings.ToUpper(id)
}

