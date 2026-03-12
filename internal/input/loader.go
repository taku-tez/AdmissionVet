package input

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadFromFile reads and parses a scan result JSON file.
// Supports AdmissionVet native format, K8sVet unified scan output, and Trivy k8s JSON.
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

	// Try Trivy k8s JSON format.
	if trivy, err := parseTrivyFormat(data); err == nil && len(trivy.Violations) > 0 {
		return trivy, nil
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
	"mv1011": "MV2001", // K8sVet: secret literal in env var
	"mv1012": "MV2001", // K8sVet: alternate secret env var check
	// RBACVet aliases
	"rb1001": "RB1001",
	"rb1002": "RB1002",
	"rb1003": "RB1003",
	// Pass through already-normalized IDs
}

func normalizeRuleID(id string) string {
	if mapped, ok := ruleIDMap[strings.ToLower(id)]; ok {
		return mapped
	}
	return strings.ToUpper(id)
}

// ── Trivy k8s JSON format ────────────────────────────────────────────────────

// trivyOutput is the top-level structure of `trivy k8s -f json` output.
type trivyOutput struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactType  string         `json:"ArtifactType"`
	Resources     []trivyResource `json:"Resources"`
}

type trivyResource struct {
	Namespace string        `json:"Namespace"`
	Kind      string        `json:"Kind"`
	Name      string        `json:"Name"`
	Results   []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string              `json:"Target"`
	Misconfigurations []trivyMisconfig    `json:"Misconfigurations"`
}

type trivyMisconfig struct {
	ID       string `json:"ID"`
	Title    string `json:"Title"`
	Message  string `json:"Message"`
	Severity string `json:"Severity"`
	Status   string `json:"Status"`
}

// trivyKSVMap maps Trivy KSV IDs to AdmissionVet rule IDs.
var trivyKSVMap = map[string]string{
	// MV1001: privileged containers / privilege escalation
	"KSV001": "MV1001", // allowPrivilegeEscalation
	"KSV006": "MV1001", // privileged container

	// MV1002: host namespace sharing
	"KSV008": "MV1002", // hostPID
	"KSV009": "MV1002", // hostIPC
	"KSV010": "MV1002", // hostNetwork

	// MV1003: hostPath volume mounts
	"KSV028": "MV1003", // hostPath volume

	// MV1004: root user execution (new rule)
	"KSV005": "MV1004", // running as root (non-numeric)
	"KSV020": "MV1004", // runAsUser >= 0 (must be > 0)
	"KSV021": "MV1004", // runAsUser == 0 explicitly
	"KSV029": "MV1004", // runAsGroup == 0

	// MV1005: dangerous Linux capabilities (new rule)
	"KSV003": "MV1005", // added capabilities
	"KSV024": "MV1005", // NET_ADMIN or SYS_ADMIN
	"KSV025": "MV1005", // SYS_ADMIN specifically
	"KSV030": "MV1005", // seccomp profile not set (related capability constraint)

	// MV1006: allowPrivilegeEscalation not set to false (new rule)
	"KSV002": "MV1006", // allowPrivilegeEscalation not explicitly false
	"KSV045": "MV1006", // allowPrivilegeEscalation (alternate check)

	// MV1007: readOnlyRootFilesystem
	"KSV014": "MV1007", // readOnlyRootFilesystem not set
	"KSV036": "MV1007", // readOnlyRootFilesystem (alternate)

	// MV2001: secrets as literal env vars
	"KSV027": "MV2001", // env var with secret-like name has literal value

	// RB1001–RB1003: RBAC
	"KSV041": "RB1001", // wildcard RBAC verbs
	"KSV042": "RB1002", // wildcard RBAC resources
	"KSV044": "RB1003", // cluster-admin binding
}

// trivySeverityMap maps Trivy severity strings to AdmissionVet Severity.
var trivySeverityMap = map[string]Severity{
	"CRITICAL": SeverityError,
	"HIGH":     SeverityError,
	"MEDIUM":   SeverityWarning,
	"LOW":      SeverityInfo,
	"UNKNOWN":  SeverityInfo,
}

// parseTrivyFormat converts a `trivy k8s -f json` output into AdmissionVet's ScanResult.
func parseTrivyFormat(data []byte) (*ScanResult, error) {
	var trivy trivyOutput
	if err := json.Unmarshal(data, &trivy); err != nil {
		return nil, err
	}
	if trivy.ArtifactType != "kubernetes" || len(trivy.Resources) == 0 {
		return nil, fmt.Errorf("not a trivy k8s output")
	}

	var violations []Violation
	for _, res := range trivy.Resources {
		resource := res.Kind + "/" + res.Name
		for _, result := range res.Results {
			for _, mc := range result.Misconfigurations {
				if mc.Status != "FAIL" {
					continue
				}
				ruleID, ok := trivyKSVMap[mc.ID]
				if !ok {
					// Pass through unknown KSV IDs with a K_ prefix.
					ruleID = "K_" + mc.ID
				}
				severity, ok := trivySeverityMap[strings.ToUpper(mc.Severity)]
				if !ok {
					severity = SeverityInfo
				}
				violations = append(violations, Violation{
					RuleID:    ruleID,
					Severity:  severity,
					Resource:  resource,
					Namespace: res.Namespace,
					Message:   mc.Message,
				})
			}
		}
	}

	return &ScanResult{Violations: violations}, nil
}

