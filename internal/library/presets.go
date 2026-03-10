// Package library provides built-in policy presets for common Kubernetes environments.
package library

import "github.com/AdmissionVet/admissionvet/internal/input"

// Preset represents a named collection of pre-defined violations to generate policies for.
type Preset struct {
	Name        string
	Description string
	Tags        []string
	Violations  []input.Violation
}

// All returns all available presets.
func All() []Preset {
	return []Preset{
		Baseline(),
		Restricted(),
		GKEStandard(),
		EKSStandard(),
		PCIDSS(),
	}
}

// Get returns a preset by name, or nil if not found.
func Get(name string) *Preset {
	for _, p := range All() {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

// workloadViolation creates a synthetic error-severity violation for generating policies.
func workloadViolation(ruleID, message string) input.Violation {
	return input.Violation{
		RuleID:   ruleID,
		Severity: input.SeverityError,
		Resource: "all-workloads",
		Message:  message,
	}
}

// Baseline returns the baseline security preset (CIS Benchmark equivalent).
func Baseline() Preset {
	return Preset{
		Name:        "baseline",
		Description: "CIS Benchmark equivalent: minimal security baseline for all clusters",
		Tags:        []string{"cis", "general"},
		Violations: []input.Violation{
			workloadViolation("MV1001", "baseline: no privileged containers"),
			workloadViolation("MV1002", "baseline: no host namespaces"),
			workloadViolation("MV1003", "baseline: no hostPath volumes"),
			workloadViolation("RB1001", "baseline: no wildcard verbs"),
			workloadViolation("RB1002", "baseline: no wildcard resources"),
			workloadViolation("NV1001", "baseline: default-deny NetworkPolicy"),
		},
	}
}

// Restricted returns the restricted security preset (maximum restrictions).
func Restricted() Preset {
	return Preset{
		Name:        "restricted",
		Description: "Maximum restrictions: minimal privilege, readOnlyRootFS, no secrets in env",
		Tags:        []string{"strict", "zero-trust"},
		Violations: []input.Violation{
			workloadViolation("MV1001", "restricted: no privileged containers"),
			workloadViolation("MV1002", "restricted: no host namespaces"),
			workloadViolation("MV1003", "restricted: no hostPath volumes"),
			workloadViolation("MV1007", "restricted: readOnlyRootFilesystem required"),
			workloadViolation("MV2001", "restricted: no secrets in env vars"),
			workloadViolation("RB1001", "restricted: no wildcard verbs"),
			workloadViolation("RB1002", "restricted: no wildcard resources"),
			workloadViolation("RB1003", "restricted: no cluster-admin binding"),
			workloadViolation("NV1001", "restricted: default-deny NetworkPolicy"),
		},
	}
}

// GKEStandard returns the GKE recommended configuration preset.
func GKEStandard() Preset {
	return Preset{
		Name:        "gke-standard",
		Description: "GKE recommended security settings: Workload Identity, Binary Authorization, and network policies",
		Tags:        []string{"gke", "google-cloud"},
		Violations: []input.Violation{
			workloadViolation("MV1001", "gke: no privileged containers"),
			workloadViolation("MV1002", "gke: no host namespaces"),
			workloadViolation("MV1003", "gke: no hostPath volumes"),
			workloadViolation("MV1007", "gke: readOnlyRootFilesystem required"),
			workloadViolation("MV2001", "gke: no secrets in env vars"),
			workloadViolation("RB1001", "gke: no wildcard verbs"),
			workloadViolation("RB1003", "gke: no cluster-admin binding"),
			workloadViolation("NV1001", "gke: default-deny NetworkPolicy"),
			workloadViolation("IV1001", "gke: Binary Authorization — require signed images"),
		},
	}
}

// EKSStandard returns the EKS recommended configuration preset.
func EKSStandard() Preset {
	return Preset{
		Name:        "eks-standard",
		Description: "EKS recommended security settings: IRSA, image scanning, and network policies",
		Tags:        []string{"eks", "aws"},
		Violations: []input.Violation{
			workloadViolation("MV1001", "eks: no privileged containers"),
			workloadViolation("MV1002", "eks: no host namespaces"),
			workloadViolation("MV1003", "eks: no hostPath volumes"),
			workloadViolation("MV1007", "eks: readOnlyRootFilesystem required"),
			workloadViolation("MV2001", "eks: no secrets in env vars"),
			workloadViolation("RB1001", "eks: no wildcard verbs"),
			workloadViolation("RB1002", "eks: no wildcard resources"),
			workloadViolation("NV1001", "eks: default-deny NetworkPolicy"),
		},
	}
}

// PCIDSS returns the PCI-DSS compliance preset.
func PCIDSS() Preset {
	return Preset{
		Name:        "pci-dss",
		Description: "PCI-DSS compliance: network segmentation, no secrets in env, least privilege",
		Tags:        []string{"pci-dss", "compliance", "fintech"},
		Violations: []input.Violation{
			workloadViolation("MV1001", "pci-dss: no privileged containers"),
			workloadViolation("MV1002", "pci-dss: no host namespaces"),
			workloadViolation("MV1003", "pci-dss: no hostPath volumes"),
			workloadViolation("MV1007", "pci-dss: readOnlyRootFilesystem required"),
			workloadViolation("MV2001", "pci-dss: no secrets in env vars — Req 3.4"),
			workloadViolation("RB1001", "pci-dss: no wildcard verbs — least privilege — Req 7"),
			workloadViolation("RB1002", "pci-dss: no wildcard resources — Req 7"),
			workloadViolation("RB1003", "pci-dss: no cluster-admin binding — Req 7.1"),
			workloadViolation("NV1001", "pci-dss: default-deny NetworkPolicy — Req 1.3"),
			workloadViolation("IV1001", "pci-dss: require signed images — Req 6.3"),
		},
	}
}
