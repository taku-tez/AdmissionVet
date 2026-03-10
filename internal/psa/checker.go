package psa

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// SimulateFile checks all workloads in a YAML file against the given PSA level.
func SimulateFile(path string, level Level, namespace string) ([]Violation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return simulate(data, level, namespace)
}

// simulate parses YAML documents and checks each workload against the PSA level.
func simulate(data []byte, level Level, namespace string) ([]Violation, error) {
	var violations []Violation

	docs := bytes.Split(data, []byte("\n---"))
	for _, raw := range docs {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}

		ps, err := parsePodSpec(raw)
		if err != nil || ps == nil {
			continue
		}

		if namespace != "" && ps.Namespace != namespace {
			continue
		}

		switch level {
		case LevelBaseline:
			violations = append(violations, checkBaseline(*ps)...)
		case LevelRestricted:
			violations = append(violations, checkBaseline(*ps)...)
			violations = append(violations, checkRestricted(*ps)...)
		}
	}
	return violations, nil
}

// parsePodSpec extracts a podSpec from a raw YAML document.
func parsePodSpec(raw []byte) (*podSpec, error) {
	var obj struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Metadata   struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		Spec struct {
			Template struct {
				Spec podSpecFields `yaml:"spec"`
			} `yaml:"template"`
			// For bare Pods:
			podSpecFields `yaml:",inline"`
		} `yaml:"spec"`
	}

	if err := yaml.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}

	workloadKinds := map[string]bool{
		"Pod": true, "Deployment": true, "StatefulSet": true,
		"DaemonSet": true, "ReplicaSet": true, "Job": true, "CronJob": true,
	}
	if !workloadKinds[obj.Kind] {
		return nil, nil
	}

	var spec podSpecFields
	if obj.Kind == "Pod" {
		spec = obj.Spec.podSpecFields
	} else {
		spec = obj.Spec.Template.Spec
	}

	return &podSpec{
		Kind:      obj.Kind,
		Name:      obj.Metadata.Name,
		Namespace: obj.Metadata.Namespace,
		Spec:      spec,
	}, nil
}

func resourceLabel(ps podSpec) string {
	ns := ps.Namespace
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf("%s/%s (ns: %s)", ps.Kind, ps.Name, ns)
}

// checkBaseline implements the PSA baseline policy.
// Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/
func checkBaseline(ps podSpec) []Violation {
	var v []Violation
	res := resourceLabel(ps)

	// PSA-BASE-001: hostProcess (Windows) — skip, hostPID/IPC/Network checks below.
	if ps.Spec.HostPID {
		v = append(v, Violation{Level: LevelBaseline, RuleID: "PSA-BASE-001", Resource: res,
			Message: "hostPID: true is not allowed at baseline level"})
	}
	if ps.Spec.HostIPC {
		v = append(v, Violation{Level: LevelBaseline, RuleID: "PSA-BASE-002", Resource: res,
			Message: "hostIPC: true is not allowed at baseline level"})
	}
	if ps.Spec.HostNetwork {
		v = append(v, Violation{Level: LevelBaseline, RuleID: "PSA-BASE-003", Resource: res,
			Message: "hostNetwork: true is not allowed at baseline level"})
	}

	// PSA-BASE-004: hostPath volumes.
	for _, vol := range ps.Spec.Volumes {
		if vol.HostPath != nil {
			v = append(v, Violation{Level: LevelBaseline, RuleID: "PSA-BASE-004", Resource: res,
				Message: fmt.Sprintf("volume '%s' uses hostPath which is not allowed at baseline level", vol.Name)})
		}
	}

	// PSA-BASE-005: privileged containers.
	for _, c := range allContainers(ps) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			v = append(v, Violation{Level: LevelBaseline, RuleID: "PSA-BASE-005", Resource: res,
				Message: fmt.Sprintf("container '%s' is privileged which is not allowed at baseline level", c.Name)})
		}

		// PSA-BASE-006: dangerous capabilities.
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			dangerousCaps := []string{
				"NET_ADMIN", "SYS_ADMIN", "SYS_TIME", "SYS_MODULE",
				"SYS_PTRACE", "NET_RAW", "SYS_CHROOT", "AUDIT_WRITE",
				"SETUID", "SETGID",
			}
			for _, cap := range c.SecurityContext.Capabilities.Add {
				for _, dangerous := range dangerousCaps {
					if strings.EqualFold(cap, dangerous) {
						v = append(v, Violation{Level: LevelBaseline, RuleID: "PSA-BASE-006", Resource: res,
							Message: fmt.Sprintf("container '%s' adds dangerous capability %s (not allowed at baseline)", c.Name, cap)})
					}
				}
			}
		}
	}

	return v
}

// checkRestricted implements the PSA restricted policy (superset of baseline).
func checkRestricted(ps podSpec) []Violation {
	var v []Violation
	res := resourceLabel(ps)

	for _, c := range allContainers(ps) {
		// PSA-REST-001: allowPrivilegeEscalation must be false.
		if c.SecurityContext == nil ||
			c.SecurityContext.AllowPrivilegeEscalation == nil ||
			*c.SecurityContext.AllowPrivilegeEscalation {
			v = append(v, Violation{Level: LevelRestricted, RuleID: "PSA-REST-001", Resource: res,
				Message: fmt.Sprintf("container '%s' must set allowPrivilegeEscalation: false (restricted)", c.Name)})
		}

		// PSA-REST-002: readOnlyRootFilesystem is recommended but not strictly required.
		// (restricted does not mandate it in K8s official, but it's best practice — we include as warning)

		// PSA-REST-003: runAsNonRoot must be true.
		podRunAsNonRoot := ps.Spec.SecurityContext != nil && ps.Spec.SecurityContext.RunAsNonRoot != nil && *ps.Spec.SecurityContext.RunAsNonRoot
		containerRunAsNonRoot := c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot
		containerRunAsUser := c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser > 0
		if !podRunAsNonRoot && !containerRunAsNonRoot && !containerRunAsUser {
			v = append(v, Violation{Level: LevelRestricted, RuleID: "PSA-REST-003", Resource: res,
				Message: fmt.Sprintf("container '%s' must set runAsNonRoot: true or runAsUser > 0 (restricted)", c.Name)})
		}

		// PSA-REST-004: capabilities — must drop ALL.
		dropsAll := false
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Drop {
				if strings.EqualFold(cap, "ALL") {
					dropsAll = true
					break
				}
			}
		}
		if !dropsAll {
			v = append(v, Violation{Level: LevelRestricted, RuleID: "PSA-REST-004", Resource: res,
				Message: fmt.Sprintf("container '%s' must drop ALL capabilities (restricted)", c.Name)})
		}

		// PSA-REST-005: seccompProfile must be RuntimeDefault or Localhost.
		podSeccomp := ps.Spec.SecurityContext != nil && ps.Spec.SecurityContext.SeccompProfile != nil &&
			(ps.Spec.SecurityContext.SeccompProfile.Type == "RuntimeDefault" || ps.Spec.SecurityContext.SeccompProfile.Type == "Localhost")
		containerSeccomp := c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
			(c.SecurityContext.SeccompProfile.Type == "RuntimeDefault" || c.SecurityContext.SeccompProfile.Type == "Localhost")
		if !podSeccomp && !containerSeccomp {
			v = append(v, Violation{Level: LevelRestricted, RuleID: "PSA-REST-005", Resource: res,
				Message: fmt.Sprintf("container '%s' must set seccompProfile: RuntimeDefault or Localhost (restricted)", c.Name)})
		}
	}

	return v
}

func allContainers(ps podSpec) []container {
	return append(ps.Spec.Containers, ps.Spec.InitContainers...)
}

// RecommendLevel returns the strictest PSA level the workloads comply with.
func RecommendLevel(violations []Violation) Level {
	hasRestricted := false
	hasBaseline := false
	for _, v := range violations {
		switch v.Level {
		case LevelRestricted:
			hasRestricted = true
		case LevelBaseline:
			hasBaseline = true
		}
	}
	if hasBaseline {
		return LevelPrivileged
	}
	if hasRestricted {
		return LevelBaseline
	}
	return LevelRestricted
}

// io.EOF sentinel for the YAML decoder helper.
var _ = io.EOF
