// Package psa implements Pod Security Admission level simulation.
package psa

// Level represents a PSA enforcement level.
type Level string

const (
	LevelPrivileged Level = "privileged"
	LevelBaseline   Level = "baseline"
	LevelRestricted Level = "restricted"
)

// Violation is a PSA compliance issue found in a workload.
type Violation struct {
	Level     Level
	RuleID    string
	Resource  string
	Namespace string
	Message   string
}

// podSpec is a minimal representation of a Kubernetes pod spec for PSA checking.
type podSpec struct {
	Kind      string
	Name      string
	Namespace string
	Spec      podSpecFields
}

type podSpecFields struct {
	HostPID        bool            `yaml:"hostPID"`
	HostIPC        bool            `yaml:"hostIPC"`
	HostNetwork    bool            `yaml:"hostNetwork"`
	Volumes        []volume        `yaml:"volumes"`
	Containers     []container     `yaml:"containers"`
	InitContainers []container     `yaml:"initContainers"`
	SecurityContext *podSecurity   `yaml:"securityContext"`
	AutomountSAToken *bool         `yaml:"automountServiceAccountToken"`
}

type volume struct {
	Name     string   `yaml:"name"`
	HostPath *struct{} `yaml:"hostPath"`
}

type container struct {
	Name            string           `yaml:"name"`
	Image           string           `yaml:"image"`
	SecurityContext *containerSecurity `yaml:"securityContext"`
}

type containerSecurity struct {
	Privileged               *bool          `yaml:"privileged"`
	AllowPrivilegeEscalation *bool          `yaml:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool          `yaml:"readOnlyRootFilesystem"`
	RunAsNonRoot             *bool          `yaml:"runAsNonRoot"`
	RunAsUser                *int64         `yaml:"runAsUser"`
	Capabilities             *capabilities  `yaml:"capabilities"`
	SeccompProfile           *seccompProfile `yaml:"seccompProfile"`
}

type capabilities struct {
	Add  []string `yaml:"add"`
	Drop []string `yaml:"drop"`
}

type seccompProfile struct {
	Type string `yaml:"type"`
}

type podSecurity struct {
	RunAsNonRoot    *bool          `yaml:"runAsNonRoot"`
	RunAsUser       *int64         `yaml:"runAsUser"`
	SeccompProfile  *seccompProfile `yaml:"seccompProfile"`
	SupplementalGroups *groupRange `yaml:"supplementalGroups"`
	FSGroup         *int64         `yaml:"fsGroup"`
}

type groupRange struct {
	Rule string `yaml:"rule"`
}
