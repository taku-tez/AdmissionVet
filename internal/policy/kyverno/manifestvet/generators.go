// Package manifestvet provides Kyverno ClusterPolicy generators for ManifestVet violations.
// Each generator creates both validate rules (block bad configs) and mutate rules (fix defaults).
package manifestvet

import (
	"fmt"
	"strings"

	"github.com/AdmissionVet/admissionvet/internal/input"
	"github.com/AdmissionVet/admissionvet/internal/policy"
	kyverno "github.com/AdmissionVet/admissionvet/internal/policy/kyverno"
)

func init() {
	policy.Register("kyverno", &mv1001{})
	policy.Register("kyverno", &mv1002{})
	policy.Register("kyverno", &mv1003{})
	policy.Register("kyverno", &mv1007{})
	policy.Register("kyverno", &mv2001{})
	// Mutate generators (same rule IDs with "-mutate" suffix — registered separately)
	policy.Register("kyverno", &mv1007Mutate{})
	policy.Register("kyverno", &mvAutomount{})
	policy.Register("kyverno", &mvImagePullPolicy{})
}

func namespaces(ns string) []string {
	if ns == "" {
		return nil
	}
	return []string{ns}
}

// ── MV1001: privileged コンテナ禁止 (validate) ───────────────────────────────

type mv1001 struct{}

func (g *mv1001) RuleID() string { return "MV1001" }

func (g *mv1001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "Privileged containers are not allowed (MV1001). Remove securityContext.privileged: true."
      pattern:
        spec:
          =(initContainers):
            - =(securityContext):
                =(privileged): "false"
          containers:
            - =(securityContext):
                =(privileged): "false"`, action)

	mutateBody := `    mutate:
      patchStrategicMerge:
        spec:
          containers:
            - (name): "*"
              securityContext:
                privileged: false`

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "mv1001-no-privileged",
		Description: "Prohibits privileged containers (MV1001)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-privileged-containers",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
			{
				Name:       "set-privileged-false",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeMutate,
				Body:       mutateBody,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── MV1002: hostPID/hostIPC/hostNetwork 禁止 (validate) ─────────────────────

type mv1002 struct{}

func (g *mv1002) RuleID() string { return "MV1002" }

func (g *mv1002) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "hostPID, hostIPC, and hostNetwork are not allowed (MV1002)."
      pattern:
        spec:
          =(hostPID): "false"
          =(hostIPC): "false"
          =(hostNetwork): "false"`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "mv1002-no-host-namespaces",
		Description: "Prohibits hostPID, hostIPC, and hostNetwork (MV1002)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-host-namespaces",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── MV1003: hostPath マウント禁止 (validate) ─────────────────────────────────

type mv1003 struct{}

func (g *mv1003) RuleID() string { return "MV1003" }

func (g *mv1003) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "hostPath volumes are not allowed (MV1003). Use emptyDir or PVC instead."
      deny:
        conditions:
          any:
            - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
              operator: GreaterThan
              value: "0"`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "mv1003-no-hostpath",
		Description: "Prohibits hostPath volume mounts (MV1003)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-hostpath-volumes",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── MV1007: readOnlyRootFilesystem 強制 (validate + mutate) ─────────────────

type mv1007 struct{}

func (g *mv1007) RuleID() string { return "MV1007" }

func (g *mv1007) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	validateBody := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "Containers must set readOnlyRootFilesystem: true (MV1007)."
      pattern:
        spec:
          containers:
            - securityContext:
                readOnlyRootFilesystem: true`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "mv1007-readonly-rootfs",
		Description: "Requires readOnlyRootFilesystem: true on all containers (MV1007)",
		Rules: []kyverno.Rule{
			{
				Name:       "require-readonly-rootfs",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeValidate,
				Body:       validateBody,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// mv1007Mutate auto-sets readOnlyRootFilesystem: true on containers missing the setting.
type mv1007Mutate struct{}

func (g *mv1007Mutate) RuleID() string { return "MV1007-MUTATE" }

func (g *mv1007Mutate) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	body := `    mutate:
      patchStrategicMerge:
        spec:
          containers:
            - (name): "*"
              securityContext:
                readOnlyRootFilesystem: true
          =(initContainers):
            - (name): "*"
              securityContext:
                readOnlyRootFilesystem: true`

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "mv1007-set-readonly-rootfs",
		Description: "Auto-sets readOnlyRootFilesystem: true on containers that do not set it (MV1007 mutate)",
		Rules: []kyverno.Rule{
			{
				Name:       "set-readonly-rootfs",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeMutate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── MV2001: env への Secret 直書き禁止 (validate) ────────────────────────────

type mv2001 struct{}

func (g *mv2001) RuleID() string { return "MV2001" }

func (g *mv2001) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	action := kyverno.ValidationAction(violations)
	body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "Secrets must not be set as literal env values (MV2001). Use secretKeyRef instead."
      foreach:
        - list: "request.object.spec.containers"
          foreach:
            - list: "element.env"
              deny:
                conditions:
                  all:
                    - key: "{{ element.value }}"
                      operator: NotEquals
                      value: ""
                    - key: "{{ element.name }}"
                      operator: AnyIn
                      value:
                        - "*PASSWORD*"
                        - "*SECRET*"
                        - "*TOKEN*"
                        - "*KEY*"
                        - "*CREDENTIAL*"
                        - "*AUTH*"`, action)

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "mv2001-no-secret-env",
		Description: "Prohibits secret values written directly to env vars (MV2001)",
		Rules: []kyverno.Rule{
			{
				Name:       "deny-secret-env-values",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeValidate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── MUTATE: automountServiceAccountToken: false の自動設定 ───────────────────

type mvAutomount struct{}

func (g *mvAutomount) RuleID() string { return "MV-MUTATE-AUTOMOUNT" }

func (g *mvAutomount) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	body := `    mutate:
      patchStrategicMerge:
        spec:
          automountServiceAccountToken: false`

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "set-automount-service-account-token-false",
		Description: "Auto-sets automountServiceAccountToken: false on pods that do not specify it",
		Rules: []kyverno.Rule{
			{
				Name:       "set-automount-false",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeMutate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}

// ── MUTATE: imagePullPolicy: Always の強制 ───────────────────────────────────

type mvImagePullPolicy struct{}

func (g *mvImagePullPolicy) RuleID() string { return "MV-MUTATE-IMAGEPULL" }

func (g *mvImagePullPolicy) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
	_ = strings.ToLower // used for consistency

	body := `    mutate:
      patchStrategicMerge:
        spec:
          containers:
            - (name): "*"
              imagePullPolicy: Always
          =(initContainers):
            - (name): "*"
              imagePullPolicy: Always`

	cp, err := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
		Name:        "enforce-image-pull-policy-always",
		Description: "Enforces imagePullPolicy: Always on all containers",
		Rules: []kyverno.Rule{
			{
				Name:       "set-image-pull-policy-always",
				MatchKinds: kyverno.WorkloadKinds,
				Namespaces: namespaces(namespace),
				Type:       kyverno.RuleTypeMutate,
				Body:       body,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}
