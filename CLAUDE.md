# CLAUDE.md — AdmissionVet Project Context

This file gives AI assistants (Claude Code, Copilot, etc.) the context needed to work
effectively in this repository. Keep it up to date when architecture or conventions change.

---

## What This Project Does

**AdmissionVet** converts Kubernetes security scan violations into admission control policies
that actively **prevent** the violation from reaching the cluster.

```
Scan results (ManifestVet / K8sVet / Trivy k8s)
    ↓ admissionvet generate
OPA/Gatekeeper ConstraintTemplate + Constraint
    OR
Kyverno ClusterPolicy (validate + mutate + generate rules)
    ↓ kubectl apply
Future deployments blocked or mutated at the API server
```

Go module: `github.com/AdmissionVet/admissionvet`

---

## Repository Layout

```
admissionvet/
├── main.go                         # Cobra root command; registers sub-commands
├── cmd/
│   ├── generators.go               # Blank imports — triggers all generator init() calls
│   ├── helpers.go                  # validateEngine, generatePolicies, writePolicies, expandPaths
│   ├── generate.go                 # admissionvet generate
│   ├── library.go                  # admissionvet list-policies / apply
│   ├── webhook.go                  # admissionvet webhook validate/test
│   ├── psa.go                      # admissionvet psa simulate
│   ├── dryrun.go                   # admissionvet dryrun
│   ├── audit.go                    # admissionvet audit (live cluster)
│   ├── drift.go                    # admissionvet drift (local vs cluster)
│   ├── version.go                  # admissionvet version list/rollback
│   └── registry.go                 # admissionvet registry add/list/remove
└── internal/
    ├── input/          # ScanResult, Violation types; JSON loader (native + K8sVet + Trivy)
    ├── exceptions/     # Exception types; wildcard suppression; generic Filter[T]
    ├── policy/         # Generator interface; per-engine registry; GeneratedPolicy
    │   ├── gatekeeper/ # ConstraintTemplate builder; manifestvet/rbacvet/networkvet generators
    │   └── kyverno/    # ClusterPolicy builder; manifestvet/rbacvet/networkvet/imagepolicy generators
    ├── output/         # yaml / helm / kustomize writers
    ├── audit/          # Live cluster check (kubectl exec); findings; drift detection
    ├── dryrun/         # Policy simulation engine; rollout impact analysis
    ├── webhook/        # ValidatingWebhook/MutatingWebhook validator (AV3001–AV4001)
    ├── psa/            # Pod Security Admission level simulation
    ├── library/        # Built-in presets (baseline, restricted, gke-standard, eks-standard, pci-dss)
    ├── versions/       # Policy history tracker; stash-based rollback (last 5)
    └── registry/       # Custom rule loader from ~/.admissionvet/registry/
```

---

## Key Patterns

### 1. Generator Pattern (adding a new rule)

Every rule is a `policy.Generator`:

```go
// internal/policy/types.go
type Generator interface {
    RuleID() string
    Generate(violations []input.Violation, namespace string) (*GeneratedPolicy, error)
}
```

To add a new rule `MV1099`:

**a) Gatekeeper — create `internal/policy/gatekeeper/manifestvet/mv1099.go`:**
```go
package manifestvet

import (...)

func init() { policy.Register("gatekeeper", &mv1099{}) }

type mv1099 struct{}
func (g *mv1099) RuleID() string { return "MV1099" }

const mv1099Rego = `package admissionvet.mv1099
violation[{"msg": msg}] {
  c := input_containers[_]
  // ... Rego logic ...
  msg := sprintf("...", [...])
}
// input_containers helpers (copy from mv1001.go)
`

func (g *mv1099) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
    name, kind := "mv1099", "Mv1099"
    ct, _ := gatekeeper.BuildConstraintTemplate(gatekeeper.ConstraintTemplateParams{
        Name: name, Kind: kind, Description: "...", Rego: mv1099Rego,
        MatchKinds: gatekeeper.WorkloadKinds, APIGroups: "*",
    })
    c, _ := gatekeeper.BuildConstraint(gatekeeper.ConstraintParams{
        Kind: kind, Name: name,
        EnforcementAction: gatekeeper.EnforcementAction(violations),
        APIGroups: "*", MatchKinds: gatekeeper.WorkloadKinds,
    })
    return &policy.GeneratedPolicy{RuleID: g.RuleID(), ConstraintTemplate: ct, Constraint: c}, nil
}
```

**b) Kyverno — add to `internal/policy/kyverno/manifestvet/generators.go`:**
```go
// In init():
policy.Register("kyverno", &mv1099{})

// New type:
type mv1099 struct{}
func (g *mv1099) RuleID() string { return "MV1099" }
func (g *mv1099) Generate(violations []input.Violation, namespace string) (*policy.GeneratedPolicy, error) {
    action := kyverno.ValidationAction(violations)
    body := fmt.Sprintf(`    validate:
      validationFailureAction: %s
      message: "..."
      pattern:
        spec:
          containers:
            - securityContext: ...`, action)
    cp, _ := kyverno.BuildClusterPolicy(kyverno.PolicyParams{
        Name: "mv1099-...", Description: "...",
        Rules: []kyverno.Rule{{
            Name: "...", MatchKinds: kyverno.WorkloadKinds,
            Namespaces: namespaces(namespace),
            Type: kyverno.RuleTypeValidate, Body: body,
        }},
    })
    return &policy.GeneratedPolicy{RuleID: g.RuleID(), ClusterPolicy: cp}, nil
}
```

**c) Audit check — add to `internal/audit/checks.go`:**
```go
// Add to workloadChecks slice:
var workloadChecks = []checkFunc{..., checkMV1099}

func checkMV1099(obj resourceObject) (string, Severity, string) {
    for _, c := range extractContainers(obj) {
        // ... check logic ...
        return "MV1099", SeverityError, fmt.Sprintf("container '%s' ...", name)
    }
    return "", "", ""
}
```

**d) Trivy mapping — add to `internal/input/loader.go`:**
```go
var trivyKSVMap = map[string]string{
    ...
    "KSV099": "MV1099",
}
```

**e) Tests:**
- `internal/audit/checks_test.go` — check function unit tests
- `internal/policy/gatekeeper/manifestvet/generators_test.go` — ConstraintTemplate/Constraint assertions
- `internal/policy/kyverno/manifestvet/generators_test.go` — ClusterPolicy assertions

### 2. Generator Registration via `init()`

`cmd/generators.go` blank-imports every generator package. This file must be updated when
adding a generator in a **new** package. Existing packages (manifestvet, rbacvet, etc.) are
already imported.

### 3. Exception Filtering

```go
// Generic filter — works for any type T
exceptions.Filter(items []T, list ExceptionList, getKey func(T) (ruleID, ns, resource string)) []T
```

All commands that surface findings accept `--exceptions <file>` and call `Filter` before printing.

### 4. RBAC YAML Structure (critical gotcha)

Kubernetes RBAC resources have **top-level** fields, NOT under `spec`:

```yaml
# ClusterRole
rules: [...]          # top-level

# ClusterRoleBinding
roleRef: {...}        # top-level
subjects: [...]       # top-level
```

`resourceObject` in both `audit/checks.go` and `dryrun/runner.go` reflects this:
```go
type resourceObject struct {
    Kind     string         `yaml:"kind"`
    Metadata map[string]any `yaml:"metadata"`
    Spec     map[string]any `yaml:"spec"`
    Rules    []any          `yaml:"rules"`    // ClusterRole/Role
    RoleRef  map[string]any `yaml:"roleRef"`  // ClusterRoleBinding
    Subjects []any          `yaml:"subjects"` // ClusterRoleBinding
}
```

### 5. Severity Model

**Input violations (3 levels):** `error` | `warning` | `info`

**Audit / webhook findings (5 levels):** `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`

`SeverityError` in audit maps to findings that are blocking-class issues.
`SeverityWarning` maps to advisory findings.

---

## Rule ID Conventions

| Prefix | Domain | Examples |
|--------|--------|---------|
| `MV1xxx` | ManifestVet — Pod/container security | MV1001–MV1007 |
| `MV2xxx` | ManifestVet — Data security | MV2001 |
| `RB1xxx` | RBACVet — RBAC rules | RB1001–RB1003 |
| `NV1xxx` | NetworkVet — Network policies | NV1001 |
| `IV1xxx` | ImagePolicy — Image verification | IV1001 |
| `AV3xxx` | ValidatingWebhookConfiguration | AV3001–AV3006 |
| `AV4xxx` | MutatingWebhookConfiguration | AV4001 |
| `CUSTOM-xxx` | User-defined rules (registry) | CUSTOM-001 |

**Current rules:**

| Rule ID | Description | Severity |
|---------|-------------|---------|
| MV1001 | Privileged containers | error |
| MV1002 | hostPID / hostIPC / hostNetwork | error |
| MV1003 | hostPath volumes | error |
| MV1004 | root user (runAsUser:0 / runAsNonRoot:false) | error |
| MV1005 | Dangerous Linux capabilities (NET_ADMIN, SYS_ADMIN, …) | error |
| MV1006 | allowPrivilegeEscalation not set to false | warning/error |
| MV1007 | readOnlyRootFilesystem not set | warning |
| MV2001 | Secret as literal env var value | error |
| RB1001 | Wildcard verb `*` in RBAC role | error |
| RB1002 | Wildcard resource `*` in RBAC role | error |
| RB1003 | cluster-admin binding to non-system:masters | error |
| NV1001 | Namespace missing default-deny NetworkPolicy | error |
| IV1001 | Image not signed with Cosign (Kyverno only) | error |

---

## Test Conventions

- Test files use `package foo_test` (external test package) except for `audit` which uses `package audit`.
- Helper functions: `errViolations(ruleID)`, `warnViolations(ruleID)`, `mustContain(t, yaml, substr)`.
- Each generator test should verify:
  1. Correct YAML kind string appears in output
  2. `validationFailureAction: Enforce` for error violations
  3. `validationFailureAction: Audit` for warning violations
  4. Key policy logic appears (e.g., field name, capability name)
  5. `ConstraintTemplate`/`Constraint` are empty for Kyverno; `ClusterPolicy` is empty for Gatekeeper.
- Run all tests: `go test -race -count=1 ./...`

---

## Input Format Detection (loader.go)

`input.LoadFromFile` auto-detects in this order:
1. **Native AdmissionVet** — `{"violations": [...]}`
2. **Trivy k8s** — `{"ArtifactType": "kubernetes", "Resources": [...]}`
3. **K8sVet unified** — `{"results": [...]}`
4. **Native fallback** — returns empty result without error

Trivy KSV IDs are mapped to AdmissionVet rule IDs via `trivyKSVMap`.
K8sVet rule IDs are normalized via `ruleIDMap` (lowercased key → canonical uppercase ID).

---

## Common Mistakes to Avoid

1. **RBAC fields under `spec`** — `rules`, `roleRef`, `subjects` are top-level, not `spec.rules` etc.
2. **Kyverno `AnyIn` operator** — does exact string matching only (no glob). For pattern matching use `Regex` operator.
3. **Kyverno numeric `value`** — use `value: 0` (integer), not `value: "0"` (string) in deny conditions.
4. **Gatekeeper `object.get` for optional fields** — use `object.get(c, ["securityContext", "privileged"], false)` instead of `c.securityContext.privileged` to handle missing securityContext.
5. **YAML document splitting** — use `bytes.TrimPrefix(data, []byte("---\n"))` before splitting on `"\n---"` to handle files that start with a document separator.

---

## Running / Building

```sh
go build -o admissionvet .
go test -race -count=1 ./...
go vet ./...
```

External tools needed at runtime:
- `kubectl` — only for `audit`, `drift`, and `webhook --cluster` subcommands
