# AdmissionVet

> Shift Kubernetes security from detection to prevention.

AdmissionVet converts scan violations from **ManifestVet**, **RBACVet**, **NetworkVet**, **K8sVet**, and **Trivy** into ready-to-apply [OPA/Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) or [Kyverno](https://kyverno.io/) admission control policies. It also audits live clusters, validates webhook configurations, simulates Pod Security Admission enforcement, and lets you test policies against existing manifests before deploying anything.

---

## Features

| Capability | Command |
|---|---|
| Generate policies from scan results | `admissionvet generate` |
| Apply a built-in policy preset | `admissionvet apply` |
| Browse available presets | `admissionvet list-policies` |
| Audit live cluster for violations | `admissionvet audit` |
| Detect drift between local and cluster | `admissionvet drift` |
| Validate webhook configurations | `admissionvet webhook validate` |
| Test webhook TLS reachability | `admissionvet webhook test` |
| Simulate Pod Security Admission | `admissionvet psa simulate` |
| Dry-run policies against manifests | `admissionvet dryrun` |
| Manage policy version history | `admissionvet version list/rollback` |
| Manage custom rule registry | `admissionvet registry add/list/remove` |

---

## Installation

```sh
go install github.com/AdmissionVet/admissionvet@latest
```

Or build from source:

```sh
git clone https://github.com/AdmissionVet/admissionvet
cd admissionvet
go build -o admissionvet .
```

**Requirements:** Go 1.21+, `kubectl` in `PATH` (only needed for `audit`, `drift`, and `webhook --cluster`)

---

## Quick Start

```sh
# 1. Audit the live cluster directly (no scan file needed)
admissionvet audit --output findings/

# 2. Generate policies from scan output
admissionvet generate --from results.json

# 3. Generate Kyverno policies, packaged as a Helm chart
admissionvet generate --from results.json --engine kyverno --format helm

# 4. Dry-run the generated policies against your manifests
admissionvet dryrun --manifest k8s/ --policy output/

# 5. Apply a built-in preset without a scan file
admissionvet apply --preset restricted --engine kyverno
```

---

## Commands

### `generate` — Generate policies from scan results

```
admissionvet generate --from <scan.json> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--from / -f` | *(required)* | Path to scan results JSON |
| `--engine` | `gatekeeper` | `gatekeeper` or `kyverno` |
| `--severity` | *(all)* | Minimum severity: `error`, `warning`, `info` |
| `--namespace / -n` | *(all)* | Limit to this namespace |
| `--output / -o` | `output` | Output directory |
| `--format` | `yaml` | `yaml`, `helm`, or `kustomize` |
| `--diff` | `false` | Compare generated files with existing output (no write) |
| `--exceptions` | *(none)* | Path to exceptions YAML file |

**Examples:**

```sh
# Only generate policies for error-severity violations
admissionvet generate --from results.json --severity error

# Namespace-scoped Kyverno policies as Kustomize base
admissionvet generate --from results.json --engine kyverno \
  --namespace team-a --format kustomize

# Preview changes without overwriting
admissionvet generate --from results.json --diff --output output/

# Suppress known-acceptable violations
admissionvet generate --from results.json --exceptions exceptions.yaml
```

---

### `audit` — Audit the live cluster

Connects to a Kubernetes cluster via `kubectl` and checks all running workloads, RBAC resources, and NetworkPolicies against the same rules used by `generate`.

```
admissionvet audit [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | `~/.kube/config` | Path to kubeconfig |
| `--context` | *(current)* | Kubernetes context to use |
| `--namespace / -n` | *(all)* | Restrict to this namespace |
| `--output / -o` | `output` | Directory to write JSON results |
| `--exceptions` | *(none)* | Path to exceptions YAML file |

**Output:**

```
Resources scanned: 84
Findings        : 5

Namespace: production (3 finding(s))
  SEVERITY  RULE    KIND        NAME     MESSAGE
  --------  ----    ----        ----     -------
  ERROR     MV1001  Deployment  nginx    container 'nginx' is running as privileged
  ERROR     MV1006  Deployment  api      container 'api' missing allowPrivilegeEscalation: false
  WARNING   MV1007  Deployment  worker   container 'worker' readOnlyRootFilesystem is not true

--- Summary by Rule ---
RULE    COUNT
MV1001  1
MV1006  1
MV1007  1
```

Exits with code `1` when any `error`-severity finding is present.

---

### `drift` — Detect policy drift

Compares locally generated policy files with the policies actually deployed in the cluster.

```
admissionvet drift [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output / -o` | `output` | Directory containing local policy files |
| `--engine` | `gatekeeper` | `gatekeeper` or `kyverno` |
| `--format` | `table` | Output format: `table` or `json` |
| `--kubeconfig` | `~/.kube/config` | Path to kubeconfig |
| `--context` | *(current)* | Kubernetes context to use |

**Table output (default):**

```
Drift detected: 1 new, 0 changed, 1 missing

STATUS     POLICY               MESSAGE
------     ------               -------
[NEW]      mv1004-constraint    generated locally but not deployed to cluster
[MISSING]  rb1003-constraint    deployed in cluster but not in output directory
```

**JSON output (`--format json`):**

```json
{
  "engine": "gatekeeper",
  "summary": {
    "total": 2,
    "new": 1,
    "changed": 0,
    "missing": 1
  },
  "findings": [
    {
      "policy_name": "mv1004-constraint",
      "status": "new",
      "message": "policy is generated locally but not deployed to the cluster"
    },
    {
      "policy_name": "rb1003-constraint",
      "status": "missing",
      "message": "policy is deployed in cluster but not present in output directory"
    }
  ]
}
```

---

### `apply` — Apply a built-in policy preset

```
admissionvet apply --preset <name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--preset` | *(required)* | Preset name (see below) |
| `--engine` | `gatekeeper` | `gatekeeper` or `kyverno` |
| `--namespace / -n` | *(all)* | Limit to this namespace |
| `--output / -o` | `output` | Output directory |
| `--format` | `yaml` | `yaml`, `helm`, or `kustomize` |

```sh
admissionvet apply --preset baseline --engine gatekeeper
admissionvet apply --preset pci-dss --engine kyverno --format helm
```

---

### `list-policies` — Browse built-in presets

```sh
admissionvet list-policies
```

| Preset | Rules |
|--------|-------|
| `baseline` | MV1001 MV1002 MV1003 RB1001 RB1002 NV1001 |
| `restricted` | MV1001 MV1002 MV1003 MV1004 MV1005 MV1006 MV1007 MV2001 RB1001 RB1002 RB1003 NV1001 |
| `gke-standard` | MV1001 MV1002 MV1003 MV1004 MV1006 MV1007 MV2001 RB1001 RB1003 NV1001 IV1001 |
| `eks-standard` | MV1001 MV1002 MV1003 MV1004 MV1006 MV1007 MV2001 RB1001 RB1002 NV1001 |
| `pci-dss` | MV1001 MV1002 MV1003 MV1004 MV1005 MV1006 MV1007 MV2001 RB1001 RB1002 RB1003 NV1001 IV1001 |

---

### `webhook validate` — Audit webhook configurations

```
admissionvet webhook validate [--from <file> | --cluster] [flags]
```

| Flag | Description |
|------|-------------|
| `--from / -f` | Path to webhook configuration YAML |
| `--cluster` | Fetch from the live cluster via `kubectl` |
| `--severity` | Filter output: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |

**Detected issues:**

| Rule | Severity | Description |
|------|----------|-------------|
| AV3001 | CRITICAL | `failurePolicy: Ignore` — webhook can be bypassed |
| AV3002 | HIGH | `timeoutSeconds < 10` — false failures under load |
| AV3003 | MEDIUM | No `kube-system` exclusion in `namespaceSelector` |
| AV3005 | CRITICAL | TLS certificate expiring within 30 days |
| AV3006 | CRITICAL | Invalid TLS certificate chain |
| AV4001 | MEDIUM | `reinvocationPolicy: IfNeeded` without idempotency guarantee |

Exits with code `1` when any `error`/`CRITICAL`-severity finding is present.

```sh
admissionvet webhook validate --from webhook.yaml
admissionvet webhook validate --cluster --severity HIGH
```

---

### `webhook test` — Test endpoint reachability

Tests TLS connectivity to each webhook service and reports latency.

```sh
admissionvet webhook test --from webhook.yaml
```

---

### `psa simulate` — Pod Security Admission simulation

Checks existing workloads against a PSA level before you label a namespace.

```
admissionvet psa simulate --from <file|dir> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--from / -f` | *(required)* | Manifest YAML file or directory |
| `--level` | `baseline` | `baseline` or `restricted` |
| `--namespace / -n` | *(all)* | Scope simulation to this namespace |

```sh
admissionvet psa simulate --from manifests/ --level restricted
```

If violations are found, the command prints them, recommends a safe PSA level, and exits with code `1`.

---

### `dryrun` — Simulate policies against manifests

Evaluates resources against generated policies without touching the cluster.

```
admissionvet dryrun --manifest <file|dir> --policy <file|dir> [flags]
```

| Flag | Description |
|------|-------------|
| `--manifest / -m` | Manifest file or directory (repeatable) |
| `--policy / -p` | Policy file or directory (repeatable) |
| `--exceptions` | Path to exceptions YAML file |

```sh
admissionvet dryrun --manifest k8s/ --policy output/
admissionvet dryrun --manifest k8s/ --policy output/ --exceptions exceptions.yaml
```

Output includes:
- Per-namespace hit table (BLOCK / WARN per resource)
- **Rollout impact** — Deployments/StatefulSets that would fail to roll out with replica counts
- **Migration plan** — guided warn → fix → enforce steps

---

### `version` — Manage policy version history

```sh
admissionvet version list --output output/
admissionvet version rollback --output output/ --to 2
```

---

### `registry` — Custom policy rules

Store organisation-specific rules in `~/.admissionvet/registry/`. Rules are loaded automatically by `generate` and `apply`.

```sh
admissionvet registry add --file my-rule.yaml
admissionvet registry list
admissionvet registry remove --rule-id CUSTOM001
```

**Custom rule YAML format:**

```yaml
rule_id: CUSTOM001
engine: kyverno          # or gatekeeper
description: "Require imagePullPolicy: Always"
match_kinds: [Pod, Deployment]
severity: error
validate_message: "imagePullPolicy must be Always"
validate_pattern: |
  spec:
    containers:
      - imagePullPolicy: Always
```

---

## Exceptions

Any command that surfaces findings accepts an `--exceptions` flag pointing to a YAML file.
Matched findings are suppressed from output and exit-code calculation.

```yaml
# exceptions.yaml
exceptions:
  # Suppress a specific rule in a specific namespace
  - ruleID: MV1001
    namespace: kube-system
    reason: "CNI plugin requires privileged containers"

  # Suppress all rules for a specific resource
  - resource: "Deployment/legacy-app"
    reason: "Scheduled for migration — JIRA: INFRA-4210"

  # Suppress all rules in a namespace (wildcard)
  - namespace: monitoring
    reason: "Prometheus node-exporter requires host access"
```

Field matching is case-insensitive. Empty fields act as wildcards.

---

## Input Formats

AdmissionVet auto-detects three scan result formats:

**Native format**
```json
{
  "violations": [
    {
      "rule_id": "MV1001",
      "resource": "Deployment/nginx",
      "namespace": "default",
      "severity": "error",
      "message": "Container nginx is privileged"
    }
  ]
}
```

**K8sVet unified format** (`{"results": [...]}`) — rule IDs are normalised automatically.

**Trivy k8s JSON** (`trivy k8s -f json`) — KSV IDs are mapped to AdmissionVet rule IDs automatically.

```sh
trivy k8s --report summary -f json cluster > trivy-results.json
admissionvet generate --from trivy-results.json --engine kyverno
```

---

## Output Formats

| Format | Structure |
|--------|-----------|
| `yaml` | Flat YAML files in `output/` |
| `helm` | Helm chart under `output/helm/` with `Chart.yaml`, `values.yaml`, and categorised templates |
| `kustomize` | Kustomize base + production overlay under `output/kustomize/` |

---

## Rule Reference

### ManifestVet — Container / Pod security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| MV1001 | error | Privileged container (`privileged: true`) |
| MV1002 | error | Host namespace sharing (`hostPID` / `hostIPC` / `hostNetwork`) |
| MV1003 | error | `hostPath` volume mount |
| MV1004 | error | Running as root (`runAsUser: 0` or `runAsNonRoot: false`) |
| MV1005 | error | Dangerous Linux capability added (`SYS_ADMIN`, `NET_ADMIN`, `ALL`, …) |
| MV1006 | warning/error | `allowPrivilegeEscalation` not set to `false` |
| MV1007 | warning | `readOnlyRootFilesystem` not set to `true` |
| MV2001 | error | Secret value written as literal env var |

### RBACVet — Access control

| Rule ID | Severity | Description |
|---------|----------|-------------|
| RB1001 | error | Wildcard verb `*` in RBAC role |
| RB1002 | error | Wildcard resource `*` in RBAC role |
| RB1003 | error | `cluster-admin` binding to non-`system:masters` subjects |

### NetworkVet — Network segmentation

| Rule ID | Severity | Description |
|---------|----------|-------------|
| NV1001 | error | Namespace missing a default-deny-all NetworkPolicy |

### ImagePolicy (Kyverno only)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| IV1001 | error | Image not signed with Cosign |

### Webhook rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| AV3001 | CRITICAL | `failurePolicy: Ignore` |
| AV3002 | HIGH | `timeoutSeconds < 10` |
| AV3003 | MEDIUM | Missing `kube-system` namespace exclusion |
| AV3005 | CRITICAL | TLS certificate expiring within 30 days |
| AV3006 | CRITICAL | Invalid TLS certificate chain |
| AV4001 | MEDIUM | `reinvocationPolicy: IfNeeded` |

**Kyverno mutate rules** (auto-remediation, generated alongside validate rules):

| Rule ID | Action |
|---------|--------|
| MV1001-MUTATE | Sets `privileged: false` |
| MV1007-MUTATE | Sets `readOnlyRootFilesystem: true` |
| MV-MUTATE-AUTOMOUNT | Sets `automountServiceAccountToken: false` |
| MV-MUTATE-IMAGEPULL | Sets `imagePullPolicy: Always` |

---

## Architecture

```
admissionvet/
├── main.go                        # Root cobra command
├── cmd/                           # CLI layer
│   ├── generators.go              # Side-effect imports — registers all built-in generators
│   ├── helpers.go                 # Shared helpers
│   ├── generate.go                # admissionvet generate
│   ├── library.go                 # admissionvet list-policies / apply
│   ├── webhook.go                 # admissionvet webhook validate/test
│   ├── psa.go                     # admissionvet psa simulate
│   ├── dryrun.go                  # admissionvet dryrun
│   ├── audit.go                   # admissionvet audit
│   ├── drift.go                   # admissionvet drift
│   ├── version.go                 # admissionvet version list/rollback
│   └── registry.go                # admissionvet registry add/list/remove
└── internal/
    ├── input/                     # ScanResult / Violation types, JSON loader, format detection
    ├── exceptions/                # Exception types, wildcard matching, generic Filter[T]
    ├── policy/                    # Generator interface + per-engine registry
    │   ├── gatekeeper/            # ConstraintTemplate + Constraint builders
    │   │   ├── manifestvet/       # MV1001–MV1007, MV2001
    │   │   ├── rbacvet/           # RB1001–RB1003
    │   │   └── networkvet/        # NV1001
    │   └── kyverno/               # ClusterPolicy builder
    │       ├── manifestvet/       # validate + mutate rules (MV1001–MV2001)
    │       ├── rbacvet/           # RB1001–RB1003
    │       ├── networkvet/        # NV1001 generate rule
    │       └── imagepolicy/       # IV1001 verifyImages rule
    ├── output/                    # yaml / helm / kustomize writers
    ├── audit/                     # Live cluster checks via kubectl; drift detection
    ├── dryrun/                    # Policy simulation engine; rollout impact analysis
    ├── webhook/                   # Webhook validator (AV3001–AV4001) + TLS checker
    ├── psa/                       # PSA level simulation
    ├── library/                   # Built-in presets
    ├── versions/                  # History tracker; stash-based rollback
    └── registry/                  # Custom rule loader from ~/.admissionvet/registry/
```

### Policy Generator Pattern

Every rule is a `Generator` implementation:

```go
type Generator interface {
    RuleID() string
    Generate(violations []Violation, namespace string) (*GeneratedPolicy, error)
}
```

Generators self-register via `init()`:

```go
func init() { policy.Register("gatekeeper", &mv1001{}) }
```

`cmd/generators.go` imports all generator packages as side-effects to trigger registration before any command runs.

---

## License

MIT
