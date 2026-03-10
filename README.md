# AdmissionVet

> Shift Kubernetes security from detection to prevention.

AdmissionVet converts scan violations from **ManifestVet**, **RBACVet**, and **NetworkVet** into ready-to-apply [OPA/Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) or [Kyverno](https://kyverno.io/) admission control policies. It also validates webhook configurations, simulates Pod Security Admission enforcement, and lets you test policies against existing manifests before deploying anything.

---

## Features

| Capability | Command |
|---|---|
| Generate policies from scan results | `admissionvet generate` |
| Apply a built-in policy preset | `admissionvet apply` |
| Browse available presets | `admissionvet list-policies` |
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

**Requirements:** Go 1.21+, `kubectl` in `PATH` (only needed for `--cluster` flags)

---

## Quick Start

```sh
# 1. Run your scanner and save the output
#    (ManifestVet, RBACVet, NetworkVet, or K8sVet — all formats supported)

# 2. Generate Gatekeeper policies (default)
admissionvet generate --from results.json

# 3. Generate Kyverno policies, packaged as a Helm chart
admissionvet generate --from results.json --engine kyverno --format helm

# 4. Apply a built-in preset without a scan file
admissionvet apply --preset restricted --engine kyverno

# 5. Dry-run the generated policies against your live manifests
admissionvet dryrun --manifest k8s/ --policy output/
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

**Examples:**

```sh
# Only generate policies for critical violations
admissionvet generate --from results.json --severity error

# Namespace-scoped Kyverno policies as Kustomize base
admissionvet generate --from results.json --engine kyverno \
  --namespace team-a --format kustomize

# Preview changes without overwriting
admissionvet generate --from results.json --diff --output output/
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

| Preset | Tags | Rules |
|--------|------|-------|
| `baseline` | cis, general | MV1001 MV1002 MV1003 RB1001 RB1002 NV1001 |
| `restricted` | strict, zero-trust | MV1001 MV1002 MV1003 MV1007 MV2001 RB1001 RB1002 RB1003 NV1001 |
| `gke-standard` | gke, google-cloud | MV1001 MV1002 MV1003 MV1007 MV2001 RB1001 RB1003 NV1001 IV1001 |
| `eks-standard` | eks, aws | MV1001 MV1002 MV1003 MV1007 MV2001 RB1001 RB1002 NV1001 |
| `pci-dss` | pci-dss, compliance, fintech | MV1001 MV1002 MV1003 MV1007 MV2001 RB1001 RB1002 RB1003 NV1001 IV1001 |

---

### `webhook validate` — Audit webhook configurations

Checks `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration` for misconfigurations.

```
admissionvet webhook validate [--from <file> | --cluster] [flags]
```

| Flag | Description |
|------|-------------|
| `--from / -f` | Path to webhook configuration YAML |
| `--cluster` | Fetch from the live cluster via `kubectl` |
| `--severity` | Filter output: `error`, `warning`, `info` |

**Detected issues:**

| Rule | Severity | Description |
|------|----------|-------------|
| AV3001 | error | `failurePolicy: Ignore` — webhook can be bypassed |
| AV3002 | warning | `timeoutSeconds < 10` — false failures under load |
| AV3003 | warning | No `kube-system` exclusion in `namespaceSelector` |
| AV3005 | error | TLS certificate expiring within 30 days |
| AV3006 | error | Invalid TLS certificate chain |
| AV4001 | warning | `reinvocationPolicy: IfNeeded` without idempotency guarantee |

Exits with code 1 when any `error`-severity finding is present.

```sh
admissionvet webhook validate --from webhook.yaml
admissionvet webhook validate --cluster --severity error
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

If violations are found, the command prints them, recommends a safe PSA level, and exits with code 1.

---

### `dryrun` — Simulate policies against manifests

Evaluates resources against generated policies without touching the cluster.

```
admissionvet dryrun --manifest <file|dir> --policy <file|dir> [...]
```

```sh
admissionvet dryrun --manifest k8s/ --policy output/
```

Output includes:
- Per-namespace hit table (BLOCK / WARN per resource)
- **Rollout impact** — Deployments/StatefulSets that would fail to roll out, with replica counts
- **Migration plan** — guided warn → fix → enforce steps

---

### `version` — Manage policy version history

```sh
# List generation history for an output directory
admissionvet version list --output output/

# Roll back to a previous version (last 5 stashed)
admissionvet version rollback --output output/ --to 2
```

---

### `registry` — Custom policy rules

Store organisation-specific rules in `~/.admissionvet/registry/`. Rules are loaded automatically by `generate` and `apply`.

```sh
# Add a rule
admissionvet registry add --file my-rule.yaml

# List all registered rules
admissionvet registry list

# Remove a rule
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

For Gatekeeper, use a `rego` field instead of `validate_pattern`. For mutating rules, add a `mutate_patch` field.

---

## Rule Reference

| Rule ID | Domain | Description |
|---------|--------|-------------|
| MV1001 | ManifestVet | Privileged containers |
| MV1002 | ManifestVet | hostPID / hostIPC / hostNetwork |
| MV1003 | ManifestVet | hostPath volumes |
| MV1007 | ManifestVet | readOnlyRootFilesystem not set |
| MV2001 | ManifestVet | Secret exposed in environment variable |
| RB1001 | RBACVet | Wildcard verb in RBAC rule |
| RB1002 | RBACVet | Wildcard resource in RBAC rule |
| RB1003 | RBACVet | cluster-admin binding |
| NV1001 | NetworkVet | Missing default-deny NetworkPolicy |
| IV1001 | ImagePolicy | Cosign image signature verification |

**Kyverno-only mutate rules** (auto-remediation, generated alongside validate rules):

| Rule ID | Action |
|---------|--------|
| MV1001-MUTATE | Sets `privileged: false` |
| MV1007-MUTATE | Sets `readOnlyRootFilesystem: true` |
| MV-MUTATE-AUTOMOUNT | Sets `automountServiceAccountToken: false` |
| MV-MUTATE-IMAGEPULL | Sets `imagePullPolicy: Always` |

---

## Input Formats

AdmissionVet auto-detects two scan result formats:

**Native format** (`{"violations": [...]}`)
```json
{
  "violations": [
    {
      "rule_id": "MV1001",
      "resource": "default/pod/nginx",
      "namespace": "default",
      "severity": "error",
      "message": "Container nginx is privileged"
    }
  ]
}
```

**K8sVet unified format** (`{"results": [...]}`) — rule IDs are normalised automatically.

---

## Output Formats

| Format | Structure |
|--------|-----------|
| `yaml` | Flat YAML files in `output/` |
| `helm` | Helm chart under `output/helm/` with `Chart.yaml`, `values.yaml`, and categorised templates |
| `kustomize` | Kustomize base + production overlay under `output/kustomize/` |

---

## Architecture

```
admissionvet/
├── main.go                        # Root cobra command
├── cmd/                           # CLI layer
│   ├── generators.go              # Side-effect imports — registers all built-in generators
│   ├── helpers.go                 # Shared helpers: validateEngine, generatePolicies, writePolicies, expandPaths
│   ├── generate.go                # admissionvet generate
│   ├── library.go                 # admissionvet list-policies / apply
│   ├── webhook.go                 # admissionvet webhook validate/test
│   ├── psa.go                     # admissionvet psa simulate
│   ├── dryrun.go                  # admissionvet dryrun
│   ├── version.go                 # admissionvet version list/rollback
│   └── registry.go                # admissionvet registry add/list/remove
└── internal/
    ├── input/                     # ScanResult / Violation types, JSON loader, filters
    ├── policy/                    # Generator interface + per-engine registry
    │   ├── gatekeeper/            # ConstraintTemplate + Constraint builders
    │   │   ├── manifestvet/       # MV1001–MV2001
    │   │   ├── rbacvet/           # RB1001–RB1003
    │   │   └── networkvet/        # NV1001
    │   └── kyverno/               # ClusterPolicy builder
    │       ├── manifestvet/       # validate + mutate rules
    │       ├── rbacvet/           # RB1001–RB1003
    │       ├── networkvet/        # NV1001 generate rule
    │       └── imagepolicy/       # IV1001 verifyImages rule
    ├── output/                    # yaml / helm / kustomize writers
    ├── webhook/                   # Webhook validator + reachability tester
    ├── psa/                       # PSA level checker
    ├── dryrun/                    # Policy simulation engine
    ├── library/                   # Built-in presets
    ├── versions/                  # Version history + stash/rollback
    └── registry/                  # Custom rule loader + registrar
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
