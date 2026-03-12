package dryrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Fixture helpers ──────────────────────────────────────────────────────────

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

const privilegedDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:latest
          securityContext:
            privileged: true
`

const safeDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-app
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: app:latest
          securityContext:
            privileged: false
            readOnlyRootFilesystem: true
`

const hostPathDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: logger
  namespace: logging
spec:
  replicas: 2
  template:
    spec:
      volumes:
        - name: logs
          hostPath:
            path: /var/log
      containers:
        - name: logger
          image: logger:latest
`

const kyvernoMV1001Policy = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: mv1001-no-privileged
spec:
  rules:
    - name: deny-privileged
      match:
        any:
          - resources:
              kinds:
                - Deployment
      validate:
        validationFailureAction: Enforce
        message: "no privileged"
`

const gatekeeperMV1003Constraint = `apiVersion: constraints.gatekeeper.sh/v1beta1
kind: Mv1003
metadata:
  name: mv1003
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: ["*"]
        kinds:
          - Deployment
`

// ── Tests ────────────────────────────────────────────────────────────────────

func TestRunFromFiles_PrivilegedBlocked(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeFile(t, dir, "deploy.yaml", privilegedDeployment)
	policyPath := writeFile(t, dir, "policy.yaml", kyvernoMV1001Policy)

	result, err := RunFromFiles([]string{manifestPath}, []string{policyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Hits) == 0 {
		t.Fatal("expected at least one policy hit for privileged container")
	}
	hit := result.Hits[0]
	if hit.Action != "block" {
		t.Errorf("want action=block, got %s", hit.Action)
	}
	if hit.Resource.Name != "nginx" {
		t.Errorf("want resource nginx, got %s", hit.Resource.Name)
	}
}

func TestRunFromFiles_SafeDeployment_NoHits(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeFile(t, dir, "safe.yaml", safeDeployment)
	policyPath := writeFile(t, dir, "policy.yaml", kyvernoMV1001Policy)

	result, err := RunFromFiles([]string{manifestPath}, []string{policyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The safe deployment has privileged:false — should not match the privileged check.
	for _, h := range result.Hits {
		if strings.Contains(h.Policy, "mv1001") {
			t.Errorf("safe deployment should not trigger mv1001, got hit: %+v", h)
		}
	}
}

func TestRunFromFiles_GatekeeperConstraint(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeFile(t, dir, "deploy.yaml", hostPathDeployment)
	policyPath := writeFile(t, dir, "constraint.yaml", gatekeeperMV1003Constraint)

	result, err := RunFromFiles([]string{manifestPath}, []string{policyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Hits) == 0 {
		t.Fatal("expected hostPath hit")
	}
	if result.Hits[0].Action != "block" {
		t.Errorf("want block, got %s", result.Hits[0].Action)
	}
}

func TestRunFromFiles_RolloutImpact(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeFile(t, dir, "deploy.yaml", privilegedDeployment)
	policyPath := writeFile(t, dir, "policy.yaml", kyvernoMV1001Policy)

	result, err := RunFromFiles([]string{manifestPath}, []string{policyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RolloutImpacts) == 0 {
		t.Fatal("expected rollout impact for blocked Deployment")
	}
	impact := result.RolloutImpacts[0]
	if impact.Replicas != 3 {
		t.Errorf("want 3 replicas, got %d", impact.Replicas)
	}
}

func TestRunFromFiles_EmptyManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeFile(t, dir, "empty.yaml", "")
	policyPath := writeFile(t, dir, "policy.yaml", kyvernoMV1001Policy)

	result, err := RunFromFiles([]string{manifestPath}, []string{policyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Hits) != 0 {
		t.Errorf("want 0 hits for empty manifest, got %d", len(result.Hits))
	}
}

func TestRunFromFiles_MultipleManifests(t *testing.T) {
	dir := t.TempDir()
	path1 := writeFile(t, dir, "priv.yaml", privilegedDeployment)
	path2 := writeFile(t, dir, "safe.yaml", safeDeployment)
	policyPath := writeFile(t, dir, "policy.yaml", kyvernoMV1001Policy)

	result, err := RunFromFiles([]string{path1, path2}, []string{policyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalResources != 2 {
		t.Errorf("want 2 total resources, got %d", result.TotalResources)
	}
}

func TestSimulationResult_BlockCount(t *testing.T) {
	result := &SimulationResult{
		Hits: []PolicyHit{
			{Resource: ResourceSummary{Namespace: "default", Kind: "Deployment", Name: "app"}, Action: "block"},
			{Resource: ResourceSummary{Namespace: "default", Kind: "Deployment", Name: "app"}, Action: "block"}, // same resource
			{Resource: ResourceSummary{Namespace: "default", Kind: "Deployment", Name: "other"}, Action: "block"},
			{Resource: ResourceSummary{Namespace: "default", Kind: "Deployment", Name: "warned"}, Action: "warn"},
		},
	}
	if got := result.BlockCount(); got != 2 {
		t.Errorf("want BlockCount=2 (deduped), got %d", got)
	}
}

func TestSimulationResult_Summary(t *testing.T) {
	result := &SimulationResult{
		Hits: []PolicyHit{
			{Resource: ResourceSummary{Namespace: "default"}, Action: "block"},
			{Resource: ResourceSummary{Namespace: "default"}, Action: "warn"},
			{Resource: ResourceSummary{Namespace: "production"}, Action: "block"},
			{Resource: ResourceSummary{Namespace: ""}, Action: "block"}, // empty → "default"
		},
	}
	summary := result.Summary()
	if len(summary["default"]) != 3 {
		t.Errorf("want 3 hits in default (including empty namespace), got %d", len(summary["default"]))
	}
	if len(summary["production"]) != 1 {
		t.Errorf("want 1 hit in production, got %d", len(summary["production"]))
	}
}

func TestRunFromFiles_MissingManifest(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", kyvernoMV1001Policy)

	_, err := RunFromFiles([]string{"/nonexistent/manifest.yaml"}, []string{policyPath})
	if err == nil {
		t.Fatal("expected error for missing manifest file")
	}
}

func TestRunFromFiles_MissingPolicy(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeFile(t, dir, "deploy.yaml", privilegedDeployment)

	_, err := RunFromFiles([]string{manifestPath}, []string{"/nonexistent/policy.yaml"})
	if err == nil {
		t.Fatal("expected error for missing policy file")
	}
}
