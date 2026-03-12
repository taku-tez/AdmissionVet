package audit

import (
	"bytes"
	"fmt"
	"os/exec"
)

// kubectlGet runs kubectl get <resource> and returns the raw YAML output.
func kubectlGet(opts Options, resource string, allNamespaces bool) ([]byte, error) {
	args := []string{"get", resource, "-o", "yaml"}

	if opts.Kubeconfig != "" {
		args = append(args, "--kubeconfig", opts.Kubeconfig)
	}
	if opts.Context != "" {
		args = append(args, "--context", opts.Context)
	}

	if allNamespaces || opts.Namespace == "" {
		args = append(args, "--all-namespaces")
	} else {
		args = append(args, "-n", opts.Namespace)
	}

	var stderr bytes.Buffer
	cmd := exec.Command("kubectl", args...)
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get %s: %w\n%s", resource, err, stderr.String())
	}
	return out, nil
}
