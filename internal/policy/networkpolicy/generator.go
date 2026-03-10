package networkpolicy

import (
	"fmt"
	"strings"
)

// GenerateDefaultDeny generates a default-deny NetworkPolicy that blocks all
// ingress and egress traffic for all pods in the given namespace.
func GenerateDefaultDeny(namespace string) string {
	var sb strings.Builder
	sb.WriteString("apiVersion: networking.k8s.io/v1\n")
	sb.WriteString("kind: NetworkPolicy\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: default-deny-all\n"))
	if namespace != "" {
		sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	}
	sb.WriteString("spec:\n")
	sb.WriteString("  podSelector: {}\n")
	sb.WriteString("  policyTypes:\n")
	sb.WriteString("    - Ingress\n")
	sb.WriteString("    - Egress\n")
	return sb.String()
}
