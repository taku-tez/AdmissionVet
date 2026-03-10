package webhook

// Severity of a finding.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Finding represents a single issue found in a webhook configuration.
type Finding struct {
	RuleID   string
	Severity Severity
	Webhook  string // webhook name
	Kind     string // ValidatingWebhookConfiguration or MutatingWebhookConfiguration
	Message  string
}

// ── Kubernetes types (minimal, for YAML parsing) ─────────────────────────────

type webhookConfig struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   objectMeta        `yaml:"metadata"`
	Webhooks   []webhookEntry    `yaml:"webhooks"`
}

type objectMeta struct {
	Name string `yaml:"name"`
}

type webhookEntry struct {
	Name                    string            `yaml:"name"`
	FailurePolicy           string            `yaml:"failurePolicy"`
	TimeoutSeconds          *int              `yaml:"timeoutSeconds"`
	NamespaceSelector       *labelSelector    `yaml:"namespaceSelector"`
	ObjectSelector          *labelSelector    `yaml:"objectSelector"`
	ClientConfig            clientConfig      `yaml:"clientConfig"`
	ReinvocationPolicy      string            `yaml:"reinvocationPolicy"`      // Mutating only
	AdmissionReviewVersions []string          `yaml:"admissionReviewVersions"`
	SideEffects             string            `yaml:"sideEffects"`
}

type labelSelector struct {
	MatchExpressions []matchExpression `yaml:"matchExpressions"`
	MatchLabels      map[string]string `yaml:"matchLabels"`
}

type matchExpression struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

type clientConfig struct {
	CABundle string `yaml:"caBundle"`
	Service  *struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
		Port      int    `yaml:"port"`
	} `yaml:"service"`
	URL string `yaml:"url"`
}
