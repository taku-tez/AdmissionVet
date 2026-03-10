package policy

import "fmt"

var globalRegistry = make(map[string]Generator)

// Register adds a Generator to the global registry.
// Panics if a Generator with the same rule ID is already registered.
func Register(g Generator) {
	id := g.RuleID()
	if _, exists := globalRegistry[id]; exists {
		panic(fmt.Sprintf("policy generator already registered for rule ID: %s", id))
	}
	globalRegistry[id] = g
}

// Get retrieves a Generator by rule ID.
func Get(ruleID string) (Generator, bool) {
	g, ok := globalRegistry[ruleID]
	return g, ok
}
