package policy

import "fmt"

// registries holds per-engine generator maps: engine → ruleID → Generator.
var registries = make(map[string]map[string]Generator)

// Register adds a Generator to the registry for the given engine.
// Panics if a Generator with the same rule ID is already registered for that engine.
func Register(engine string, g Generator) {
	if registries[engine] == nil {
		registries[engine] = make(map[string]Generator)
	}
	id := g.RuleID()
	if _, exists := registries[engine][id]; exists {
		panic(fmt.Sprintf("policy generator already registered for engine=%s rule=%s", engine, id))
	}
	registries[engine][id] = g
}

// Get retrieves a Generator by engine and rule ID.
func Get(engine, ruleID string) (Generator, bool) {
	m, ok := registries[engine]
	if !ok {
		return nil, false
	}
	g, ok := m[ruleID]
	return g, ok
}
