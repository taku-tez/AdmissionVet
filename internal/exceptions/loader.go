package exceptions

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// LoadFromFile reads and parses an exceptions YAML file.
// Returns an empty ExceptionList if path is empty.
func LoadFromFile(path string) (*ExceptionList, error) {
	if path == "" {
		return &ExceptionList{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading exceptions file: %w", err)
	}

	var list ExceptionList
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parsing exceptions file: %w", err)
	}
	return &list, nil
}

// Filter returns only those items that are NOT suppressed by any exception.
// getKey extracts (ruleID, namespace, resource) from an item of type T.
func Filter[T any](items []T, list *ExceptionList, getKey func(T) (ruleID, namespace, resource string)) []T {
	if list == nil || len(list.Exceptions) == 0 {
		return items
	}
	var result []T
	for _, item := range items {
		ruleID, namespace, resource := getKey(item)
		suppressed := false
		for _, ex := range list.Exceptions {
			if ex.Matches(ruleID, namespace, resource) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			result = append(result, item)
		}
	}
	return result
}
