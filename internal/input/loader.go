package input

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFromFile reads and parses a scan result JSON file.
func LoadFromFile(path string) (*ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scan results: %w", err)
	}
	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing scan results JSON: %w", err)
	}
	return &result, nil
}
