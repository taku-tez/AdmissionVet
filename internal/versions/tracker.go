// Package versions tracks and manages the history of generated policy files.
package versions

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const historyFile = ".admissionvet-history.json"

// Entry records a single generation event.
type Entry struct {
	Version   int               `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Engine    string            `json:"engine"`
	Source    string            `json:"source"` // --from file or --preset name
	Files     map[string]string `json:"files"`  // filename → sha256 hash
}

// History is the full history stored in the output directory.
type History struct {
	Entries []Entry `json:"entries"`
}

// Load reads the history from the output directory.
// Returns an empty history if the file does not exist.
func Load(outputDir string) (*History, error) {
	path := filepath.Join(outputDir, historyFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &History{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading history: %w", err)
	}
	var h History
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parsing history: %w", err)
	}
	return &h, nil
}

// Save writes the history to the output directory.
func (h *History) Save(outputDir string) error {
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling history: %w", err)
	}
	return os.WriteFile(filepath.Join(outputDir, historyFile), data, 0o644)
}

// Record snapshots the current state of the output directory as a new version.
func Record(outputDir, engine, source string) (*Entry, error) {
	h, err := Load(outputDir)
	if err != nil {
		return nil, err
	}

	files, err := hashFiles(outputDir)
	if err != nil {
		return nil, err
	}

	version := 1
	if len(h.Entries) > 0 {
		version = h.Entries[len(h.Entries)-1].Version + 1
	}

	entry := Entry{
		Version:   version,
		Timestamp: time.Now().UTC(),
		Engine:    engine,
		Source:    source,
		Files:     files,
	}
	h.Entries = append(h.Entries, entry)

	if err := h.Save(outputDir); err != nil {
		return nil, err
	}
	return &entry, nil
}

// Rollback restores the output directory to a specific version.
// It reads the file hashes from the history but does not re-store files
// (it marks the rollback as a new entry pointing to the old file set).
// Returns an error if the version does not exist.
func Rollback(outputDir string, targetVersion int) error {
	h, err := Load(outputDir)
	if err != nil {
		return err
	}

	var target *Entry
	for i := range h.Entries {
		if h.Entries[i].Version == targetVersion {
			target = &h.Entries[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("version %d not found", targetVersion)
	}

	// Delete current YAML files and restore from version snapshot.
	// Since we store hashes (not content), we verify existing files match.
	// For actual rollback, we need a stash directory.
	stashDir := filepath.Join(outputDir, ".admissionvet-stash")
	stashPath := filepath.Join(stashDir, fmt.Sprintf("v%d", targetVersion))

	if _, err := os.Stat(stashPath); os.IsNotExist(err) {
		return fmt.Errorf("stash for version %d not found in %s — rollback not possible (stash only kept for 5 versions)", targetVersion, stashDir)
	}

	// Remove current YAML files.
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("reading output directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == historyFile {
			continue
		}
		if err := os.Remove(filepath.Join(outputDir, e.Name())); err != nil {
			return fmt.Errorf("removing %s: %w", e.Name(), err)
		}
	}

	// Copy stashed files back.
	stashedFiles, err := os.ReadDir(stashPath)
	if err != nil {
		return fmt.Errorf("reading stash: %w", err)
	}
	for _, f := range stashedFiles {
		src := filepath.Join(stashPath, f.Name())
		dst := filepath.Join(outputDir, f.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("reading stash file %s: %w", f.Name(), err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fmt.Errorf("restoring %s: %w", f.Name(), err)
		}
	}

	// Record rollback as a new version entry.
	newVersion := h.Entries[len(h.Entries)-1].Version + 1
	rollbackEntry := Entry{
		Version:   newVersion,
		Timestamp: time.Now().UTC(),
		Engine:    target.Engine,
		Source:    fmt.Sprintf("rollback-to-v%d", targetVersion),
		Files:     target.Files,
	}
	h.Entries = append(h.Entries, rollbackEntry)
	return h.Save(outputDir)
}

// Stash saves the current output directory contents to a stash for later rollback.
// Only the last 5 versions are kept to save disk space.
func Stash(outputDir string, version int) error {
	stashDir := filepath.Join(outputDir, ".admissionvet-stash", fmt.Sprintf("v%d", version))
	if err := os.MkdirAll(stashDir, 0o755); err != nil {
		return fmt.Errorf("creating stash directory: %w", err)
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == historyFile {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outputDir, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stashDir, e.Name()), data, 0o644); err != nil {
			return err
		}
	}

	// Prune stashes older than 5 versions.
	pruneStash(filepath.Join(outputDir, ".admissionvet-stash"), version)
	return nil
}

func pruneStash(stashBase string, currentVersion int) {
	entries, _ := os.ReadDir(stashBase)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for len(entries) > 5 {
		os.RemoveAll(filepath.Join(stashBase, entries[0].Name()))
		entries = entries[1:]
	}
}

func hashFiles(dir string) (map[string]string, error) {
	hashes := make(map[string]string)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == historyFile {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		hashes[e.Name()] = fmt.Sprintf("%x", sum)
	}
	return hashes, nil
}
