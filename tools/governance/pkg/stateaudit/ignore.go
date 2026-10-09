package stateaudit

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Ignore exempts one location of a layer from the sensitive markers. A gitleaks detection is never exempt.
type Ignore struct {
	Layer   string
	Address string
	Path    string
	Reason  string
}

// ignoreEntry is one entry of the ignore file, which names one or more addresses and one or more paths.
type ignoreEntry struct {
	Address   string   `yaml:"address"`
	Addresses []string `yaml:"addresses"`
	Path      string   `yaml:"path"`
	Paths     []string `yaml:"paths"`
	Reason    string   `yaml:"reason"`
}

// LoadIgnores reads the ignore file at path.
func LoadIgnores(path string) ([]Ignore, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stateaudit: open %s: %w", path, err)
	}
	defer func() { _ = file.Close() /* WHY: Read-only handle cleanup error is unactionable. */ }()

	var content struct {
		Ignores map[string][]ignoreEntry `yaml:"ignores"`
	}
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	err = decoder.Decode(&content)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("stateaudit: parse %s: %w", path, err)
	}
	var ignores []Ignore
	for _, layer := range slices.Sorted(maps.Keys(content.Ignores)) {
		for i, entry := range content.Ignores[layer] {
			expanded, err := expandIgnoreEntry(layer, entry)
			if err != nil {
				return nil, fmt.Errorf("stateaudit: %s layer %s entry %d: %w", path, layer, i+1, err)
			}
			ignores = append(ignores, expanded...)
		}
	}
	return ignores, nil
}

// expandIgnoreEntry returns one Ignore per pair of the addresses and the paths of entry.
func expandIgnoreEntry(layer string, entry ignoreEntry) ([]Ignore, error) {
	addresses, err := pickOneOrMany(entry.Address, entry.Addresses, "address", "addresses")
	if err != nil {
		return nil, err
	}
	paths, err := pickOneOrMany(entry.Path, entry.Paths, "path", "paths")
	if err != nil {
		return nil, err
	}
	if entry.Reason == "" {
		return nil, errors.New("MUST set reason")
	}
	var ignores []Ignore
	for _, address := range addresses {
		for _, p := range paths {
			ignores = append(ignores, Ignore{Layer: layer, Address: address, Path: p, Reason: entry.Reason})
		}
	}
	return ignores, nil
}

func pickOneOrMany(one string, many []string, oneKey, manyKey string) ([]string, error) {
	if (one == "") == (len(many) == 0) {
		return nil, fmt.Errorf("MUST set exactly one of %s and %s", oneKey, manyKey)
	}
	if one != "" {
		return []string{one}, nil
	}
	if slices.Contains(many, "") {
		return nil, fmt.Errorf("%s MUST NOT hold an empty item", manyKey)
	}
	return many, nil
}

// ApplyIgnores returns the findings which no entry names, and the entries which named none.
func ApplyIgnores(findings []Finding, ignores []Ignore) ([]Finding, []Ignore) {
	used := make([]bool, len(ignores))
	var kept []Finding
	for _, f := range findings {
		marked := f.Detection == DetectionSensitiveAttribute || f.Detection == DetectionSensitiveOutput
		index := slices.IndexFunc(ignores, func(i Ignore) bool {
			return marked && i.Layer == f.Layer && i.Address == f.Address && i.Path == f.Path
		})
		if index < 0 {
			kept = append(kept, f)
			continue
		}
		used[index] = true
	}
	var unused []Ignore
	for i, entry := range ignores {
		if !used[i] {
			unused = append(unused, entry)
		}
	}
	return kept, unused
}
