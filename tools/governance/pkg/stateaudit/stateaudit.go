// Package stateaudit reports where a Terraform state holds a confidential value, never the value itself.
package stateaudit

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Detection names the evidence of a finding. A gitleaks rule appears as "gitleaks:<rule>".
type Detection string

const (
	// DetectionSensitiveAttribute marks a path listed in sensitive_attributes.
	DetectionSensitiveAttribute Detection = "sensitive-attribute"
	// DetectionSensitiveOutput marks a root output declared sensitive.
	DetectionSensitiveOutput Detection = "sensitive-output"
)

// ErrFindings reports a finding or an unused ignore entry.
var ErrFindings = errors.New("stateaudit: the states hold confidential values")

// Finding is one location of a confidential value.
type Finding struct {
	Layer     string
	Version   string
	Address   string
	Path      string
	Detection Detection
}

// Ignore exempts one location and detection of a layer.
type Ignore struct {
	Layer     string    `yaml:"layer"`
	Address   string    `yaml:"address"`
	Path      string    `yaml:"path"`
	Detection Detection `yaml:"detection"`
	Reason    string    `yaml:"reason"`
}

// Report holds the findings, the unused ignore entries, and the scanned versions.
type Report struct {
	Findings      []Finding
	UnusedIgnores []Ignore
	Scanned       []string
}

// ValueDetector returns the detections of one value under the attribute name key.
type ValueDetector interface {
	Detect(key, value string) []Detection
}

type stateDocument struct {
	Serial  int `json:"serial"`
	Outputs map[string]struct {
		Value     any  `json:"value"`
		Sensitive bool `json:"sensitive"`
	} `json:"outputs"`
	Resources []struct {
		Module    string          `json:"module"`
		Mode      string          `json:"mode"`
		Type      string          `json:"type"`
		Name      string          `json:"name"`
		Instances []stateInstance `json:"instances"`
	} `json:"resources"`
}

type stateInstance struct {
	IndexKey            any          `json:"index_key"`
	Attributes          any          `json:"attributes"`
	SensitiveAttributes [][]pathStep `json:"sensitive_attributes"`
}

type pathStep struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

// scanner collects the findings of one state version.
type scanner struct {
	layer, version string
	detector       ValueDetector
	findings       []Finding
}

func parseState(document []byte) (stateDocument, error) {
	var state stateDocument
	err := json.Unmarshal(document, &state)
	if err != nil {
		return stateDocument{}, fmt.Errorf("stateaudit: parse the state: %w", err)
	}
	return state, nil
}

// ScanState returns the findings of one state document.
func ScanState(layer, version string, document []byte, detector ValueDetector) ([]Finding, error) {
	state, err := parseState(document)
	if err != nil {
		return nil, err
	}
	s := &scanner{layer: layer, version: version, detector: detector}
	for name, output := range state.Outputs {
		s.scanValue("output."+name, output.Value, nil, output.Sensitive, DetectionSensitiveOutput)
	}
	for _, resource := range state.Resources {
		address := resource.Type + "." + resource.Name
		if resource.Mode == "data" {
			address = "data." + address
		}
		if resource.Module != "" {
			address = resource.Module + "." + address
		}
		for _, instance := range resource.Instances {
			err := s.scanInstance(address+formatIndexKey(instance.IndexKey), instance)
			if err != nil {
				return nil, fmt.Errorf("stateaudit: %s: %w", address, err)
			}
		}
	}
	slices.SortFunc(s.findings, func(x, y Finding) int {
		return cmp.Or(cmp.Compare(x.Address, y.Address), cmp.Compare(x.Path, y.Path), cmp.Compare(x.Detection, y.Detection))
	})
	return s.findings, nil
}

func (s *scanner) scanInstance(address string, instance stateInstance) error {
	var sensitive [][]string
	for _, steps := range instance.SensitiveAttributes {
		path, err := resolvePath(steps)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, path)
	}
	walkLeaves(instance.Attributes, nil, func(path []string, value string) {
		isSensitive := slices.ContainsFunc(sensitive, func(p []string) bool { return len(p) <= len(path) && slices.Equal(p, path[:len(p)]) })
		s.addLeaf(address, path, value, isSensitive, DetectionSensitiveAttribute)
	})
	return nil
}

func (s *scanner) scanValue(address string, value any, path []string, isSensitive bool, marked Detection) {
	walkLeaves(value, path, func(path []string, leaf string) {
		s.addLeaf(address, path, leaf, isSensitive, marked)
	})
}

// addLeaf records the marked detection of a sensitive leaf, and the detector results of any other leaf.
func (s *scanner) addLeaf(address string, path []string, value string, isSensitive bool, marked Detection) {
	detections := []Detection{marked}
	if !isSensitive {
		key := ""
		if len(path) > 0 {
			key = path[len(path)-1]
		}
		detections = s.detector.Detect(key, value)
	}
	for _, detection := range detections {
		s.findings = append(s.findings, Finding{
			Layer: s.layer, Version: s.version, Address: address, Path: strings.Join(path, "."), Detection: detection,
		})
	}
}

// walkLeaves calls visit for every non-empty string below value.
func walkLeaves(value any, path []string, visit func(path []string, value string)) {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(v)) {
			walkLeaves(v[key], append(slices.Clone(path), key), visit)
		}
	case []any:
		for i, child := range v {
			walkLeaves(child, append(slices.Clone(path), strconv.Itoa(i)), visit)
		}
	case string:
		if v != "" {
			visit(path, v)
		}
	}
}

func resolvePath(steps []pathStep) ([]string, error) {
	path := make([]string, 0, len(steps))
	for _, step := range steps {
		switch step.Type {
		case "get_attr":
			var name string
			err := json.Unmarshal(step.Value, &name)
			if err != nil {
				return nil, fmt.Errorf("sensitive attribute step: %w", err)
			}
			path = append(path, name)
		case "index":
			var index struct {
				Value any `json:"value"`
			}
			err := json.Unmarshal(step.Value, &index)
			if err != nil {
				return nil, fmt.Errorf("sensitive index step: %w", err)
			}
			path = append(path, fmt.Sprint(index.Value))
		default:
			return nil, fmt.Errorf("unknown sensitive path step %q", step.Type)
		}
	}
	return path, nil
}

func formatIndexKey(key any) string {
	switch k := key.(type) {
	case string:
		return "[" + strconv.Quote(k) + "]"
	case float64:
		return "[" + strconv.FormatFloat(k, 'f', -1, 64) + "]"
	default:
		return ""
	}
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
	defer func() { _ = file.Close() }()

	var content struct {
		Ignores []Ignore `yaml:"ignores"`
	}
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	err = decoder.Decode(&content)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("stateaudit: parse %s: %w", path, err)
	}
	for i, entry := range content.Ignores {
		if entry.Layer == "" || entry.Address == "" || entry.Path == "" || entry.Detection == "" || entry.Reason == "" {
			return nil, fmt.Errorf("stateaudit: %s entry %d MUST set layer, address, path, detection, and reason", path, i+1)
		}
	}
	return content.Ignores, nil
}

// ApplyIgnores returns the findings which no entry names, and the entries which named none.
func ApplyIgnores(findings []Finding, ignores []Ignore) ([]Finding, []Ignore) {
	used := make([]bool, len(ignores))
	var kept []Finding
	for _, f := range findings {
		index := slices.IndexFunc(ignores, func(i Ignore) bool {
			return i.Layer == f.Layer && i.Address == f.Address && i.Path == f.Path && i.Detection == f.Detection
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

// WriteReport writes report as plain text.
func WriteReport(w io.Writer, report Report) error {
	var b strings.Builder
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "%s@%s  %s  %s  [%s]\n", f.Layer, f.Version, f.Address, f.Path, f.Detection)
	}
	for _, i := range report.UnusedIgnores {
		fmt.Fprintf(&b, "unused ignore: %s  %s  %s  [%s]\n", i.Layer, i.Address, i.Path, i.Detection)
	}
	fmt.Fprintf(&b, "%d finding(s) in %d version(s), %d unused ignore(s)\n",
		len(report.Findings), len(report.Scanned), len(report.UnusedIgnores))
	_, err := io.WriteString(w, b.String())
	if err != nil {
		return fmt.Errorf("stateaudit: write the report: %w", err)
	}
	return nil
}
