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
	"reflect"
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

	// value is set by a revealing audit alone.
	value string
}

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
	reveal         bool
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

// ScanState returns the findings of one state document without the values.
func ScanState(layer, version string, document []byte, detector ValueDetector) ([]Finding, error) {
	return scanState(layer, version, document, detector, false)
}

func scanState(layer, version string, document []byte, detector ValueDetector, reveal bool) ([]Finding, error) {
	state, err := parseState(document)
	if err != nil {
		return nil, err
	}
	s := &scanner{layer: layer, version: version, detector: detector, reveal: reveal}
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
	walkLeaves(mergeJSONRestatements(instance.Attributes), nil, func(path []string, value string) {
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
		finding := Finding{Layer: s.layer, Version: s.version, Address: address, Path: strings.Join(path, "."), Detection: detection}
		if s.reveal {
			finding.value = value
		}
		s.findings = append(s.findings, finding)
	}
}

// mergeJSONRestatements drops each <name>_json string whose JSON object restates the map <name>, hence one value is
// reported once at <name>.<key>. A key which the map lacks or holds with another value stays under <name>_json.
func mergeJSONRestatements(attributes any) any {
	attrs, ok := attributes.(map[string]any)
	if !ok {
		return attributes
	}
	merged := maps.Clone(attrs)
	for key, value := range attrs {
		name, isJSON := strings.CutSuffix(key, "_json")
		text, isString := value.(string)
		restated, hasMap := attrs[name].(map[string]any)
		var decoded map[string]any
		if !isJSON || !isString || !hasMap || json.Unmarshal([]byte(text), &decoded) != nil {
			continue
		}
		maps.DeleteFunc(decoded, func(k string, v any) bool { return restates(restated[k], v) })
		if len(decoded) == 0 {
			delete(merged, key)
		} else {
			merged[key] = decoded
		}
	}
	return merged
}

// restates reports whether held equals decoded, where a map attribute holds a nested value as JSON text.
func restates(held, decoded any) bool {
	if reflect.DeepEqual(held, decoded) {
		return true
	}
	text, ok := held.(string)
	if !ok {
		return false
	}
	var parsed any
	return json.Unmarshal([]byte(text), &parsed) == nil && reflect.DeepEqual(parsed, decoded)
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

// WriteReport writes report as plain text.
func WriteReport(w io.Writer, report Report) error {
	var b strings.Builder
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "%s@%s  %s  %s  [%s]\n", f.Layer, f.Version, f.Address, f.Path, f.Detection)
		if f.value != "" {
			fmt.Fprintf(&b, "    value: %q\n", f.value)
		}
	}
	for _, i := range report.UnusedIgnores {
		fmt.Fprintf(&b, "unused ignore: %s  %s  %s\n", i.Layer, i.Address, i.Path)
	}
	fmt.Fprintf(&b, "%d finding(s) in %d version(s), %d unused ignore(s)\n",
		len(report.Findings), len(report.Scanned), len(report.UnusedIgnores))
	_, err := io.WriteString(w, b.String())
	if err != nil {
		return fmt.Errorf("stateaudit: write the report: %w", err)
	}
	return nil
}
