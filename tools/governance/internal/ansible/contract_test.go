package ansible

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type argumentSpecsDoc struct {
	ArgumentSpecs map[string]struct {
		Options map[string]any `yaml:"options"`
	} `yaml:"argument_specs"`
}

// TestGroupVarsAllMatchesInferredTopologyProjection verifies that group_vars/all projects every shared topology key declared in role argument specs.
func TestGroupVarsAllMatchesInferredTopologyProjection(t *testing.T) {
	ansibleDir := resolveRepoAnsibleDir(t)
	domains := loadTopologyDomains(t, ansibleDir)
	expected := inferDomainMappings(t, ansibleDir, domains)

	groupVarsDir := filepath.Join(ansibleDir, "inventory", "group_vars", "all")
	entries, err := os.ReadDir(groupVarsDir)
	if err != nil {
		t.Fatalf("read group_vars/all: %v", err)
	}

	var gotFiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			gotFiles = append(gotFiles, entry.Name())
		}
	}
	wantFiles := make([]string, 0, len(expected))
	for domain := range expected {
		wantFiles = append(wantFiles, domain+".yaml")
	}
	sort.Strings(gotFiles)
	sort.Strings(wantFiles)
	if !slices.Equal(gotFiles, wantFiles) {
		t.Fatalf("group_vars/all files = %v, want %v", gotFiles, wantFiles)
	}

	for domain, wantVars := range expected {
		assertGroupVarsFile(t, filepath.Join(groupVarsDir, domain+".yaml"), domain, wantVars)
	}
}

// TestRolesReadNoUnprefixedTopologyKeys asserts contracted roles reference shared topology sections exclusively through role-prefixed inputs.
func TestRolesReadNoUnprefixedTopologyKeys(t *testing.T) {
	ansibleDir := resolveRepoAnsibleDir(t)
	domains := loadTopologyDomains(t, ansibleDir)
	forbidden := make(map[string]bool, len(domains)+1)
	for domain := range domains {
		forbidden[domain] = true
	}
	forbidden["workstation_topology"] = true

	specFiles, err := filepath.Glob(filepath.Join(ansibleDir, "roles", "*", "meta", "argument_specs.yml"))
	if err != nil || len(specFiles) == 0 {
		t.Fatalf("glob argument_specs.yml: files=%v, err=%v", specFiles, err)
	}
	for _, specPath := range specFiles {
		roleDir := filepath.Dir(filepath.Dir(specPath))
		assertRoleUsesPrefixedTopology(t, roleDir, forbidden)
	}
}

// TestPlaybooksDeclareNoVarsFiles asserts that playbooks rely on inventory group_vars/all instead of vars_files.
func TestPlaybooksDeclareNoVarsFiles(t *testing.T) {
	ansibleDir := resolveRepoAnsibleDir(t)
	playbooks, err := filepath.Glob(filepath.Join(ansibleDir, "playbooks", "*.yaml"))
	if err != nil || len(playbooks) == 0 {
		t.Fatalf("glob playbooks: files=%v, err=%v", playbooks, err)
	}
	for _, path := range playbooks {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read playbook %s: %v", path, err)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatalf("unmarshal playbook %s: %v", path, err)
		}
		for i, play := range plays {
			if _, ok := play["vars_files"]; ok {
				t.Errorf("%s play[%d] declares vars_files, want group_vars/all projection alone", filepath.Base(path), i)
			}
		}
	}
}

func resolveRepoAnsibleDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "ansible"))
	if err != nil {
		t.Fatalf("resolve ansible dir: %v", err)
	}
	return dir
}

func loadTopologyDomains(t *testing.T, ansibleDir string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(ansibleDir, "..", "workstation-topology.yaml"))
	if err != nil {
		t.Fatalf("read workstation-topology.yaml: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal workstation-topology.yaml: %v", err)
	}
	domains := make(map[string]bool, len(root))
	for key := range root {
		domains[key] = true
	}
	return domains
}

func inferDomainMappings(t *testing.T, ansibleDir string, domains map[string]bool) map[string][]string {
	t.Helper()
	specFiles, err := filepath.Glob(filepath.Join(ansibleDir, "roles", "*", "meta", "argument_specs.yml"))
	if err != nil || len(specFiles) == 0 {
		t.Fatalf("glob argument_specs.yml: files=%v, err=%v", specFiles, err)
	}
	inferred := make(map[string][]string)
	for _, specPath := range specFiles {
		roleName := filepath.Base(filepath.Dir(filepath.Dir(specPath)))
		spec := parseArgumentSpecs(t, specPath)
		for _, entry := range spec.ArgumentSpecs {
			for optName := range entry.Options {
				domain, ok := strings.CutPrefix(optName, roleName+"_")
				if ok && domains[domain] && !slices.Contains(inferred[domain], optName) {
					inferred[domain] = append(inferred[domain], optName)
				}
			}
		}
	}
	for domain := range inferred {
		sort.Strings(inferred[domain])
	}
	return inferred
}

func parseArgumentSpecs(t *testing.T, path string) argumentSpecsDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc argumentSpecsDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return doc
}

func assertGroupVarsFile(t *testing.T, path, domain string, wantVars []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		t.Fatalf("%s must contain a top-level YAML mapping", filepath.Base(path))
	}
	mapping := doc.Content[0]
	wantPairs := 1 + len(wantVars)
	if len(mapping.Content) != 2*wantPairs {
		t.Fatalf("%s has %d keys, want %d (shared key plus role mappings)", filepath.Base(path), len(mapping.Content)/2, wantPairs)
	}

	gotKey, gotVal := mapping.Content[0].Value, mapping.Content[1].Value
	wantVal := "{{ workstation_topology." + domain + " }}"
	if gotKey != domain || gotVal != wantVal {
		t.Errorf("%s entry 0 = (%q: %q), want (%q: %q)", filepath.Base(path), gotKey, gotVal, domain, wantVal)
	}

	wantRoleVal := "{{ " + domain + " }}"
	for i, wantVar := range wantVars {
		keyNode, valNode := mapping.Content[2*(i+1)], mapping.Content[2*(i+1)+1]
		if keyNode.Value != wantVar || valNode.Value != wantRoleVal {
			t.Errorf("%s entry %d = (%q: %q), want (%q: %q)", filepath.Base(path), i+1, keyNode.Value, valNode.Value, wantVar, wantRoleVal)
		}
	}
}

var (
	jinjaExprPattern = regexp.MustCompile(`(?s)(\{\{.*?\}\}|\{%.*?%\})`)
	wordTokenPattern = regexp.MustCompile(`\b[a-z][a-z0-9_]*\b`)
)

func assertRoleUsesPrefixedTopology(t *testing.T, roleDir string, forbidden map[string]bool) {
	t.Helper()
	for _, sub := range []string{"defaults", "tasks", "templates", "handlers"} {
		subDir := filepath.Join(roleDir, sub)
		entries, err := os.ReadDir(subDir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", subDir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			checkRoleFile(t, filepath.Join(subDir, entry.Name()), forbidden)
		}
	}
}

func checkRoleFile(t *testing.T, path string, forbidden map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)
	if strings.HasSuffix(path, ".j2") {
		for _, expr := range jinjaExprPattern.FindAllString(text, -1) {
			assertNoForbiddenBareTokens(t, path, 0, expr, forbidden)
		}
		return
	}
	assertYAMLHasNoForbiddenTokens(t, path, text, forbidden)
}

func assertYAMLHasNoForbiddenTokens(t *testing.T, path, text string, forbidden map[string]bool) {
	t.Helper()
	inAssertionBlock := false
	blockIndent := 0
	for lineIdx, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if inAssertionBlock && indent <= blockIndent && !strings.HasPrefix(trimmed, "-") {
			inAssertionBlock = false
		}
		if strings.Contains(trimmed, "that:") || strings.Contains(trimmed, "when:") || strings.Contains(trimmed, "loop:") {
			inAssertionBlock = true
			blockIndent = indent
			assertNoForbiddenBareTokens(t, path, lineIdx+1, line, forbidden)
			continue
		}
		if inAssertionBlock || strings.Contains(line, "{{") || strings.Contains(line, "{%") {
			assertNoForbiddenBareTokens(t, path, lineIdx+1, line, forbidden)
		}
	}
}

func assertNoForbiddenBareTokens(t *testing.T, path string, lineNo int, snippet string, forbidden map[string]bool) {
	t.Helper()
	for _, idx := range wordTokenPattern.FindAllStringIndex(snippet, -1) {
		tok := snippet[idx[0]:idx[1]]
		if !forbidden[tok] {
			continue
		}
		// Ignore attribute accesses like workstation_topology.<domain>; workstation_topology itself still triggers.
		if idx[0] > 0 && snippet[idx[0]-1] == '.' {
			continue
		}
		t.Errorf("%s:%d references unprefixed topology identifier %q in %q", path, lineNo, tok, strings.TrimSpace(snippet))
	}
}
