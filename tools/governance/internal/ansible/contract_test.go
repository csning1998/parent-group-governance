package ansible

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type argumentSpecsDoc struct {
	ArgumentSpecs map[string]struct {
		Options map[string]any `yaml:"options"`
	} `yaml:"argument_specs"`
}

type roleTask struct {
	Name        string     `yaml:"name"`
	Command     any        `yaml:"ansible.builtin.command"`
	Shell       any        `yaml:"ansible.builtin.shell"`
	ShortCmd    any        `yaml:"command"`
	ShortShell  any        `yaml:"shell"`
	ChangedWhen any        `yaml:"changed_when"`
	Register    string     `yaml:"register"`
	CheckMode   *bool      `yaml:"check_mode"`
	Block       []roleTask `yaml:"block"`
	Rescue      []roleTask `yaml:"rescue"`
	Always      []roleTask `yaml:"always"`
}

var (
	jinjaExprPattern = regexp.MustCompile(`(?s)(\{\{.*?\}\}|\{%.*?%\})`)
	wordTokenPattern = regexp.MustCompile(`\b[a-z][a-z0-9_]*\b`)
)

// TestGroupVarsAllMatchesInferredTopologyProjection verifies that group_vars/all projects every shared topology key declared in role argument specs.
func TestGroupVarsAllMatchesInferredTopologyProjection(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	domains := mustLoadTopologyDomains(t, ansibleDir)

	specFiles, err := filepath.Glob(filepath.Join(ansibleDir, "roles", "*", "meta", "argument_specs.yml"))
	if err != nil || len(specFiles) == 0 {
		t.Fatalf("glob argument_specs.yml: files=%v, err=%v", specFiles, err)
	}
	expected := make(map[string][]string)
	for _, specPath := range specFiles {
		roleName := filepath.Base(filepath.Dir(filepath.Dir(specPath)))
		spec := mustReadYAML[argumentSpecsDoc](t, specPath)
		for _, entry := range spec.ArgumentSpecs {
			for optName := range entry.Options {
				domain, ok := strings.CutPrefix(optName, roleName+"_")
				if ok && domains[domain] && !slices.Contains(expected[domain], optName) {
					expected[domain] = append(expected[domain], optName)
				}
			}
		}
	}
	for domain := range expected {
		slices.Sort(expected[domain])
	}

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
	slices.Sort(gotFiles)
	slices.Sort(wantFiles)
	if !slices.Equal(gotFiles, wantFiles) {
		t.Fatalf("group_vars/all files = %v, want %v", gotFiles, wantFiles)
	}

	for domain, wantVars := range expected {
		path := filepath.Join(groupVarsDir, domain+".yaml")
		doc := mustReadYAML[yaml.Node](t, path)
		if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
			t.Fatalf("%s must contain a top-level YAML mapping", filepath.Base(path))
		}
		mapping := doc.Content[0]
		if wantPairs := 1 + len(wantVars); len(mapping.Content) != 2*wantPairs {
			t.Fatalf("%s has %d keys, want %d (shared key plus role mappings)", filepath.Base(path), len(mapping.Content)/2, wantPairs)
		}
		wantTopVal := "{{ workstation_topology." + domain + " }}"
		if gotKey, gotVal := mapping.Content[0].Value, mapping.Content[1].Value; gotKey != domain || gotVal != wantTopVal {
			t.Errorf("%s entry 0 = (%q: %q), want (%q: %q)", filepath.Base(path), gotKey, gotVal, domain, wantTopVal)
		}
		wantRoleVal := "{{ " + domain + " }}"
		for i, wantVar := range wantVars {
			keyNode, valNode := mapping.Content[2*(i+1)], mapping.Content[2*(i+1)+1]
			if keyNode.Value != wantVar || valNode.Value != wantRoleVal {
				t.Errorf("%s entry %d = (%q: %q), want (%q: %q)", filepath.Base(path), i+1, keyNode.Value, valNode.Value, wantVar, wantRoleVal)
			}
		}
	}
}

// TestRolesReadNoUnprefixedTopologyKeys asserts contracted roles reference shared topology sections exclusively through role-prefixed inputs.
func TestRolesReadNoUnprefixedTopologyKeys(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	forbidden := mustLoadTopologyDomains(t, ansibleDir)
	forbidden["workstation_topology"] = true

	specFiles, err := filepath.Glob(filepath.Join(ansibleDir, "roles", "*", "meta", "argument_specs.yml"))
	if err != nil || len(specFiles) == 0 {
		t.Fatalf("glob argument_specs.yml: files=%v, err=%v", specFiles, err)
	}
	for _, specPath := range specFiles {
		roleDir := filepath.Dir(filepath.Dir(specPath))
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
				if !entry.IsDir() {
					assertRoleFilePrefixedTopology(t, filepath.Join(subDir, entry.Name()), forbidden)
				}
			}
		}
	}
}

// TestPlaybooksDeclareNoVarsFiles asserts that playbooks rely on inventory group_vars/all instead of vars_files.
func TestPlaybooksDeclareNoVarsFiles(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	playbooks, err := filepath.Glob(filepath.Join(ansibleDir, "playbooks", "*.yaml"))
	if err != nil || len(playbooks) == 0 {
		t.Fatalf("glob playbooks: files=%v, err=%v", playbooks, err)
	}
	for _, path := range playbooks {
		for i, play := range mustReadYAML[[]map[string]any](t, path) {
			if _, ok := play["vars_files"]; ok {
				t.Errorf("%s play[%d] declares vars_files, want group_vars/all projection alone", filepath.Base(path), i)
			}
		}
	}
}

// TestHostRolesSatisfyCheckModeContract enforces check_mode safety across all governance-managed host roles.
func TestHostRolesSatisfyCheckModeContract(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	hostRoles := []string{
		"workstation_selinux",
		"workstation_libvirt",
		"workstation_vault_proxy",
		"workstation_vault_audit",
		"workstation_host_telemetry",
	}
	for _, role := range hostRoles {
		taskFiles, err := filepath.Glob(filepath.Join(ansibleDir, "roles", role, "tasks", "*.yaml"))
		if err != nil || len(taskFiles) == 0 {
			t.Fatalf("glob tasks for %s: files=%v, err=%v", role, taskFiles, err)
		}
		for _, taskFile := range taskFiles {
			rel := filepath.Join(role, "tasks", filepath.Base(taskFile))
			assertRoleTasksCheckMode(t, rel, mustReadYAML[[]roleTask](t, taskFile))
		}
	}
}

func assertRoleFilePrefixedTopology(t *testing.T, path string, forbidden map[string]bool) {
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
	inAssertionBlock, blockIndent := false, 0
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
			inAssertionBlock, blockIndent = true, indent
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

func assertRoleTasksCheckMode(t *testing.T, rel string, tasks []roleTask) {
	t.Helper()
	for _, task := range tasks {
		assertRoleTasksCheckMode(t, rel, task.Block)
		assertRoleTasksCheckMode(t, rel, task.Rescue)
		assertRoleTasksCheckMode(t, rel, task.Always)
		if task.Command == nil && task.Shell == nil && task.ShortCmd == nil && task.ShortShell == nil {
			continue
		}
		changedWhen, ok := task.ChangedWhen.(bool)
		if !ok {
			continue
		}
		if !changedWhen && task.Register != "" && (task.CheckMode == nil || *task.CheckMode) {
			t.Errorf("%s task %q is a read-only probe (changed_when: false, register: %s) and must set check_mode: false", rel, task.Name, task.Register)
		}
		if changedWhen && task.CheckMode != nil && !*task.CheckMode {
			t.Errorf("%s task %q mutates host state (changed_when: true) and must not set check_mode: false", rel, task.Name)
		}
	}
}

func mustResolveAnsibleDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "ansible"))
	if err != nil {
		t.Fatalf("resolve ansible dir: %v", err)
	}
	return dir
}

func mustReadYAML[T any](t *testing.T, path string) T {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc T
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return doc
}

func mustLoadTopologyDomains(t *testing.T, ansibleDir string) map[string]bool {
	t.Helper()
	root := mustReadYAML[map[string]any](t, filepath.Join(ansibleDir, "..", "workstation-topology.yaml"))
	domains := make(map[string]bool, len(root))
	for key := range root {
		domains[key] = true
	}
	return domains
}
