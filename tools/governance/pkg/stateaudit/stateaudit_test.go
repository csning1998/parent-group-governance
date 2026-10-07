package stateaudit

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Split literals keep the pre-commit secret scan off the fixtures.
var (
	fakePAT    = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"
	fakeRunner = "glrt-" + "t1_AbCdEfGhIjKlMnOpQrSt"
)

// prefixDetector flags a value with the prefix of a GitLab personal access token, as a stand-in for gitleaks.
type prefixDetector struct{}

func (prefixDetector) Detect(_, value string) []Detection {
	if strings.HasPrefix(value, "glpat-") {
		return []Detection{"gitleaks:gitlab-pat"}
	}
	return nil
}

// stateFixture is a version 4 state with every shape which ScanState reads.
func stateFixture() []byte {
	return []byte(`{
  "version": 4,
  "serial": 3,
  "outputs": {
    "registry": {"value": {"endpoint": "https://vault.example"}, "type": ["object", {}]},
    "admin": {"value": {"password": "operator-chosen-password"}, "type": ["object", {}], "sensitive": true}
  },
  "resources": [
    {"mode": "managed", "type": "gitlab_user_runner", "name": "shared", "instances": [
      {"attributes": {"id": "7", "description": "shared", "token": "` + fakeRunner + `", "empty": ""},
       "sensitive_attributes": [[{"type": "get_attr", "value": "token"}], [{"type": "get_attr", "value": "empty"}]]}
    ]},
    {"module": "module.contexts", "mode": "data", "type": "terraform_remote_state", "name": "bastion", "instances": [
      {"index_key": 0, "attributes": {"config": {"value": {"address": "https://state.example", "password": "` + fakePAT + `"}}},
       "sensitive_attributes": []}
    ]},
    {"mode": "managed", "type": "gitlab_group_variable", "name": "review", "instances": [
      {"index_key": "SONAR_TOKEN", "attributes": {"key": "SONAR_TOKEN", "value": "` + fakePAT + `"},
       "sensitive_attributes": [[{"type": "get_attr", "value": "value"}]]}
    ]},
    {"mode": "managed", "type": "vault_kv_secret_v2", "name": "list", "instances": [
      {"attributes": {"items": ["public", "private"]},
       "sensitive_attributes": [[{"type": "get_attr", "value": "items"}, {"type": "index", "value": {"value": 1, "type": "number"}}]]}
    ]}
  ]
}`)
}

func TestScanState(t *testing.T) {
	got, err := ScanState("group-gitlab-runner", "current", stateFixture(), prefixDetector{})
	if err != nil {
		t.Fatalf("ScanState: %v", err)
	}
	want := []Finding{
		{Layer: "group-gitlab-runner", Version: "current", Address: `gitlab_group_variable.review["SONAR_TOKEN"]`, Path: "value", Detection: DetectionSensitiveAttribute},
		{Layer: "group-gitlab-runner", Version: "current", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute},
		{Layer: "group-gitlab-runner", Version: "current", Address: "module.contexts.data.terraform_remote_state.bastion[0]", Path: "config.value.password", Detection: "gitleaks:gitlab-pat"},
		{Layer: "group-gitlab-runner", Version: "current", Address: "output.admin", Path: "password", Detection: DetectionSensitiveOutput},
		{Layer: "group-gitlab-runner", Version: "current", Address: "vault_kv_secret_v2.list", Path: "items.1", Detection: DetectionSensitiveAttribute},
	}
	if !slices.Equal(got, want) {
		t.Errorf("ScanState =\n%+v\nwant\n%+v", got, want)
	}
}

func TestScanStateRejectsMalformedDocument(t *testing.T) {
	for name, document := range map[string]string{
		"not json":    "Error: Unauthorized",
		"empty":       "",
		"resources":   `{"version": 4, "resources": {"type": "x"}}`,
		"sensitivity": `{"version": 4, "resources": [{"mode": "managed", "type": "x", "name": "y", "instances": [{"attributes": {}, "sensitive_attributes": "token"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ScanState("a", "current", []byte(document), prefixDetector{})
			if err == nil {
				t.Errorf("ScanState(%s) error = nil, want a parse error", name)
			}
		})
	}
}

func TestApplyIgnores(t *testing.T) {
	findings := []Finding{
		{Layer: "a", Version: "current", Address: "data.vault_generic_secret.facts", Path: "data.domain", Detection: DetectionSensitiveAttribute},
		{Layer: "a", Version: "serial-2", Address: "data.vault_generic_secret.facts", Path: "data.domain", Detection: DetectionSensitiveAttribute},
		{Layer: "a", Version: "current", Address: "output.facts", Path: "domain", Detection: DetectionSensitiveOutput},
		{Layer: "a", Version: "current", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute},
		{Layer: "a", Version: "current", Address: "terraform_remote_state.x", Path: "config.password", Detection: "gitleaks:gitlab-pat"},
	}
	ignores := []Ignore{
		{Layer: "a", Address: "data.vault_generic_secret.facts", Path: "data.domain", Reason: "facts"},
		{Layer: "a", Address: "output.facts", Path: "domain", Reason: "facts"},
		{Layer: "a", Address: "terraform_remote_state.x", Path: "config.password", Reason: "a gitleaks detection"},
		{Layer: "b", Address: "gitlab_user_runner.shared", Path: "token", Reason: "wrong layer"},
	}
	kept, unused := ApplyIgnores(findings, ignores)
	if !slices.Equal(kept, findings[3:]) {
		t.Errorf("kept = %+v, want the runner token and the gitleaks detection", kept)
	}
	if !slices.Equal(unused, ignores[2:]) {
		t.Errorf("unused = %+v, want the entries of the gitleaks detection and the wrong layer", unused)
	}
}

func writeIgnoreFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), IgnoreFileName)
	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	return path
}

func TestLoadIgnoresExpandsEveryPair(t *testing.T) {
	path := writeIgnoreFile(t, `ignores:
  layer-b:
    - address: x.single
      path: data.one
      reason: single
  layer-a:
    - addresses: [x.first, x.second]
      paths: [data.one, data.two]
      reason: pairs
`)
	got, err := LoadIgnores(path)
	want := []Ignore{
		{Layer: "layer-a", Address: "x.first", Path: "data.one", Reason: "pairs"},
		{Layer: "layer-a", Address: "x.first", Path: "data.two", Reason: "pairs"},
		{Layer: "layer-a", Address: "x.second", Path: "data.one", Reason: "pairs"},
		{Layer: "layer-a", Address: "x.second", Path: "data.two", Reason: "pairs"},
		{Layer: "layer-b", Address: "x.single", Path: "data.one", Reason: "single"},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("LoadIgnores = %+v, %v, want %+v", got, err, want)
	}

	got, err = LoadIgnores(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil || len(got) != 0 {
		t.Errorf("LoadIgnores(absent) = %+v, %v, want none and nil", got, err)
	}
}

func TestLoadIgnoresRejectsIncompleteEntry(t *testing.T) {
	for name, content := range map[string]string{
		"no reason":              "ignores:\n  a:\n    - {address: b, path: c}\n",
		"no address":             "ignores:\n  a:\n    - {path: c, reason: r}\n",
		"address and addresses":  "ignores:\n  a:\n    - {address: b, addresses: [d], path: c, reason: r}\n",
		"path and paths":         "ignores:\n  a:\n    - {address: b, path: c, paths: [d], reason: r}\n",
		"empty item":             "ignores:\n  a:\n    - {address: b, paths: [c, ''], reason: r}\n",
		"detection is not a key": "ignores:\n  a:\n    - {address: b, path: c, reason: r, detection: sensitive-attribute}\n",
		"layer list":             "ignores:\n  - {address: b, path: c, reason: r}\n",
		"not yaml":               "ignores: [",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadIgnores(writeIgnoreFile(t, content))
			if err == nil {
				t.Errorf("LoadIgnores(%s) error = nil, want a rejection", name)
			}
		})
	}
}

func TestScanStateMergesJSONRestatement(t *testing.T) {
	document := []byte(`{"version": 4, "resources": [
  {"mode": "managed", "type": "vault_kv_secret_v2", "name": "registry", "instances": [
    {"attributes": {
       "data": {"domain": "example.test", "stages": "[\"dev\"]"},
       "data_json": "{\"domain\": \"example.test\", \"stages\": [\"dev\"], \"extra\": \"only-in-json\"}"},
     "sensitive_attributes": [[{"type": "get_attr", "value": "data"}], [{"type": "get_attr", "value": "data_json"}]]}
  ]}
]}`)
	got, err := ScanState("a", "current", document, prefixDetector{})
	if err != nil {
		t.Fatalf("ScanState: %v", err)
	}
	var paths []string
	for _, f := range got {
		paths = append(paths, f.Path)
	}
	if want := []string{"data.domain", "data.stages", "data_json.extra"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

func TestWriteReportNamesLocationsAlone(t *testing.T) {
	findings, err := ScanState("group-gitlab-runner", "current", stateFixture(), prefixDetector{})
	if err != nil {
		t.Fatalf("ScanState: %v", err)
	}
	report := Report{
		Findings:      findings,
		UnusedIgnores: []Ignore{{Layer: "b", Address: "x.y", Path: "z", Reason: "stale"}},
		Scanned:       []string{"group-gitlab-runner@current"},
	}
	var out bytes.Buffer
	err = WriteReport(&out, report)
	if err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	text := out.String()
	for _, want := range []string{"gitlab_user_runner.shared", "token", "sensitive-attribute", "gitleaks:gitlab-pat", "5 finding", "1 version", "unused ignore", "x.y"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{fakePAT, fakeRunner, "operator-chosen-password"} {
		if strings.Contains(text, secret) {
			t.Errorf("report holds a value:\n%s", text)
		}
	}
}

func TestWriteReportOfCleanStates(t *testing.T) {
	var out bytes.Buffer
	err := WriteReport(&out, Report{Scanned: []string{"a@current", "a@serial-2"}})
	if err != nil || !strings.Contains(out.String(), "0 finding") || !strings.Contains(out.String(), "2 version") {
		t.Errorf("WriteReport = %q, %v, want a summary of 0 findings in 2 versions", out.String(), err)
	}
}
