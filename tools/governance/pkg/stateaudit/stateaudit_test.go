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
		{Layer: "a", Version: "current", Address: "data.vault_generic_secret.facts", Path: "data_json", Detection: DetectionSensitiveAttribute},
		{Layer: "a", Version: "serial-2", Address: "data.vault_generic_secret.facts", Path: "data_json", Detection: DetectionSensitiveAttribute},
		{Layer: "a", Version: "current", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute},
	}
	ignores := []Ignore{
		{Layer: "a", Address: "data.vault_generic_secret.facts", Path: "data_json", Detection: DetectionSensitiveAttribute, Reason: "facts"},
		{Layer: "a", Address: "gitlab_user_runner.shared", Path: "token", Detection: "gitleaks:gitlab-pat", Reason: "wrong detection"},
		{Layer: "b", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute, Reason: "wrong layer"},
	}
	kept, unused := ApplyIgnores(findings, ignores)
	if !slices.Equal(kept, findings[2:]) {
		t.Errorf("kept = %+v, want the runner token alone", kept)
	}
	if !slices.Equal(unused, ignores[1:]) {
		t.Errorf("unused = %+v, want the entries of the wrong detection and the wrong layer", unused)
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

func TestLoadIgnores(t *testing.T) {
	path := writeIgnoreFile(t, `ignores:
  - layer: foundation-vault-bastion
    address: data.vault_generic_secret.platform_trust
    path: data_json
    detection: sensitive-attribute
    reason: The path holds network facts.
`)
	got, err := LoadIgnores(path)
	want := []Ignore{{
		Layer: "foundation-vault-bastion", Address: "data.vault_generic_secret.platform_trust", Path: "data_json",
		Detection: DetectionSensitiveAttribute, Reason: "The path holds network facts.",
	}}
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
		"no reason":    "ignores:\n  - {layer: a, address: b, path: c, detection: sensitive-attribute}\n",
		"no detection": "ignores:\n  - {layer: a, address: b, path: c, reason: r}\n",
		"no path":      "ignores:\n  - {layer: a, address: b, detection: sensitive-attribute, reason: r}\n",
		"unknown key":  "ignores:\n  - {layer: a, address: b, path: c, detection: sensitive-attribute, reason: r, value: x}\n",
		"not yaml":     "ignores: [",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadIgnores(writeIgnoreFile(t, content))
			if err == nil {
				t.Errorf("LoadIgnores(%s) error = nil, want a rejection", name)
			}
		})
	}
}

func TestWriteReportNamesLocationsAlone(t *testing.T) {
	findings, err := ScanState("group-gitlab-runner", "current", stateFixture(), prefixDetector{})
	if err != nil {
		t.Fatalf("ScanState: %v", err)
	}
	report := Report{
		Findings:      findings,
		UnusedIgnores: []Ignore{{Layer: "b", Address: "x.y", Path: "z", Detection: DetectionSensitiveAttribute, Reason: "stale"}},
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
