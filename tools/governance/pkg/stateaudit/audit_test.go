package stateaudit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeSource serves current states and historical versions from memory.
type fakeSource struct {
	current  map[string][]byte
	versions map[string]map[int][]byte
	failing  string
	missing  string
}

func (s fakeSource) FetchCurrent(_ context.Context, address string) ([]byte, error) {
	if address == s.failing {
		return nil, errors.New("backend returned 503")
	}
	if address == s.missing {
		return nil, ErrStateMissing
	}
	return s.current[address], nil
}

func (s fakeSource) FetchVersion(_ context.Context, address string, serial int) ([]byte, error) {
	document, ok := s.versions[address][serial]
	if !ok {
		return nil, ErrVersionMissing
	}
	return document, nil
}

func cleanState(serial string) []byte {
	return []byte(`{"version": 4, "serial": ` + serial + `, "resources": []}`)
}

func runnerState(serial string) []byte {
	return []byte(`{"version": 4, "serial": ` + serial + `, "resources": [
  {"mode": "managed", "type": "gitlab_user_runner", "name": "shared", "instances": [
    {"attributes": {"token": "` + fakeRunner + `"}, "sensitive_attributes": [[{"type": "get_attr", "value": "token"}]]}
  ]}
]}`)
}

func twoLayerConfig() Config {
	return Config{
		Layers: []Layer{{Name: "a", Address: "https://state/a"}, {Name: "b", Address: "https://state/b"}},
		Source: fakeSource{
			current: map[string][]byte{"https://state/a": cleanState("3"), "https://state/b": runnerState("1")},
			versions: map[string]map[int][]byte{
				"https://state/a": {2: runnerState("2")},
			},
		},
		Detector: prefixDetector{},
	}
}

func TestAuditCurrentStates(t *testing.T) {
	report, err := Audit(context.Background(), twoLayerConfig())
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	want := []Finding{{Layer: "b", Version: "current", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute}}
	if !slices.Equal(report.Findings, want) || !slices.Equal(report.Scanned, []string{"a@current", "b@current"}) {
		t.Errorf("Audit = %+v, want the runner token of b in two current states", report)
	}
}

func TestAuditHistory(t *testing.T) {
	cfg := twoLayerConfig()
	cfg.History = true

	report, err := Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !slices.Contains(report.Findings, Finding{Layer: "a", Version: "serial-2", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute}) {
		t.Errorf("findings = %+v, want the runner token of a at serial 2", report.Findings)
	}
	if !slices.Equal(report.Scanned, []string{"a@current", "a@serial-2", "b@current"}) {
		t.Errorf("scanned = %q, want a@current, a@serial-2, b@current", report.Scanned)
	}
}

func TestAuditAppliesIgnores(t *testing.T) {
	cfg := twoLayerConfig()
	cfg.Ignores = []Ignore{
		{Layer: "b", Address: "gitlab_user_runner.shared", Path: "token", Detection: DetectionSensitiveAttribute, Reason: "test"},
		{Layer: "a", Address: "x.y", Path: "z", Detection: DetectionSensitiveAttribute, Reason: "stale"},
	}
	report, err := Audit(context.Background(), cfg)
	if err != nil || len(report.Findings) != 0 || !slices.Equal(report.UnusedIgnores, cfg.Ignores[1:]) {
		t.Errorf("Audit = %+v, %v, want no finding and the stale entry unused", report, err)
	}
}

func TestAuditStopsOnSourceFailure(t *testing.T) {
	cfg := twoLayerConfig()
	source := cfg.Source.(fakeSource)
	source.failing = "https://state/b"
	cfg.Source = source

	_, err := Audit(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "b") || !strings.Contains(err.Error(), "503") {
		t.Errorf("Audit error = %v, want the failure of layer b", err)
	}
}

func TestRun(t *testing.T) {
	cases := []struct {
		name    string
		cfg     func() Config
		wantErr error
		want    string
	}{
		{"finding", twoLayerConfig, ErrFindings, "gitlab_user_runner.shared"},
		{"clean", func() Config {
			cfg := twoLayerConfig()
			cfg.Layers = cfg.Layers[:1]
			return cfg
		}, nil, "0 finding"},
		{"unused ignore", func() Config {
			cfg := twoLayerConfig()
			cfg.Layers = cfg.Layers[:1]
			cfg.Ignores = []Ignore{{Layer: "a", Address: "x.y", Path: "z", Detection: DetectionSensitiveAttribute, Reason: "stale"}}
			return cfg
		}, ErrFindings, "x.y"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Run(context.Background(), c.cfg(), &out)
			if !errors.Is(err, c.wantErr) || !strings.Contains(out.String(), c.want) {
				t.Errorf("Run = %v with %q, want %v with %q", err, out.String(), c.wantErr, c.want)
			}
		})
	}
}

func TestConfigFromEnv(t *testing.T) {
	terraformDir := t.TempDir()
	writeLayer(t, filepath.Join(terraformDir, "layers"), "a",
		"terraform {\n  backend \"http\" {\n    address = \"https://gitlab.com/api/v4/projects/1/terraform/state/a\"\n  }\n}\n")
	err := os.WriteFile(filepath.Join(terraformDir, IgnoreFileName),
		[]byte("ignores:\n  - {layer: a, address: x.y, path: z, detection: sensitive-attribute, reason: test}\n"), 0o600)
	if err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	env := map[string]string{"TF_HTTP_USERNAME": "gitlab-ci-token", "TF_HTTP_PASSWORD": "backend-secret"}

	cfg, err := ConfigFromEnv(terraformDir, func(key string) string { return env[key] }, true)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	source, ok := cfg.Source.(HTTPSource)
	if !ok || source.Username != "gitlab-ci-token" || source.Password != "backend-secret" || source.Client == nil {
		t.Errorf("Source = %+v, want an HTTPSource of the TF_HTTP credentials", cfg.Source)
	}
	if len(cfg.Layers) != 1 || len(cfg.Ignores) != 1 || !cfg.History || cfg.Detector == nil {
		t.Errorf("Config = %+v, want one layer, one ignore entry, history, and a detector", cfg)
	}
}

func TestConfigFromEnvRequiresCredentials(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no password": {"TF_HTTP_USERNAME": "gitlab-ci-token"},
		"no username": {"TF_HTTP_PASSWORD": "backend-secret"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ConfigFromEnv(t.TempDir(), func(key string) string { return env[key] }, false)
			if !errors.Is(err, ErrCredentialsMissing) {
				t.Errorf("ConfigFromEnv error = %v, want ErrCredentialsMissing", err)
			}
		})
	}
}

func TestNewCommand(t *testing.T) {
	var gotHistory []bool
	cmd := NewCommand(func(history bool) (Config, error) {
		gotHistory = append(gotHistory, history)
		cfg := twoLayerConfig()
		cfg.Layers = cfg.Layers[:1]
		return cfg, nil
	})
	flag := cmd.Flags().Lookup("history")
	if cmd.Name() != "state-audit" || flag == nil || flag.DefValue != "false" {
		t.Fatalf("command %q, flag %v, want state-audit with --history defaulting to false", cmd.Name(), flag)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--history"})
	err := cmd.Execute()
	if err != nil || !slices.Equal(gotHistory, []bool{true}) || !strings.Contains(out.String(), "0 finding") {
		t.Errorf("Execute = %v, history %v, output %q", err, gotHistory, out.String())
	}
}

func TestNewCommandReturnsTheResolveFailure(t *testing.T) {
	cmd := NewCommand(func(bool) (Config, error) { return Config{}, ErrCredentialsMissing })
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if !errors.Is(err, ErrCredentialsMissing) {
		t.Errorf("Execute error = %v, want ErrCredentialsMissing", err)
	}
}

func TestAuditSkipsALayerWithoutState(t *testing.T) {
	cfg := twoLayerConfig()
	source := cfg.Source.(fakeSource)
	source.missing = "https://state/a"
	cfg.Source = source

	report, err := Audit(context.Background(), cfg)
	if err != nil || !slices.Equal(report.Scanned, []string{"b@current"}) {
		t.Errorf("Audit = %+v, %v, want layer a skipped and b scanned", report, err)
	}
}
