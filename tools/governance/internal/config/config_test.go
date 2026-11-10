package config

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

func TestBootstrapEnvFirstRun(t *testing.T) {
	root := t.TempDir()
	out := ui.New(io.Discard, io.Discard)

	e, err := BootstrapEnv(root, out)
	if err != nil {
		t.Fatalf("BootstrapEnv: %v", err)
	}

	if got := e.Get(KeyProjectRoot); got != root {
		t.Errorf("PROJECT_ROOT = %q, want %q", got, root)
	}
	if got := e.Get(KeySonarQubeDBPassword); got == "" {
		t.Error("SONARQUBE_DB_PASSWORD = empty, want a generated password")
	}
	facts, err := DetectHostFacts()
	if err != nil {
		t.Fatalf("DetectHostFacts: %v", err)
	}
	if got := e.Get(KeyHostUID); got != strconv.Itoa(facts.CurrentUID) {
		t.Errorf("HOST_UID = %q, want %q", got, strconv.Itoa(facts.CurrentUID))
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); err != nil {
		t.Errorf(".env not written: %v", err)
	}
}

func TestBootstrapEnvGeneratesSonarDBPasswordWhenMissingFromExistingFile(t *testing.T) {
	root := t.TempDir()
	out := ui.New(io.Discard, io.Discard)
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte(KeyProjectRoot+"=\""+root+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := BootstrapEnv(root, out)
	if err != nil {
		t.Fatalf("BootstrapEnv: %v", err)
	}
	if got := e.Get(KeySonarQubeDBPassword); got == "" {
		t.Error("SONARQUBE_DB_PASSWORD = empty, want a generated password")
	}
}

// TestBootstrapEnvRefusesSonarDBPasswordRegeneration asserts refusal when .env lacks the password and the data directory exists.
func TestBootstrapEnvRefusesSonarDBPasswordRegeneration(t *testing.T) {
	cases := map[string]string{
		"existing env file": KeyProjectRoot + "=\"/tmp\"\n",
		"missing env file":  "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			envPath := filepath.Join(root, ".env")
			if content != "" {
				if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Join(root, "sonarqube", "postgres-data"), 0o755); err != nil {
				t.Fatal(err)
			}

			_, err := BootstrapEnv(root, ui.New(io.Discard, io.Discard))
			if err == nil || !strings.Contains(err.Error(), KeySonarQubeDBPassword) {
				t.Fatalf("BootstrapEnv = %v, want a refusal which names %s", err, KeySonarQubeDBPassword)
			}
			data, readErr := os.ReadFile(envPath)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if string(data) != content {
				t.Errorf(".env = %q, want the content left as %q", data, content)
			}
		})
	}
}

func TestLoadMissingFileYieldsEmptyEnv(t *testing.T) {
	e, err := Load(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := e.Get("ANYTHING"); got != "" {
		t.Errorf("Get on empty Env = %q, want empty", got)
	}
}

func TestVerifyHostEnvironmentLength(t *testing.T) {
	checks := VerifyHostEnvironment()
	if len(checks) != 3 {
		t.Fatalf("len(checks) = %d, want 3", len(checks))
	}
}
