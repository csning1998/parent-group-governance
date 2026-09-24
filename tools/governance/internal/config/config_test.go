package config

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

func TestLoadMissingFileYieldsEmptyEnv(t *testing.T) {
	e, err := Load(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := e.Get("ANYTHING"); got != "" {
		t.Errorf("Get on empty Env = %q, want empty", got)
	}
}

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
	if got := e.Get(KeyBastionVaultAddr); got != "https://127.0.0.1:8200" {
		t.Errorf("BASTION_VAULT_ADDR = %q", got)
	}
	if got := e.Get(KeyBastionVaultCACert); got != "${PROJECT_ROOT}/vault/tls/ca.pem" {
		t.Errorf("BASTION_VAULT_CACERT = %q", got)
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

func TestVerifyHostEnvironmentLength(t *testing.T) {
	checks := VerifyHostEnvironment()
	if len(checks) != 3 {
		t.Fatalf("len(checks) = %d, want 3", len(checks))
	}
}
