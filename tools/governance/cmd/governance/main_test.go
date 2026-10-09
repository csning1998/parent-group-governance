package main

import (
	"os"
	"path/filepath"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
)

// The CLI configures every Vault client explicitly, hence an ambient variable such as VAULT_SKIP_VERIFY never applies.
func TestExecuteClearsTheVaultEnvironmentBeforeAnyCommand(t *testing.T) {
	t.Setenv(vaultapi.EnvVaultSkipVerify, "true")
	t.Setenv(vaultapi.EnvVaultCACert, "/nonexistent/ca.pem")

	if code := execute([]string{"--help"}); code != 0 {
		t.Fatalf("execute(--help) = %d, want 0", code)
	}

	for _, name := range []string{vaultapi.EnvVaultSkipVerify, vaultapi.EnvVaultCACert} {
		if value, ok := os.LookupEnv(name); ok {
			t.Errorf("%s = %q after execute, want unset", name, value)
		}
	}
}

// Ansible, Terraform, and the CLI share workstation-topology.yaml, hence a checkout without the file runs no command.
func TestExecuteFailsWithoutTheTopologyFile(t *testing.T) {
	root := t.TempDir()
	err := os.Mkdir(filepath.Join(root, ".git"), 0o755)
	if err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	t.Chdir(root)

	if code := execute([]string{"--help"}); code != 1 {
		t.Errorf("execute(--help) = %d, want 1 without %s", code, topology.FileName)
	}
}
