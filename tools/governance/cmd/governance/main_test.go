package main

import (
	"os"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
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
