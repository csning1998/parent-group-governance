package vaultenv

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestNamesCoverTheVaultAPIEnvironment(t *testing.T) {
	read := []string{
		vaultapi.EnvVaultAddress,
		vaultapi.EnvVaultAgentAddr,
		vaultapi.EnvVaultCACert,
		vaultapi.EnvVaultCACertBytes,
		vaultapi.EnvVaultCAPath,
		vaultapi.EnvVaultClientCert,
		vaultapi.EnvVaultClientKey,
		vaultapi.EnvVaultClientTimeout,
		vaultapi.EnvVaultHeaders,
		vaultapi.EnvVaultSRVLookup,
		vaultapi.EnvVaultSkipVerify,
		vaultapi.EnvVaultNamespace,
		vaultapi.EnvVaultTLSServerName,
		vaultapi.EnvVaultWrapTTL,
		vaultapi.EnvVaultMaxRetries,
		vaultapi.EnvVaultToken,
		vaultapi.EnvVaultMFA,
		vaultapi.EnvRateLimit,
		vaultapi.EnvHTTPProxy,
		vaultapi.EnvVaultProxyAddr,
		vaultapi.EnvVaultDisableRedirects,
	}
	for _, name := range read {
		if !slices.Contains(Names, name) {
			t.Errorf("Names lacks %s, which the Vault API client reads", name)
		}
	}
}

func TestClearRemovesEveryVaultVariable(t *testing.T) {
	for _, name := range Names {
		t.Setenv(name, "ambient")
	}
	t.Setenv("GOVERNANCE_VAULTENV_UNRELATED", "kept")

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	for _, name := range Names {
		if value, ok := os.LookupEnv(name); ok {
			t.Errorf("%s = %q after Clear, want unset", name, value)
		}
	}
	if got := os.Getenv("GOVERNANCE_VAULTENV_UNRELATED"); got != "kept" {
		t.Errorf("GOVERNANCE_VAULTENV_UNRELATED = %q, want kept", got)
	}
}

// A CA path of a wiped TLS directory reproduces the bootstrap failure of the CLI and the test suites.
func TestClearLetsAClientIgnoreAnAmbientCACertWhichDoesNotExist(t *testing.T) {
	t.Setenv(vaultapi.EnvVaultCACert, filepath.Join(t.TempDir(), "absent", "ca.pem"))

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	_, err := vaultclient.NewClient(vaultclient.Config{Address: "http://127.0.0.1:8200"})
	if err != nil {
		t.Errorf("NewClient after Clear: %v", err)
	}
}
