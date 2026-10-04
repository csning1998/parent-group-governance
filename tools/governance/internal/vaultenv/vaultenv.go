// Package vaultenv removes the ambient Vault environment, since the governance CLI configures every Vault client explicitly.
package vaultenv

import (
	"fmt"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

// Names lists every variable which the Vault API client reads from the process environment.
var Names = []string{
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

// Clear removes every variable of Names from the process environment.
func Clear() error {
	for _, name := range Names {
		err := os.Unsetenv(name)
		if err != nil {
			return fmt.Errorf("vaultenv: unset %s: %w", name, err)
		}
	}
	return nil
}
