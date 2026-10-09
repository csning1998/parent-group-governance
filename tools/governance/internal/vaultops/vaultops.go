// Package vaultops provides Bastion Vault TLS, initialization, unseal, and status operations.
package vaultops

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// Paths groups all project-relative and user-relative paths needed by Vault operations.
type Paths struct {
	ProjectRoot      string
	AnsibleDir       string
	Home             string
	bastionVaultAddr string
	listenerIPs      []net.IP
}

// NewPaths constructs Paths for a caller outside this package, with the Bastion Vault of workstation-topology.yaml.
func NewPaths(projectRoot, ansibleDir, home string, bastion topology.BastionVault) Paths {
	return Paths{
		ProjectRoot:      projectRoot,
		AnsibleDir:       ansibleDir,
		Home:             home,
		bastionVaultAddr: bastion.APIEndpoint(),
		listenerIPs:      bastion.ListenerIPs(),
	}
}

// ResolveTLSDir returns the directory of the local CA and the Bastion Vault listener certificate.
func (p Paths) ResolveTLSDir() string { return filepath.Join(p.ProjectRoot, "vault", "tls") }

func (p Paths) newBastionClientWithToken(token string) (*vaultapi.Client, error) {
	return newClient(p.resolveBastionAddr(), p.resolveCACertFile(), token)
}

func (p Paths) resolveBastionAddr() string { return p.bastionVaultAddr }

func (p Paths) resolveCACertFile() string { return filepath.Join(p.ResolveTLSDir(), "ca.pem") }

func (p Paths) resolveInitFile() string { return filepath.Join(p.resolveKeysDir(), "init-output.json") }

func (p Paths) resolveKeysDir() string { return filepath.Join(p.ProjectRoot, "vault", "keys") }

func (p Paths) resolveRootTokenFile() string { return filepath.Join(p.Home, ".vault-token") }

func (p Paths) resolveUnsealKeyFile() string { return filepath.Join(p.resolveKeysDir(), "unseal.key") }

// SealStatus records reachability, initialization, and seal state for one Vault instance.
type SealStatus = vaultclient.SealStatus

// InspectBastionStatus queries the full seal status of Bastion Vault.
func InspectBastionStatus(ctx context.Context, p Paths) SealStatus {
	return vaultclient.InspectStatus(ctx, vaultclient.Config{
		Address:    p.resolveBastionAddr(),
		CACertPath: p.resolveCACertFile(),
	})
}

// ProbeBastionSealState checks whether Bastion Vault is reachable and reports its sealed state.
func ProbeBastionSealState(ctx context.Context, p Paths) (running, sealed bool, err error) {
	client, err := p.newBastionClientWithToken("")
	if err != nil {
		return false, false, err
	}
	return vaultclient.ProbeSealState(ctx, client)
}

// Init initializes Bastion Vault with Shamir secret shares, persists unseal keys, and performs initial unseal.
func Init(ctx context.Context, p Paths, out *ui.Printer) error {
	if _, err := os.Stat(p.resolveInitFile()); err == nil {
		return fmt.Errorf("vaultops: %s already exists, refusing to re-init", p.resolveInitFile())
	}

	client, err := p.newBastionClientWithToken("")
	if err != nil {
		return err
	}
	resp, err := client.Sys().InitWithContext(ctx, &vaultapi.InitRequest{SecretShares: 5, SecretThreshold: 3})
	if err != nil {
		return fmt.Errorf("vaultops: vault init against %s: %w", p.resolveBastionAddr(), err)
	}

	if err := persistInitOutput(p, resp); err != nil {
		return err
	}

	out.Print(ui.Info, "Keys saved to "+p.resolveKeysDir())

	if err := persistBootstrapRootToken(p); err != nil {
		return err
	}
	if err := Unseal(ctx, p, out); err != nil {
		return fmt.Errorf("vaultops: auto-unseal after init: %w", err)
	}

	out.Print(ui.OK, "Bastion Vault is ready for use.")
	return nil
}

// Unseal applies stored unseal keys to Bastion Vault until the sealed flag clears.
func Unseal(ctx context.Context, p Paths, out *ui.Printer) error {
	keysRaw, err := os.ReadFile(p.resolveUnsealKeyFile())
	if err != nil {
		return fmt.Errorf("vaultops: unseal keys not found at %s, run Init first: %w", p.resolveUnsealKeyFile(), err)
	}

	if _, sealed, err := ProbeBastionSealState(ctx, p); err == nil && !sealed {
		out.Print(ui.Info, "Bastion Vault is already unsealed.")
		return nil
	}

	client, err := p.newBastionClientWithToken("")
	if err != nil {
		return err
	}
	if err := applyUnsealKeys(ctx, client, keysRaw); err != nil {
		return err
	}
	if err := waitUntilUnsealed(ctx, p, 10*time.Second); err != nil {
		return err
	}

	out.Print(ui.OK, "Bastion Vault Unsealed and ready.")
	return nil
}

// EnableKVEngine enables the kv-v2 secrets engine at secret/ if not already mounted.
func EnableKVEngine(ctx context.Context, p Paths, out *ui.Printer) error {
	token := vaultclient.ReadTokenFile(p.Home)
	if token == "" {
		return fmt.Errorf("vaultops: root token not found at %s", p.resolveRootTokenFile())
	}
	client, err := p.newBastionClientWithToken(token)
	if err != nil {
		return err
	}

	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err == nil {
		if _, exists := mounts["secret/"]; exists {
			out.Print(ui.Info, "kv-v2 secrets engine is already enabled.")
			return nil
		}
	}

	out.Print(ui.Task, "'secret/' path not found, enabling kv-v2...")
	if err := client.Sys().MountWithContext(ctx, "secret", &vaultapi.MountInput{Type: "kv-v2"}); err != nil {
		return fmt.Errorf("vaultops: enable kv-v2: %w", err)
	}
	return nil
}

// applyUnsealKeys submits every non-blank line of keysRaw to the Vault unseal endpoint in order.
func applyUnsealKeys(ctx context.Context, client *vaultapi.Client, keysRaw []byte) error {
	for _, key := range strings.Split(strings.TrimSpace(string(keysRaw)), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, err := client.Sys().UnsealWithContext(ctx, key); err != nil {
			return fmt.Errorf("vaultops: unseal: %w", err)
		}
	}
	return nil
}

func newClient(addr, caCertPath, token string) (*vaultapi.Client, error) {
	return vaultclient.NewClient(vaultclient.Config{
		Address:    addr,
		CACertPath: caCertPath,
		Token:      token,
	})
}

// persistBootstrapRootToken writes the root token of the initialization to the token helper file, which the bootstrap
// steps read until RevokeRoot.
func persistBootstrapRootToken(p Paths) error {
	data, err := os.ReadFile(p.resolveInitFile())
	if err != nil {
		return fmt.Errorf("vaultops: read %s: %w", p.resolveInitFile(), err)
	}
	var init struct {
		RootToken string `json:"root_token"`
	}
	if err := json.Unmarshal(data, &init); err != nil {
		return fmt.Errorf("vaultops: parse %s: %w", p.resolveInitFile(), err)
	}
	if init.RootToken == "" {
		return fmt.Errorf("vaultops: %s contains empty root_token", p.resolveInitFile())
	}
	return vaultclient.PersistTokenFile(p.Home, init.RootToken)
}

func persistInitOutput(p Paths, resp *vaultapi.InitResponse) error {
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		return fmt.Errorf("vaultops: mkdir %s: %w", p.resolveKeysDir(), err)
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("vaultops: marshal init response: %w", err)
	}
	if err := os.WriteFile(p.resolveInitFile(), raw, 0o600); err != nil {
		return fmt.Errorf("vaultops: write %s: %w", p.resolveInitFile(), err)
	}
	if len(resp.KeysB64) == 0 {
		return fmt.Errorf("vaultops: no unseal keys in init response")
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte(strings.Join(resp.KeysB64, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("vaultops: write %s: %w", p.resolveUnsealKeyFile(), err)
	}
	return nil
}

// waitUntilUnsealed polls the Bastion Vault sealed flag until the flag clears or timeout elapses.
func waitUntilUnsealed(ctx context.Context, p Paths, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, sealed, err := ProbeBastionSealState(ctx, p); err == nil && !sealed {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("vaultops: still reporting sealed after %v of unseal attempts", timeout)
}
