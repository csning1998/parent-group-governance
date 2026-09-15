// Package vaultops provides Bastion Vault TLS, initialization, unseal, and status operations.
package vaultops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

// Paths groups all project-relative and user-relative paths needed by Vault operations.
type Paths struct {
	ProjectRoot      string
	AnsibleDir       string
	Home             string
	bastionVaultAddr string
}

// NewPaths constructs Paths for a caller outside this package.
func NewPaths(projectRoot, ansibleDir, home, bastionVaultAddr string) Paths {
	return Paths{
		ProjectRoot:      projectRoot,
		AnsibleDir:       ansibleDir,
		Home:             home,
		bastionVaultAddr: bastionVaultAddr,
	}
}

func (p Paths) resolveBastionAddr() string {
	if p.bastionVaultAddr != "" {
		return p.bastionVaultAddr
	}
	return "https://172.16.0.1:8200"
}

func (p Paths) resolveKeysDir() string       { return filepath.Join(p.ProjectRoot, "vault", "keys") }
func (p Paths) resolveTLSDir() string        { return filepath.Join(p.ProjectRoot, "vault", "tls") }
func (p Paths) resolveInitFile() string      { return filepath.Join(p.resolveKeysDir(), "init-output.json") }
func (p Paths) resolveUnsealKeyFile() string { return filepath.Join(p.resolveKeysDir(), "unseal.key") }
func (p Paths) resolveRootTokenFile() string { return filepath.Join(p.Home, ".vault-token") }
func (p Paths) resolveCACertFile() string    { return filepath.Join(p.resolveTLSDir(), "ca.pem") }

func newClient(addr, caCertPath, token string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	if caCertPath != "" {
		if err := cfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: caCertPath}); err != nil {
			return nil, fmt.Errorf("vaultops: configure TLS from %s: %w", caCertPath, err)
		}
	}
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vaultops: new client for %s: %w", addr, err)
	}
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}

func (p Paths) newBastionClientWithToken(token string) (*vaultapi.Client, error) {
	return newClient(p.resolveBastionAddr(), p.resolveCACertFile(), token)
}

// SealStatus records reachability, initialization, and seal state for one Vault instance.
type SealStatus struct {
	Reachable   bool
	Initialized bool
	Sealed      bool
}

// InspectTargetStatus queries the Vault instance at addr, verifying its TLS certificate against
// caCert. A zero SealStatus means the instance did not response.
func InspectTargetStatus(ctx context.Context, addr, caCert string) SealStatus {
	client, err := newClient(addr, caCert, "")
	if err != nil {
		return SealStatus{}
	}
	st, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return SealStatus{}
	}
	return SealStatus{Reachable: true, Initialized: st.Initialized, Sealed: st.Sealed}
}

// InspectBastionStatus queries the full seal status of Bastion Vault.
func InspectBastionStatus(ctx context.Context, p Paths) SealStatus {
	return InspectTargetStatus(ctx, p.resolveBastionAddr(), p.resolveCACertFile())
}

// ProbeBastionState checks whether Bastion Vault is reachable and reports its sealed state.
func ProbeBastionState(ctx context.Context, p Paths) (running, sealed bool, err error) {
	client, err := p.newBastionClientWithToken("")
	if err != nil {
		return false, false, err
	}
	st, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return false, false, nil
	}
	return true, st.Sealed, nil
}

// SyncVaultToken extracts the root token from the initialization file or existing token file and updates the environment.
func SyncVaultToken(p Paths, env interface{ Set(string, string) }) (string, error) {
	var token string

	if data, err := os.ReadFile(p.resolveInitFile()); err == nil {
		var init struct {
			RootToken string `json:"root_token"`
		}
		if err := json.Unmarshal(data, &init); err != nil {
			return "", fmt.Errorf("vaultops: parse %s: %w", p.resolveInitFile(), err)
		}
		token = init.RootToken
	} else if data, err := os.ReadFile(p.resolveRootTokenFile()); err == nil {
		token = strings.TrimSpace(string(data))
	} else {
		return "", nil
	}

	if token == "" {
		return "", fmt.Errorf("vaultops: failed to extract a valid token")
	}

	env.Set("VAULT_TOKEN", token)

	tmp := p.resolveRootTokenFile() + fmt.Sprintf(".tmp%d", time.Now().UnixNano())
	if err := os.WriteFile(tmp, []byte(token), 0o600); err != nil {
		return "", fmt.Errorf("vaultops: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, p.resolveRootTokenFile()); err != nil {
		return "", fmt.Errorf("vaultops: replace %s: %w", p.resolveRootTokenFile(), err)
	}
	return token, nil
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

// Init initializes Bastion Vault with Shamir secret shares, persists unseal keys, and performs initial unseal.
func Init(ctx context.Context, p Paths, out *ui.Printer, env interface{ Set(string, string) }) error {
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

	if _, err := SyncVaultToken(p, env); err != nil {
		return err
	}
	if err := UnsealBastion(ctx, p, out, env); err != nil {
		return fmt.Errorf("vaultops: auto-unseal after init: %w", err)
	}

	out.Print(ui.OK, "Bastion Vault is ready for use.")
	return nil
}

// UnsealBastion applies stored unseal keys to Bastion Vault until the sealed flag clears.
func UnsealBastion(ctx context.Context, p Paths, out *ui.Printer, env interface{ Set(string, string) }) error {
	keysRaw, err := os.ReadFile(p.resolveUnsealKeyFile())
	if err != nil {
		return fmt.Errorf("vaultops: unseal keys not found at %s, run Init first: %w", p.resolveUnsealKeyFile(), err)
	}

	if _, sealed, err := ProbeBastionState(ctx, p); err == nil && !sealed {
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
	return syncSessionTokenIfPresent(p, out, env)
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

// waitUntilUnsealed polls the Bastion Vault sealed flag until the flag clears or timeout elapses.
func waitUntilUnsealed(ctx context.Context, p Paths, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, sealed, err := ProbeBastionState(ctx, p); err == nil && !sealed {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("vaultops: still reporting sealed after 5s of unseal attempts")
}

// syncSessionTokenIfPresent copies the root token into env when Init has already written one.
func syncSessionTokenIfPresent(p Paths, out *ui.Printer, env interface{ Set(string, string) }) error {
	if _, statErr := os.Stat(p.resolveRootTokenFile()); statErr != nil {
		return nil
	}
	if _, err := SyncVaultToken(p, env); err != nil {
		return err
	}
	out.Print(ui.Info, "Vault environment variables set for this session.")
	return nil
}

// EnableKVEngine enables the kv-v2 secrets engine at secret/ if not already mounted.
func EnableKVEngine(ctx context.Context, p Paths, out *ui.Printer) error {
	tokenRaw, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil {
		return fmt.Errorf("vaultops: root token not found at %s: %w", p.resolveRootTokenFile(), err)
	}
	client, err := p.newBastionClientWithToken(strings.TrimSpace(string(tokenRaw)))
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

// NewAuthenticatedBastionClient builds a Bastion Vault client authenticated with the root token persisted at
// Paths' resolveRootTokenFile location.
func NewAuthenticatedBastionClient(p Paths) (*vaultapi.Client, error) {
	tokenRaw, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil {
		return nil, fmt.Errorf("vaultops: root token not found at %s: %w", p.resolveRootTokenFile(), err)
	}
	return p.newBastionClientWithToken(strings.TrimSpace(string(tokenRaw)))
}
