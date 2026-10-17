// Package vaultops provides Vault TLS certificate generation, initialization, unsealing,
// KV-v2 engine mounting, and root token lifecycle operations.
package vaultops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// Operator coordinates administrative operations against a target Vault instance.
type Operator struct {
	paths  Paths
	client *vaultapi.Client
	out    *ui.Printer
}

// NewOperator builds an Operator against a target Vault server endpoint.
func NewOperator(paths Paths, server vaultclient.Config, out *ui.Printer) (*Operator, error) {
	client, err := vaultclient.NewClient(server)
	if err != nil {
		return nil, fmt.Errorf("vaultops: build client for %s: %w", server.Address, err)
	}
	return &Operator{
		paths:  paths,
		client: client,
		out:    out,
	}, nil
}

// Init initializes Vault with 3-of-5 Shamir secret shares, persists unseal keys and the root token,
// and unseals the instance.
func (op *Operator) Init(ctx context.Context) error {
	if _, err := os.Stat(op.paths.InitFile()); err == nil {
		return fmt.Errorf("vaultops: %s already exists, refusing to re-init", op.paths.InitFile())
	}

	resp, err := op.client.Sys().InitWithContext(ctx, &vaultapi.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		return fmt.Errorf("vaultops: vault init against %s: %w", op.client.Address(), err)
	}

	if resp.RootToken == "" {
		return errors.New("vaultops: empty root_token in init response")
	}

	if err := op.persistInitOutput(resp); err != nil {
		return err
	}

	op.out.Print(ui.Info, "Keys saved to "+op.paths.KeysDir())

	if err := vaultclient.PersistTokenFile(op.paths.Home, resp.RootToken); err != nil {
		return err
	}
	if err := op.Unseal(ctx); err != nil {
		return fmt.Errorf("vaultops: auto-unseal after init: %w", err)
	}

	op.out.Print(ui.OK, "Vault is ready for use.")
	return nil
}

// Unseal applies stored unseal keys until the Vault instance reports an unsealed state.
func (op *Operator) Unseal(ctx context.Context) error {
	keysRaw, err := os.ReadFile(op.paths.UnsealKeyFile())
	if err != nil {
		return fmt.Errorf("vaultops: unseal keys not found at %s, run Init first: %w", op.paths.UnsealKeyFile(), err)
	}

	status, err := op.client.Sys().SealStatusWithContext(ctx)
	if err == nil && !status.Sealed {
		op.out.Print(ui.Info, "Vault is already unsealed.")
		return nil
	}

	for _, key := range strings.Split(strings.TrimSpace(string(keysRaw)), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, err := op.client.Sys().UnsealWithContext(ctx, key); err != nil {
			return fmt.Errorf("vaultops: unseal: %w", err)
		}
	}

	if err := op.waitUntilUnsealed(ctx, 10*time.Second); err != nil {
		return err
	}

	op.out.Print(ui.OK, "Vault is unsealed and ready.")
	return nil
}

// EnableKVEngine mounts the kv-v2 secrets engine at secret/ when the mount is absent.
func (op *Operator) EnableKVEngine(ctx context.Context) error {
	token := vaultclient.ReadTokenFile(op.paths.Home)
	if token == "" {
		return fmt.Errorf("vaultops: root token not found at %s", op.paths.RootTokenFile())
	}

	client, err := op.client.Clone()
	if err != nil {
		return fmt.Errorf("vaultops: clone client: %w", err)
	}
	client.SetToken(token)

	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err == nil {
		if _, exists := mounts["secret/"]; exists {
			op.out.Print(ui.Info, "kv-v2 secrets engine is already enabled.")
			return nil
		}
	}

	op.out.Print(ui.Task, "'secret/' path not found, enabling kv-v2...")
	if err := client.Sys().MountWithContext(ctx, "secret", &vaultapi.MountInput{Type: "kv-v2"}); err != nil {
		return fmt.Errorf("vaultops: enable kv-v2: %w", err)
	}
	return nil
}

func (op *Operator) persistInitOutput(resp *vaultapi.InitResponse) error {
	keysDir := op.paths.KeysDir()
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return fmt.Errorf("vaultops: mkdir %s: %w", keysDir, err)
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("vaultops: marshal init response: %w", err)
	}
	if err := os.WriteFile(op.paths.InitFile(), raw, 0o600); err != nil {
		return fmt.Errorf("vaultops: write %s: %w", op.paths.InitFile(), err)
	}
	if len(resp.KeysB64) == 0 {
		return errors.New("vaultops: the init response does not contain unseal keys")
	}
	if err := os.WriteFile(op.paths.UnsealKeyFile(), []byte(strings.Join(resp.KeysB64, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("vaultops: write %s: %w", op.paths.UnsealKeyFile(), err)
	}
	return nil
}

func (op *Operator) waitUntilUnsealed(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		status, err := op.client.Sys().SealStatusWithContext(ctx)
		if err == nil && !status.Sealed {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return fmt.Errorf("vaultops: still reporting sealed after %v of unseal attempts", timeout)
}
