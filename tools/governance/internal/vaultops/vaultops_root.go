package vaultops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

var (
	// ErrNoRootToken reports a token helper file without a live root token.
	ErrNoRootToken = errors.New("vaultops: ~/.vault-token holds no live root token")
	// ErrFoundationNotReady reports a foundation identity without a login, which a revocation would leave as the only
	// administrator of the Bastion Vault.
	ErrFoundationNotReady = errors.New("vaultops: the foundation Vault Proxy holds no login with its policy")
	// ErrRootTokenPresent reports a token helper file which already holds a token before a new root token.
	ErrRootTokenPresent = errors.New("vaultops: ~/.vault-token already holds a token, run revoke-root first")
	// ErrGenerateRootInProgress reports an unfinished generate-root attempt, which this CLI did not start.
	ErrGenerateRootInProgress = errors.New("vaultops: a generate-root attempt is in progress, cancel it with vault operator generate-root -cancel")
)

// GenerateRoot produces a root token for break-glass from the stored unseal keys and writes the token to the token
// helper file. RevokeRoot revokes the token after the work.
func GenerateRoot(ctx context.Context, p Paths, out *ui.Printer) error {
	if vaultclient.ReadTokenFile(p.Home) != "" {
		return ErrRootTokenPresent
	}
	keysRaw, err := os.ReadFile(p.resolveUnsealKeyFile())
	if err != nil {
		return fmt.Errorf("vaultops: unseal keys not found at %s: %w", p.resolveUnsealKeyFile(), err)
	}

	client, err := p.newBastionClientWithToken("")
	if err != nil {
		return err
	}
	status, err := client.Sys().GenerateRootStatusWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vaultops: generate-root status: %w", err)
	}
	if status.Started {
		return ErrGenerateRootInProgress
	}
	attempt, err := client.Sys().GenerateRootInitWithContext(ctx, "", "")
	if err != nil {
		return fmt.Errorf("vaultops: generate-root init: %w", err)
	}

	encoded, err := submitGenerateRootKeys(ctx, client, attempt.Nonce, keysRaw)
	if err != nil {
		_ = client.Sys().GenerateRootCancelWithContext(context.WithoutCancel(ctx))
		return err
	}
	token, err := decodeRootToken(encoded, attempt.OTP)
	if err != nil {
		return err
	}
	if err := vaultclient.PersistTokenFile(p.Home, token); err != nil {
		return err
	}
	out.Print(ui.Warn, "Root token written to ~/.vault-token. Run ./governance vault revoke-root after the break-glass work.")
	return nil
}

// RevokeRoot revokes the root token of the token helper file after the bootstrap, once the foundation identity logs in
// through its Proxy with foundationPolicy. The token helper file and the root_token of the initialization file go away.
func RevokeRoot(ctx context.Context, p Paths, foundation vaultclient.Config, foundationPolicy string, out *ui.Printer) error {
	token := vaultclient.ReadTokenFile(p.Home)
	if token == "" {
		return ErrNoRootToken
	}

	foundationClient, err := vaultclient.NewClient(foundation)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFoundationNotReady, err)
	}
	self, err := foundationClient.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || !holdsPolicy(self, foundationPolicy) {
		return fmt.Errorf("%w: %s at %s", ErrFoundationNotReady, foundationPolicy, foundation.Address)
	}

	rootClient, err := p.newBastionClientWithToken(token)
	if err != nil {
		return err
	}
	rootSelf, err := rootClient.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || !holdsPolicy(rootSelf, "root") {
		return ErrNoRootToken
	}
	if err := rootClient.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
		return fmt.Errorf("vaultops: revoke the root token: %w", err)
	}

	if err := vaultclient.RemoveTokenFile(p.Home); err != nil {
		return err
	}
	if err := clearInitRootToken(p); err != nil {
		return err
	}
	out.Print(ui.OK, "Root token revoked. ./governance vault generate-root restores one for break-glass.")
	return nil
}

// clearInitRootToken empties root_token of the initialization file and keeps every other field.
func clearInitRootToken(p Paths) error {
	data, err := os.ReadFile(p.resolveInitFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vaultops: read %s: %w", p.resolveInitFile(), err)
	}
	var init map[string]any
	if err := json.Unmarshal(data, &init); err != nil {
		return fmt.Errorf("vaultops: parse %s: %w", p.resolveInitFile(), err)
	}
	init["root_token"] = ""
	raw, err := json.Marshal(init)
	if err != nil {
		return fmt.Errorf("vaultops: marshal %s: %w", p.resolveInitFile(), err)
	}
	if err := os.WriteFile(p.resolveInitFile(), raw, 0o600); err != nil {
		return fmt.Errorf("vaultops: write %s: %w", p.resolveInitFile(), err)
	}
	return nil
}

// decodeRootToken reverses the encoding of Vault, which XORs the token with the one-time password and applies
// unpadded standard base64.
func decodeRootToken(encoded, otp string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("vaultops: decode the encoded root token: %w", err)
	}
	if len(raw) != len(otp) {
		return "", fmt.Errorf("vaultops: the encoded root token holds %d bytes, while the one-time password holds %d", len(raw), len(otp))
	}
	token := make([]byte, len(raw))
	for i := range raw {
		token[i] = raw[i] ^ otp[i]
	}
	return string(token), nil
}

func holdsPolicy(secret *vaultapi.Secret, policy string) bool {
	if secret == nil {
		return false
	}
	policies, err := secret.TokenPolicies()
	return err == nil && slices.Contains(policies, policy)
}

// submitGenerateRootKeys submits unseal keys until the attempt completes, and returns the encoded root token.
func submitGenerateRootKeys(ctx context.Context, client *vaultapi.Client, nonce string, keysRaw []byte) (string, error) {
	for _, key := range strings.Split(strings.TrimSpace(string(keysRaw)), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		status, err := client.Sys().GenerateRootUpdateWithContext(ctx, key, nonce)
		if err != nil {
			return "", fmt.Errorf("vaultops: generate-root update: %w", err)
		}
		if status.Complete {
			return status.EncodedToken, nil
		}
	}
	return "", errors.New("vaultops: the stored unseal keys did not reach the generate-root threshold")
}
