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
	// ErrNoRootToken reports a token helper file that lacks a live token with the root policy.
	ErrNoRootToken = errors.New("vaultops: the token helper file does not hold a live root token")
	// ErrSuccessorNotReady reports a successor operator identity that lacks an active login with its policy.
	ErrSuccessorNotReady = errors.New("vaultops: the successor identity does not hold a login with its policy")
	// ErrRootTokenPresent reports a token helper file that already holds a token before generate-root runs.
	ErrRootTokenPresent = errors.New("vaultops: the token helper file already holds a token, revoke the token first")
	// ErrGenerateRootInProgress reports an unfinished generate-root attempt.
	ErrGenerateRootInProgress = errors.New("vaultops: a generate-root attempt is in progress, cancel it with vault operator generate-root -cancel")
)

// GenerateRoot generates a break-glass root token from stored unseal keys and writes the token to ~/.vault-token.
func (op *Operator) GenerateRoot(ctx context.Context) error {
	if vaultclient.ReadTokenFile(op.paths.Home) != "" {
		return ErrRootTokenPresent
	}
	keysRaw, err := os.ReadFile(op.paths.UnsealKeyFile())
	if err != nil {
		return fmt.Errorf("vaultops: unseal keys not found at %s: %w", op.paths.UnsealKeyFile(), err)
	}

	status, err := op.client.Sys().GenerateRootStatusWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vaultops: generate-root status: %w", err)
	}
	if status.Started {
		return ErrGenerateRootInProgress
	}
	attempt, err := op.client.Sys().GenerateRootInitWithContext(ctx, "", "")
	if err != nil {
		return fmt.Errorf("vaultops: generate-root init: %w", err)
	}

	encoded, err := op.submitGenerateRootKeys(ctx, attempt.Nonce, keysRaw)
	if err != nil {
		// Attempt cancellation is best-effort cleanup after key submission failure.
		_ = op.client.Sys().GenerateRootCancelWithContext(context.WithoutCancel(ctx))
		return err
	}
	token, err := decodeRootToken(encoded, attempt.OTP)
	if err != nil {
		return err
	}
	if err := vaultclient.PersistTokenFile(op.paths.Home, token); err != nil {
		return err
	}
	op.out.Print(ui.Warn, "Root token written to "+op.paths.RootTokenFile()+".")
	return nil
}

// RevokeRoot revokes the root token once the successor operator identity logs in with successorPolicy.
func (op *Operator) RevokeRoot(ctx context.Context, successor vaultclient.Config, successorPolicy string) error {
	token := vaultclient.ReadTokenFile(op.paths.Home)
	if token == "" {
		return ErrNoRootToken
	}

	successorClient, err := vaultclient.NewClient(successor)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSuccessorNotReady, err)
	}
	policies, err := lookupPolicies(ctx, successorClient)
	if err != nil || !slices.Contains(policies, successorPolicy) {
		return fmt.Errorf("%w: %s at %s", ErrSuccessorNotReady, successorPolicy, successor.Address)
	}

	rootClient, err := op.client.Clone()
	if err != nil {
		return fmt.Errorf("vaultops: clone client: %w", err)
	}
	rootClient.SetToken(token)

	rootPolicies, err := lookupPolicies(ctx, rootClient)
	if err != nil {
		return fmt.Errorf("vaultops: lookup root token policies: %w", err)
	}
	if !slices.Contains(rootPolicies, "root") {
		return ErrNoRootToken
	}
	if err := rootClient.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
		return fmt.Errorf("vaultops: revoke the root token: %w", err)
	}

	if err := vaultclient.RemoveTokenFile(op.paths.Home); err != nil {
		return err
	}
	if err := op.clearInitRootToken(); err != nil {
		return err
	}
	op.out.Print(ui.OK, "Root token revoked.")
	return nil
}

func (op *Operator) submitGenerateRootKeys(ctx context.Context, nonce string, keysRaw []byte) (string, error) {
	for _, key := range strings.Split(strings.TrimSpace(string(keysRaw)), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		status, err := op.client.Sys().GenerateRootUpdateWithContext(ctx, key, nonce)
		if err != nil {
			return "", fmt.Errorf("vaultops: generate-root update: %w", err)
		}
		if status.Complete {
			token := status.EncodedToken
			if token == "" {
				token = status.EncodedRootToken
			}
			return token, nil
		}
	}
	return "", errors.New("vaultops: the stored unseal keys did not reach the generate-root threshold")
}

// decodeRootToken MUST unmask the encoded payload with the one-time password per the Vault generate root protocol.
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

func (op *Operator) clearInitRootToken() error {
	path := op.paths.InitFile()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vaultops: read %s: %w", path, err)
	}
	var init map[string]any
	if err := json.Unmarshal(data, &init); err != nil {
		return fmt.Errorf("vaultops: parse %s: %w", path, err)
	}
	init["root_token"] = ""
	raw, err := json.Marshal(init)
	if err != nil {
		return fmt.Errorf("vaultops: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("vaultops: write %s: %w", path, err)
	}
	return nil
}

func lookupPolicies(ctx context.Context, client *vaultapi.Client) ([]string, error) {
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	raw, ok := secret.Data["policies"]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, nil
	}
	policies := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			policies = append(policies, s)
		}
	}
	return policies, nil
}
