package vault

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
	// ErrNoRootToken reports a token helper file without a live token of the root policy.
	ErrNoRootToken = errors.New("vault: the token helper file does not contain a live root token")
	// ErrSuccessorNotReady reports a successor operator identity without an active login with its policy.
	ErrSuccessorNotReady = errors.New("vault: the successor identity lacks a login with its policy")
	// ErrRootTokenPresent reports a token helper file with an existing token before generate-root runs.
	ErrRootTokenPresent = errors.New("vault: the token helper file already contains a token, revoke the token first")
	// ErrGenerateRootInProgress reports an unfinished generate-root attempt.
	ErrGenerateRootInProgress = errors.New("vault: a generate-root attempt is in progress, cancel it with vault operator generate-root -cancel")
)

// GenerateRoot creates a recovery root token from stored unseal keys and writes the token to ~/.vault-token.
func (op *Operator) GenerateRoot(ctx context.Context) error {
	if vaultclient.ReadTokenFile(op.paths.Home) != "" {
		return ErrRootTokenPresent
	}
	keysRaw, err := os.ReadFile(op.paths.UnsealKeyFile())
	if err != nil {
		return fmt.Errorf("vault: unseal keys not found at %s: %w", op.paths.UnsealKeyFile(), err)
	}

	status, err := op.client.Sys().GenerateRootStatusWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault: generate-root status: %w", err)
	}
	if status.Started {
		return ErrGenerateRootInProgress
	}
	attempt, err := op.client.Sys().GenerateRootInitWithContext(ctx, "", "")
	if err != nil {
		return fmt.Errorf("vault: generate-root init: %w", err)
	}

	encoded, err := op.submitGenerateRootKeys(ctx, attempt.Nonce, keysRaw)
	if err != nil {
		// Cancellation is best effort cleanup after key submission failure.
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
		return fmt.Errorf("vault: clone client: %w", err)
	}
	rootClient.SetToken(token)

	rootPolicies, err := lookupPolicies(ctx, rootClient)
	if err != nil {
		return fmt.Errorf("vault: lookup root token policies: %w", err)
	}
	if !slices.Contains(rootPolicies, "root") {
		return ErrNoRootToken
	}
	if err := rootClient.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
		return fmt.Errorf("vault: revoke the root token: %w", err)
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
			return "", fmt.Errorf("vault: generate-root update: %w", err)
		}
		if status.Complete {
			token := status.EncodedToken
			if token == "" {
				token = status.EncodedRootToken
			}
			return token, nil
		}
	}
	return "", errors.New("vault: the stored unseal keys did not reach the generate-root threshold")
}

// decodeRootToken unmasks the base64 payload by XORing the payload with the OTP per the Vault generate-root protocol.
func decodeRootToken(encoded, otp string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("vault: decode the encoded root token: %w", err)
	}
	if len(raw) != len(otp) {
		return "", fmt.Errorf("vault: the encoded root token has %d bytes, while the one-time password has %d", len(raw), len(otp))
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
		return fmt.Errorf("vault: read %s: %w", path, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("vault: parse %s: %w", path, err)
	}
	payload["root_token"] = ""
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("vault: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("vault: write %s: %w", path, err)
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
