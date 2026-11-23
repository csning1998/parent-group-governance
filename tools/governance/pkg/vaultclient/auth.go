package vaultclient

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// AuthMethod defines the interface for authenticating against Vault to obtain a client token.
type AuthMethod interface {
	Login(ctx context.Context, client *vaultapi.Client) (string, error)
}

// AppRoleAuth defines parameters for Vault AppRole authentication.
type AppRoleAuth struct {
	Mount    string // Auth method mount path (defaults to "approle" if empty)
	RoleID   string
	SecretID string
}

// Login authenticates against Vault using an AppRole role ID and secret ID.
func (a AppRoleAuth) Login(ctx context.Context, client *vaultapi.Client) (string, error) {
	if client == nil {
		return "", fmt.Errorf("vaultclient: nil client provided")
	}
	if a.RoleID == "" {
		return "", fmt.Errorf("vaultclient: empty role id provided")
	}
	if a.SecretID == "" {
		return "", fmt.Errorf("vaultclient: empty secret id provided")
	}

	mount := a.Mount
	if mount == "" {
		mount = "approle"
	}
	return submitLogin(ctx, client, "approle", mount, map[string]any{
		"role_id":   a.RoleID,
		"secret_id": a.SecretID,
	})
}

// JWTAuth defines parameters for Vault JWT/OIDC authentication methods.
type JWTAuth struct {
	Token string
	Role  string
	Mount string // Auth method mount path (defaults to "jwt" if empty)
}

// Login authenticates against Vault using JWT/OIDC credentials.
func (j JWTAuth) Login(ctx context.Context, client *vaultapi.Client) (string, error) {
	if client == nil {
		return "", fmt.Errorf("vaultclient: nil client provided")
	}
	if j.Token == "" {
		return "", fmt.Errorf("vaultclient: empty jwt token provided")
	}
	if j.Role == "" {
		return "", fmt.Errorf("vaultclient: empty role provided")
	}

	mount := j.Mount
	if mount == "" {
		mount = "jwt"
	}
	return submitLogin(ctx, client, "jwt", mount, map[string]any{
		"role": j.Role,
		"jwt":  j.Token,
	})
}

// TokenAuth implements direct token authentication.
type TokenAuth struct {
	Token string
}

// Login returns the configured direct Vault token.
func (a TokenAuth) Login(ctx context.Context, client *vaultapi.Client) (string, error) {
	if a.Token == "" {
		return "", fmt.Errorf("vaultclient: empty token provided")
	}
	return a.Token, nil
}

func submitLogin(ctx context.Context, client *vaultapi.Client, method, mount string, payload map[string]any) (string, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", payload)
	if err != nil {
		return "", fmt.Errorf("vaultclient: %s login: %w", method, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("vaultclient: empty client token in auth response")
	}
	return secret.Auth.ClientToken, nil
}
