// Package vaultclient provides a generic Vault API client, reachability inspection, session token synchronization, and secret helpers.
package vaultclient

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config encapsulates connection parameters and authentication credentials for constructing a Vault API client.
type Config struct {
	Address    string
	CACertPath string
	Token      string
	Auth       AuthMethod
}

// AuthMethod defines the interface for authenticating against Vault to obtain a client token.
type AuthMethod interface {
	Login(ctx context.Context, client *vaultapi.Client) (string, error)
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

// JWTAuth defines parameters for Vault JWT/OIDC authentication methods (e.g. SPIRE SVID or GitLab CI ID tokens).
// type JWTAuth struct {
// 	Token string // Raw JWT / SPIFFE SVID string
// 	Role  string // Vault JWT auth role name
// 	Mount string // Auth method mount path (defaults to "jwt" if empty)
// }
//
// func (j JWTAuth) Login(ctx context.Context, client *vaultapi.Client) (string, error) {
// 	mount := j.Mount
// 	if mount == "" {
// 		mount = "jwt"
// 	}
// 	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]interface{}{
// 		"role": j.Role,
// 		"jwt":  j.Token,
// 	})
// 	if err != nil {
// 		return "", fmt.Errorf("vaultclient: jwt login: %w", err)
// 	}
// 	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
// 		return "", fmt.Errorf("vaultclient: empty client token in auth response")
// 	}
// 	return secret.Auth.ClientToken, nil
// }

// SealStatus records reachability, initialization, and seal state for a target Vault instance.
type SealStatus struct {
	Reachable   bool
	Initialized bool
	Sealed      bool
}

// EnvSetter is a minimal interface for storing key-value pairs into an execution environment.
type EnvSetter interface {
	Set(key, value string)
}

// NewClient constructs a configured Vault API client according to cfg.
func NewClient(cfg Config) (*vaultapi.Client, error) {
	apiCfg := vaultapi.DefaultConfig()
	if cfg.Address != "" {
		apiCfg.Address = cfg.Address
	}
	if cfg.CACertPath != "" {
		if err := apiCfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: cfg.CACertPath}); err != nil {
			return nil, fmt.Errorf("vaultclient: configure TLS from %s: %w", cfg.CACertPath, err)
		}
	}
	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vaultclient: new client for %s: %w", cfg.Address, err)
	}
	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}
	return client, nil
}

// InspectStatus queries the Vault instance defined by cfg, reporting reachability, initialization, and seal status.
func InspectStatus(ctx context.Context, cfg Config) SealStatus {
	client, err := NewClient(cfg)
	if err != nil {
		return SealStatus{}
	}
	st, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return SealStatus{}
	}
	return SealStatus{
		Reachable:   true,
		Initialized: st.Initialized,
		Sealed:      st.Sealed,
	}
}

// ProbeState checks whether the target client can query seal status, reporting running and sealed flags.
func ProbeState(ctx context.Context, client *vaultapi.Client) (running, sealed bool, err error) {
	if client == nil {
		return false, false, fmt.Errorf("vaultclient: nil client provided")
	}
	st, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return false, false, nil
	}
	return true, st.Sealed, nil
}

// ReadKVv2Field reads mountPath/data/secretPath from a KV v2 engine and returns the specified field value.
func ReadKVv2Field(ctx context.Context, client *vaultapi.Client, mountPath, secretPath, field string) (value string, ok bool) {
	if client == nil {
		return "", false
	}
	secret, err := client.Logical().ReadWithContext(ctx, mountPath+"/data/"+secretPath)
	if err != nil || secret == nil {
		return "", false
	}
	data, _ := secret.Data["data"].(map[string]interface{})
	value, ok = data[field].(string)
	return value, ok
}

const tokenFileName = ".vault-token"

func resolveTokenFile(homeDir string) string {
	return filepath.Join(homeDir, tokenFileName)
}

// ReadTokenFile reads the Vault root token from ~/.vault-token beneath homeDir.
func ReadTokenFile(homeDir string) string {
	data, err := os.ReadFile(resolveTokenFile(homeDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SyncSessionToken reads the token from ~/.vault-token, sets VAULT_TOKEN in env, and ensures 0600 file permissions.
func SyncSessionToken(homeDir string, env EnvSetter) (string, error) {
	tokenFile := resolveTokenFile(homeDir)
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", nil
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("vaultclient: failed to extract a valid token")
	}

	if env != nil {
		env.Set("VAULT_TOKEN", token)
	}
	if err := writeTokenFile(tokenFile, token); err != nil {
		return "", err
	}
	return token, nil
}

// PersistTokenFile writes token to homeDir/.vault-token at 0600 through a unique temporary file.
func PersistTokenFile(homeDir, token string) error {
	return writeTokenFile(resolveTokenFile(homeDir), token)
}

func writeTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("vaultclient: create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	if err := finalizeTokenTemp(f, path, token); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func finalizeTokenTemp(f *os.File, path, token string) error {
	tmp := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("vaultclient: chmod %s: %w", tmp, err)
	}
	if _, err := f.Write([]byte(token)); err != nil {
		_ = f.Close()
		return fmt.Errorf("vaultclient: write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vaultclient: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("vaultclient: replace %s: %w", path, err)
	}
	return nil
}

// SecretRef encapsulates the mount path, secret path, and field key for a KV-v2 secret lookup.
type SecretRef struct {
	Mount string
	Path  string
	Field string
}

// ResolveTargetContext resolves Vault connection parameters across dev/bastion and prod targets.
func ResolveTargetContext(ctx context.Context, target string, bastionCfg, prodCfg Config, ref SecretRef) (addr, token, caCert string, err error) {
	if target != "prod" {
		return bastionCfg.Address, bastionCfg.Token, bastionCfg.CACertPath, nil
	}

	caCert = prodCfg.CACertPath
	if bastionCfg.Token == "" {
		return prodCfg.Address, "", caCert, fmt.Errorf("vaultclient: bastion token required to resolve prod context")
	}

	client, err := NewClient(bastionCfg)
	if err != nil {
		return prodCfg.Address, "", caCert, fmt.Errorf("vaultclient: connect to bastion: %w", err)
	}

	token, ok := ReadKVv2Field(ctx, client, ref.Mount, ref.Path, ref.Field)
	if !ok || token == "" {
		return prodCfg.Address, "", caCert, fmt.Errorf("vaultclient: failed to read %s from %s/%s", ref.Field, ref.Mount, ref.Path)
	}
	return prodCfg.Address, token, caCert, nil
}
