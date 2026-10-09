// Package vaultclient provides a generic Vault API client, reachability inspection, session token synchronization, and secret helpers.
package vaultclient

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// probeTimeout bounds a status probe, since the Vault API defaults of 60 seconds and two retries
// stall the interactive banner for minutes against an unreachable address.
const probeTimeout = 3 * time.Second

const tokenFileName = ".vault-token"

// AppRoleAuth defines parameters for Vault AppRole authentication.
type AppRoleAuth struct {
	Mount    string // Auth method mount path (defaults to "approle" if empty)
	RoleID   string
	SecretID string
}

// AuthMethod defines the interface for authenticating against Vault to obtain a client token.
type AuthMethod interface {
	Login(ctx context.Context, client *vaultapi.Client) (string, error)
}

// Config encapsulates connection parameters and authentication credentials for constructing a Vault API client.
type Config struct {
	Address    string
	CACertPath string
	// ClientCert and ClientKey name the client certificate which an mTLS listener, such as a Vault Proxy, requires.
	ClientCert string
	ClientKey  string
	Token      string
	Auth       AuthMethod
}

// JWTAuth defines parameters for Vault JWT/OIDC authentication methods.
type JWTAuth struct {
	Token string // Raw JWT / SPIFFE SVID string
	Role  string // Vault JWT auth role name
	Mount string // Auth method mount path (defaults to "jwt" if empty)
}

// SealStatus records reachability, initialization, and seal state for a target Vault instance.
type SealStatus struct {
	Reachable   bool
	Initialized bool
	Sealed      bool
}

// SecretRef encapsulates the mount path, secret path, and field key for a KV-v2 secret lookup.
type SecretRef struct {
	Mount string
	Path  string
	Field string
}

// TokenAuth implements direct token authentication.
type TokenAuth struct {
	Token string
}

// InspectStatus queries the Vault instance defined by cfg, reporting reachability, initialization, and seal status.
func InspectStatus(ctx context.Context, cfg Config) SealStatus {
	client, err := NewClient(cfg)
	if err != nil {
		return SealStatus{}
	}
	st, err := probeSealStatus(ctx, client)
	if err != nil {
		return SealStatus{}
	}
	return SealStatus{
		Reachable:   true,
		Initialized: st.Initialized,
		Sealed:      st.Sealed,
	}
}

// NewClient constructs a configured Vault API client according to cfg.
func NewClient(cfg Config) (*vaultapi.Client, error) {
	apiCfg := vaultapi.DefaultConfig()
	if cfg.Address != "" {
		apiCfg.Address = cfg.Address
	}
	if cfg.CACertPath != "" || cfg.ClientCert != "" || cfg.ClientKey != "" {
		tlsCfg := &vaultapi.TLSConfig{CACert: cfg.CACertPath, ClientCert: cfg.ClientCert, ClientKey: cfg.ClientKey}
		if err := apiCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("vaultclient: configure TLS for %s: %w", cfg.Address, err)
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

// PersistTokenFile writes token to homeDir/.vault-token at 0600 through a unique temporary file.
func PersistTokenFile(homeDir, token string) error {
	return writeTokenFile(resolveTokenFile(homeDir), token)
}

// ProbeState checks whether the target client can query seal status, reporting running and sealed flags.
func ProbeState(ctx context.Context, client *vaultapi.Client) (running, sealed bool, err error) {
	if client == nil {
		return false, false, fmt.Errorf("vaultclient: nil client provided")
	}
	st, err := probeSealStatus(ctx, client)
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

// ReadTokenFile reads the Vault root token from ~/.vault-token beneath homeDir.
func ReadTokenFile(homeDir string) string {
	data, err := os.ReadFile(resolveTokenFile(homeDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// RemoveTokenFile deletes homeDir/.vault-token, and an absent file counts as removed.
func RemoveTokenFile(homeDir string) error {
	err := os.Remove(resolveTokenFile(homeDir))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("vaultclient: remove %s: %w", resolveTokenFile(homeDir), err)
	}
	return nil
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
	return submitLogin(ctx, client, "approle", mount, map[string]interface{}{
		"role_id":   a.RoleID,
		"secret_id": a.SecretID,
	})
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
	return submitLogin(ctx, client, "jwt", mount, map[string]interface{}{
		"role": j.Role,
		"jwt":  j.Token,
	})
}

// Login returns the configured direct Vault token.
func (a TokenAuth) Login(ctx context.Context, client *vaultapi.Client) (string, error) {
	if a.Token == "" {
		return "", fmt.Errorf("vaultclient: empty token provided")
	}
	return a.Token, nil
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

// probeSealStatus clones the target client, disables retries, applies probeTimeout,
// and queries the Vault seal status endpoint defensively.
func probeSealStatus(ctx context.Context, client *vaultapi.Client) (*vaultapi.SealStatusResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("vaultclient: nil client provided")
	}
	probe, err := client.Clone()
	if err != nil {
		return nil, fmt.Errorf("vaultclient: clone client for probe: %w", err)
	}
	probe.SetMaxRetries(0)
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return probe.Sys().SealStatusWithContext(ctx)
}

func resolveTokenFile(homeDir string) string {
	return filepath.Join(homeDir, tokenFileName)
}

func submitLogin(ctx context.Context, client *vaultapi.Client, method, mount string, payload map[string]interface{}) (string, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", payload)
	if err != nil {
		return "", fmt.Errorf("vaultclient: %s login: %w", method, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("vaultclient: empty client token in auth response")
	}
	return secret.Auth.ClientToken, nil
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
