// Package vaultclient provides a generic Vault API client, reachability inspection, session token synchronization, and secret helpers.
package vaultclient

import (
	"context"
	"errors"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config encapsulates connection parameters and authentication credentials for constructing a Vault API client.
type Config struct {
	Address    string
	CACertPath string
	// ClientCert and ClientKey supply the client certificate required by mTLS listeners such as Vault Proxy.
	ClientCert string
	ClientKey  string
	Token      string
	Auth       AuthMethod
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

// SecretRef locates a single field in a Vault KV v2 secret.
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
		return prodCfg.Address, "", caCert, errors.New("vaultclient: bastion token required to resolve prod context")
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

// ReadKVv2Field reads mountPath/data/secretPath from a KV v2 engine and returns the specified field value.
func ReadKVv2Field(ctx context.Context, client *vaultapi.Client, mountPath, secretPath, field string) (value string, ok bool) {
	if client == nil {
		return "", false
	}
	secret, err := client.Logical().ReadWithContext(ctx, mountPath+"/data/"+secretPath)
	if err != nil || secret == nil {
		return "", false
	}
	data, _ := secret.Data["data"].(map[string]any)
	value, ok = data[field].(string)
	return value, ok
}
