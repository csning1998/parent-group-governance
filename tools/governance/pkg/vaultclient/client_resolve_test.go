package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func kvAppConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/secret/data/app/config" {
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"data": map[string]interface{}{
				"api_key": "secret123",
			},
		},
	})
}

func TestReadKVv2Field(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(kvAppConfigHandler))
	t.Cleanup(server.Close)

	client, err := vaultclient.NewClient(vaultclient.Config{Address: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	val, ok := vaultclient.ReadKVv2Field(context.Background(), client, "secret", "app/config", "api_key")
	if !ok || val != "secret123" {
		t.Fatalf("expected ('secret123', true), got (%q, %v)", val, ok)
	}

	missingVal, missingOk := vaultclient.ReadKVv2Field(context.Background(), client, "secret", "app/config", "nonexistent")
	if missingOk || missingVal != "" {
		t.Fatalf("expected ('', false) for missing field, got (%q, %v)", missingVal, missingOk)
	}

	nilVal, nilOk := vaultclient.ReadKVv2Field(context.Background(), nil, "secret", "app/config", "api_key")
	if nilOk || nilVal != "" {
		t.Fatalf("ReadKVv2Field(nil client) = (%q, %v), want ('', false)", nilVal, nilOk)
	}

	missingPathVal, missingPathOk := vaultclient.ReadKVv2Field(context.Background(), client, "secret", "missing/path", "api_key")
	if missingPathOk || missingPathVal != "" {
		t.Fatalf("ReadKVv2Field missing path = (%q, %v), want ('', false)", missingPathVal, missingPathOk)
	}
}

func kvProdTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/secret/data/example-platform/credentials" {
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"data": map[string]interface{}{
				"prod_vault_root_token": "s.prod-root-token",
			},
		},
	})
}

func sampleProdConfig() vaultclient.Config {
	return vaultclient.Config{
		Address:    "https://prod.example:443",
		CACertPath: "/path/to/prod-ca.crt",
	}
}

func TestTokenAuth(t *testing.T) {
	auth := vaultclient.TokenAuth{Token: "s.valid-token"}
	tok, err := auth.Login(context.Background(), nil)
	if err != nil {
		t.Fatalf("TokenAuth.Login: %v", err)
	}
	if tok != "s.valid-token" {
		t.Errorf("tok = %q, want s.valid-token", tok)
	}

	emptyAuth := vaultclient.TokenAuth{}
	if _, err := emptyAuth.Login(context.Background(), nil); err == nil {
		t.Fatal("TokenAuth.Login(empty): want error, got nil")
	}
}

var sampleProdSecretRef = vaultclient.SecretRef{
	Mount: "secret",
	Path:  "example-platform/credentials",
	Field: "prod_vault_root_token",
}

func TestResolveTargetContext(t *testing.T) {
	bastionServer := httptest.NewServer(http.HandlerFunc(kvProdTokenHandler))
	t.Cleanup(bastionServer.Close)

	bastionCfg := vaultclient.Config{
		Address:    bastionServer.URL,
		CACertPath: "",
		Token:      "s.bastion-token",
	}
	prod := sampleProdConfig()

	addr, token, caCert, err := vaultclient.ResolveTargetContext(context.Background(), "dev", bastionCfg, prod, sampleProdSecretRef)
	if err != nil {
		t.Fatalf("ResolveTargetContext(dev): %v", err)
	}
	if addr != bastionCfg.Address || token != bastionCfg.Token || caCert != bastionCfg.CACertPath {
		t.Errorf("dev target resolved (%q, %q, %q), want (%q, %q, %q)",
			addr, token, caCert, bastionCfg.Address, bastionCfg.Token, bastionCfg.CACertPath)
	}

	addr, token, caCert, err = vaultclient.ResolveTargetContext(context.Background(), "prod", bastionCfg, prod, sampleProdSecretRef)
	if err != nil {
		t.Fatalf("ResolveTargetContext(prod): %v", err)
	}
	if addr != prod.Address || token != "s.prod-root-token" || caCert != prod.CACertPath {
		t.Errorf("prod target resolved (%q, %q, %q), want (%q, s.prod-root-token, %q)",
			addr, token, caCert, prod.Address, prod.CACertPath)
	}
}

func TestResolveTargetContextProdErrors(t *testing.T) {
	prod := sampleProdConfig()
	testCases := []struct {
		name       string
		bastionCfg vaultclient.Config
		wantErr    string
	}{
		{
			name:       "missing bastion token",
			bastionCfg: vaultclient.Config{},
			wantErr:    "token",
		},
		{
			name: "invalid bastion TLS CA path",
			bastionCfg: vaultclient.Config{
				Address:    "https://127.0.0.1:8200",
				CACertPath: "/nonexistent/path/ca.pem",
				Token:      "s.bastion-token",
			},
			wantErr: "TLS",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, token, caCert, err := vaultclient.ResolveTargetContext(context.Background(), "prod", tc.bastionCfg, prod, sampleProdSecretRef)
			if err == nil {
				t.Fatalf("ResolveTargetContext(prod) succeeded unexpectedly: addr=%q token=%q caCert=%q, want error containing %q",
					addr, token, caCert, tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
				t.Errorf("ResolveTargetContext(prod) error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
