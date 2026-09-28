package tokensource_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/tokensource"
)

// Mock Server & Test Helpers

type mockServerParams struct {
	authMountPath string
	loginToken    string
	loginStatus   int
	loginErrors   []string
	secretPath    string
	secretStatus  int
	secretData    map[string]any
	secretErrors  []string
	delay         time.Duration
	onRequest     func(r *http.Request)
}

type customRoundTripper struct {
	base http.RoundTripper
}

func (c *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-Custom-Test-Header", "true")
	return c.base.RoundTrip(req)
}

func newMockVaultHandler(p mockServerParams) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.delay > 0 {
			time.Sleep(p.delay)
		}
		if p.onRequest != nil {
			p.onRequest(r)
		}
		if handleMockLogin(w, r, p) {
			return
		}
		if handleMockSecret(w, r, p) {
			return
		}
		http.NotFound(w, r)
	})
}

func handleMockLogin(w http.ResponseWriter, r *http.Request, p mockServerParams) bool {
	authMount := p.authMountPath
	if authMount == "" {
		authMount = tokensource.DefaultAuthMountPath
	}
	if r.URL.Path != fmt.Sprintf("/v1/auth/%s/login", authMount) {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	if p.loginStatus != 0 {
		w.WriteHeader(p.loginStatus)
	}
	if len(p.loginErrors) > 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": p.loginErrors})
		return true
	}
	if p.loginToken != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": p.loginToken},
		})
		return true
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{}})
	return true
}

func handleMockSecret(w http.ResponseWriter, r *http.Request, p mockServerParams) bool {
	expectedPath := p.secretPath
	if expectedPath == "" {
		expectedPath = "/v1/secret/data/ci/credentials"
	}
	if r.URL.Path != expectedPath {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	if p.secretStatus != 0 {
		w.WriteHeader(p.secretStatus)
	}
	if len(p.secretErrors) > 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": p.secretErrors})
		return true
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{"data": p.secretData},
	})
	return true
}

func newMockVaultKVServer(t *testing.T, p mockServerParams) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(newMockVaultHandler(p))
	t.Cleanup(server.Close)
	return server
}

func newMockVaultKVTLSServer(t *testing.T, p mockServerParams) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(newMockVaultHandler(p))
	t.Cleanup(server.Close)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(ca.pem) error = %v", err)
	}
	return server, certFile
}

func newDefaultVaultKVConfig(vaultAddr string) tokensource.VaultKVConfig {
	return tokensource.VaultKVConfig{
		VaultAddr:   vaultAddr,
		Role:        "ci-reviewer",
		JWT:         "valid-jwt",
		MountPath:   "secret",
		SecretPath:  "ci/credentials",
		SecretField: "api_key",
	}
}

func startMockServer(t *testing.T, useTLS bool, p mockServerParams) (serverURL, caCertFile string, baseTransport http.RoundTripper) {
	t.Helper()
	if useTLS {
		server, certPath := newMockVaultKVTLSServer(t, p)
		return server.URL, certPath, server.Client().Transport
	}
	server := newMockVaultKVServer(t, p)
	return server.URL, "", server.Client().Transport
}

func runVaultKVSuccessCase(t *testing.T, useTLS bool, p mockServerParams, setup func(*tokensource.VaultKVConfig, string, http.RoundTripper), wantToken string, expectHeader bool) {
	t.Helper()
	var headerReceived bool
	p.onRequest = func(r *http.Request) {
		if r.Header.Get("X-Custom-Test-Header") == "true" {
			headerReceived = true
		}
	}

	serverURL, caCertFile, baseTransport := startMockServer(t, useTLS, p)
	cfg := newDefaultVaultKVConfig(serverURL)
	if setup != nil {
		setup(&cfg, caCertFile, baseTransport)
	}

	vk, err := tokensource.NewVaultKV(cfg)
	if err != nil {
		t.Fatalf("NewVaultKV() error = %v", err)
	}

	token, err := vk.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if token != wantToken {
		t.Errorf("Token() = %q, want %q", token, wantToken)
	}
	if expectHeader && !headerReceived {
		t.Errorf("custom RoundTripper was discarded when CACertPath was specified")
	}
}

// Static Token Provider Tests

// TestStatic_TokenBehavior covers Static token provider behaviors for valid and empty values.
func TestStatic_TokenBehavior(t *testing.T) {
	tests := []struct {
		name      string
		staticVal tokensource.Static
		wantToken string
		wantErr   error
	}{
		{
			name:      "configured static credential",
			staticVal: "mock-static-token",
			wantToken: "mock-static-token",
			wantErr:   nil,
		},
		{
			name:      "empty static credential",
			staticVal: "",
			wantToken: "",
			wantErr:   tokensource.ErrEmptyStatic,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.staticVal.Token(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Token() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.wantToken {
				t.Errorf("Token() = %q, want %q", got, tc.wantToken)
			}
		})
	}
}

// VaultKV Configuration Tests

// TestVaultKV_ConfigValidationBehavior covers parameter validation behaviors upon NewVaultKV construction.
func TestVaultKV_ConfigValidationBehavior(t *testing.T) {
	valid := newDefaultVaultKVConfig("https://vault.example.com")

	tests := []struct {
		name      string
		mutate    func(*tokensource.VaultKVConfig)
		wantError bool
	}{
		{
			name:      "valid configuration",
			mutate:    func(c *tokensource.VaultKVConfig) {},
			wantError: false,
		},
		{
			name: "empty VaultAddr",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.VaultAddr = ""
			},
			wantError: true,
		},
		{
			name: "empty Role",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.Role = ""
			},
			wantError: true,
		},
		{
			name: "empty JWT",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.JWT = ""
			},
			wantError: true,
		},
		{
			name: "empty MountPath",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.MountPath = ""
			},
			wantError: true,
		},
		{
			name: "empty SecretPath",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.SecretPath = ""
			},
			wantError: true,
		},
		{
			name: "empty SecretField",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.SecretField = ""
			},
			wantError: true,
		},
		{
			name: "nonexistent CACertPath",
			mutate: func(c *tokensource.VaultKVConfig) {
				c.CACertPath = "/nonexistent/ca.pem"
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			_, err := tokensource.NewVaultKV(cfg)
			if (err != nil) != tc.wantError {
				t.Errorf("NewVaultKV() error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}

// VaultKV Retrieval Tests

// TestVaultKV_RetrievalSuccessScenarios covers standard, custom CA TLS, custom auth mount, and custom transport preservation scenarios in a matrix.
func TestVaultKV_RetrievalSuccessScenarios(t *testing.T) {
	tests := []struct {
		name         string
		useTLS       bool
		serverParams mockServerParams
		setupConfig  func(cfg *tokensource.VaultKVConfig, caCertFile string, baseTransport http.RoundTripper)
		wantToken    string
		expectHeader bool
	}{
		{
			name: "standard retrieval with default auth mount",
			serverParams: mockServerParams{
				loginToken: "vault-client-token-abc",
				secretData: map[string]any{"api_key": "mock-secret-payload-value"},
			},
			setupConfig: func(cfg *tokensource.VaultKVConfig, _ string, _ http.RoundTripper) {
				cfg.JWT = "mock-gitlab-jwt"
			},
			wantToken: "mock-secret-payload-value",
		},
		{
			name:   "TLS retrieval with custom CA cert",
			useTLS: true,
			serverParams: mockServerParams{
				loginToken: "tls-token",
				secretPath: "/v1/secret/data/ci/tls-secret",
				secretData: map[string]any{"api_key": "secret-tls-val"},
			},
			setupConfig: func(cfg *tokensource.VaultKVConfig, caCertFile string, _ http.RoundTripper) {
				cfg.SecretPath = "ci/tls-secret"
				cfg.CACertPath = caCertFile
			},
			wantToken: "secret-tls-val",
		},
		{
			name: "custom auth mount path",
			serverParams: mockServerParams{
				authMountPath: "custom-spire-jwt",
				loginToken:    "spire-token",
				secretData:    map[string]any{"api_key": "custom-mount-secret"},
			},
			setupConfig: func(cfg *tokensource.VaultKVConfig, _ string, _ http.RoundTripper) {
				cfg.AuthMountPath = "custom-spire-jwt"
			},
			wantToken: "custom-mount-secret",
		},
		{
			name:         "custom HTTP transport preserved when CACertPath configured",
			useTLS:       true,
			expectHeader: true,
			serverParams: mockServerParams{
				loginToken: "tls-token",
				secretPath: "/v1/secret/data/ci/tls-secret",
				secretData: map[string]any{"api_key": "custom-transport-secret"},
			},
			setupConfig: func(cfg *tokensource.VaultKVConfig, caCertFile string, baseTransport http.RoundTripper) {
				cfg.SecretPath = "ci/tls-secret"
				cfg.CACertPath = caCertFile
				cfg.HTTPClient = &http.Client{
					Transport: &customRoundTripper{base: baseTransport},
					Timeout:   15 * time.Second,
				}
			},
			wantToken: "custom-transport-secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runVaultKVSuccessCase(t, tc.useTLS, tc.serverParams, tc.setupConfig, tc.wantToken, tc.expectHeader)
		})
	}
}

// TestVaultKV_ConcurrentAccess covers parallel token retrieval across multiple workers.
func TestVaultKV_ConcurrentAccess(t *testing.T) {
	server := newMockVaultKVServer(t, mockServerParams{
		loginToken: "concurrent-token",
		secretData: map[string]any{"api_key": "concurrent-val"},
	})

	cfg := newDefaultVaultKVConfig(server.URL)
	cfg.JWT = "jwt-val"
	vk, err := tokensource.NewVaultKV(cfg)
	if err != nil {
		t.Fatalf("NewVaultKV() error = %v", err)
	}

	const workers = 10
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			token, err := vk.Token(context.Background())
			if err != nil {
				errCh <- err
				return
			}
			if token != "concurrent-val" {
				errCh <- fmt.Errorf("unexpected token %q", token)
				return
			}
			errCh <- nil
		}()
	}

	for i := 0; i < workers; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent Token() failed: %v", err)
		}
	}
}

// TestVaultKV_ServerErrorScenarios covers failure behaviors when Vault server returns non-200 or invalid payloads.
func TestVaultKV_ServerErrorScenarios(t *testing.T) {
	tests := []struct {
		name          string
		serverParams  mockServerParams
		cfgMutate     func(*tokensource.VaultKVConfig)
		wantErrSubstr string
	}{
		{
			name: "login failure 403",
			serverParams: mockServerParams{
				loginStatus: http.StatusForbidden,
				loginErrors: []string{"permission denied for role"},
			},
			wantErrSubstr: "permission denied for role",
		},
		{
			name: "login response missing client_token",
			serverParams: mockServerParams{
				loginToken: "",
			},
			wantErrSubstr: "missing client_token",
		},
		{
			name: "secret path 404 not found",
			serverParams: mockServerParams{
				loginToken:   "valid-token",
				secretStatus: http.StatusNotFound,
				secretErrors: []string{"path not found"},
			},
			wantErrSubstr: "path not found",
		},
		{
			name: "secret payload data is nil",
			serverParams: mockServerParams{
				loginToken: "valid-token",
				secretData: nil,
			},
			wantErrSubstr: "vault secret payload contains no data",
		},
		{
			name: "secret payload missing requested field",
			serverParams: mockServerParams{
				loginToken: "valid-token",
				secretData: map[string]any{"other_field": "some-value"},
			},
			wantErrSubstr: "not found in vault secret data",
		},
		{
			name: "secret field value is not a string",
			serverParams: mockServerParams{
				loginToken: "valid-token",
				secretData: map[string]any{"api_key": 12345},
			},
			wantErrSubstr: "is not a non-empty string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newMockVaultKVServer(t, tc.serverParams)
			cfg := newDefaultVaultKVConfig(server.URL)
			if tc.cfgMutate != nil {
				tc.cfgMutate(&cfg)
			}

			vk, err := tokensource.NewVaultKV(cfg)
			if err != nil {
				t.Fatalf("NewVaultKV() error = %v", err)
			}

			_, err = vk.Token(context.Background())
			if err == nil {
				t.Fatalf("Token() expected error for %s, got nil", tc.name)
			}
			if tc.wantErrSubstr != "" && !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("Token() error = %q, want substring %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

// TestVaultKV_ContextCancellation covers handling when caller cancels context during retrieval.
func TestVaultKV_ContextCancellation(t *testing.T) {
	server := newMockVaultKVServer(t, mockServerParams{
		delay:      100 * time.Millisecond,
		loginToken: "delayed-token",
	})

	cfg := newDefaultVaultKVConfig(server.URL)
	vk, err := tokensource.NewVaultKV(cfg)
	if err != nil {
		t.Fatalf("NewVaultKV() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = vk.Token(ctx)
	if err == nil {
		t.Fatalf("Token() expected error with cancelled context, got nil")
	}
}

// Suppress unused imports for tls and x509 in root scope.
var (
	_ = tls.VersionTLS12
	_ = x509.NewCertPool
)
