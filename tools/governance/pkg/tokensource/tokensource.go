package tokensource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrEmptyStatic is returned when a Static credential is empty.
var ErrEmptyStatic = errors.New("tokensource: static credential is empty")

// Provider yields the credential sent in the Authorization header of a provider request.
type Provider interface {
	Token(ctx context.Context) (string, error)
}

// Static contains a credential supplied verbatim by the environment.
type Static string

// Token returns the static credential.
func (s Static) Token(context.Context) (string, error) {
	if s == "" {
		return "", ErrEmptyStatic
	}
	return string(s), nil
}

// DefaultAuthMountPath specifies the default Vault JWT auth backend mount path.
// Refer to terraform/layers/foundation-vault-bastion/access-auth-mounts.tf.
const DefaultAuthMountPath = "gitlab-saas-ci-job-jwt-provider"

// VaultKVConfig specifies parameters for exchanging a JWT for a secret from Vault.
type VaultKVConfig struct {
	VaultAddr     string
	AuthMountPath string
	Role          string
	JWT           string
	MountPath     string
	SecretPath    string
	SecretField   string
	CACertPath    string
	HTTPClient    *http.Client
}

// VaultKV resolves credentials from a HashiCorp Vault KV v2 secret engine via JWT authentication.
type VaultKV struct {
	cfg        VaultKVConfig
	httpClient *http.Client
}

// NewVaultKV constructs a VaultKV token source.
func NewVaultKV(cfg VaultKVConfig) (*VaultKV, error) {
	if err := validateVaultKVConfig(cfg); err != nil {
		return nil, err
	}

	if cfg.AuthMountPath == "" {
		cfg.AuthMountPath = DefaultAuthMountPath
	}

	client, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	return &VaultKV{
		cfg:        cfg,
		httpClient: client,
	}, nil
}

// Token exchanges the configured JWT for a Vault client token and retrieves the secret field value.
func (v *VaultKV) Token(ctx context.Context) (string, error) {
	clientToken, err := v.login(ctx)
	if err != nil {
		return "", err
	}
	return v.readSecret(ctx, clientToken)
}

func (v *VaultKV) login(ctx context.Context) (string, error) {
	vaultAddr := strings.TrimRight(v.cfg.VaultAddr, "/")
	authMount := strings.Trim(v.cfg.AuthMountPath, "/")
	loginURL := fmt.Sprintf("%s/v1/auth/%s/login", vaultAddr, authMount)

	var loginResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	err := v.doJSON(ctx, vaultRequest{
		op:      "login",
		method:  http.MethodPost,
		url:     loginURL,
		payload: map[string]string{"role": v.cfg.Role, "jwt": v.cfg.JWT},
	}, &loginResp)
	if err != nil {
		return "", err
	}
	if loginResp.Auth.ClientToken == "" {
		return "", errors.New("tokensource: vault login response missing client_token")
	}

	return loginResp.Auth.ClientToken, nil
}

func (v *VaultKV) readSecret(ctx context.Context, clientToken string) (string, error) {
	vaultAddr := strings.TrimRight(v.cfg.VaultAddr, "/")
	mountPath := strings.Trim(v.cfg.MountPath, "/")
	secretPath := strings.Trim(v.cfg.SecretPath, "/")
	secretURL := fmt.Sprintf("%s/v1/%s/data/%s", vaultAddr, mountPath, secretPath)

	var kvResp struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	err := v.doJSON(ctx, vaultRequest{
		op:     "secret read",
		method: http.MethodGet,
		url:    secretURL,
		token:  clientToken,
	}, &kvResp)
	if err != nil {
		return "", err
	}

	if kvResp.Data.Data == nil {
		return "", errors.New("tokensource: vault secret payload contains no data")
	}

	val, ok := kvResp.Data.Data[v.cfg.SecretField]
	if !ok {
		return "", fmt.Errorf("tokensource: field %q not found in vault secret data", v.cfg.SecretField)
	}

	strVal, ok := val.(string)
	if !ok || strVal == "" {
		return "", fmt.Errorf("tokensource: field %q in vault secret data is not a non-empty string", v.cfg.SecretField)
	}

	return strVal, nil
}

type vaultRequest struct {
	op      string
	method  string
	url     string
	token   string
	payload any
}

func (v *VaultKV) doJSON(ctx context.Context, r vaultRequest, out any) error {
	var bodyReader io.Reader
	if r.payload != nil {
		raw, err := json.Marshal(r.payload)
		if err != nil {
			return fmt.Errorf("tokensource: marshal %s payload: %w", r.op, err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, r.method, r.url, bodyReader)
	if err != nil {
		return fmt.Errorf("tokensource: create %s request: %w", r.op, err)
	}
	if r.payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.token != "" {
		req.Header.Set("X-Vault-Token", r.token)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("tokensource: vault %s request failed: %w", r.op, err)
	}
	// Close failure is secondary after reading the response.
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("tokensource: read %s response body: %w", r.op, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tokensource: vault %s failed with status %d: %s", r.op, resp.StatusCode, sanitizeVaultError(resp.StatusCode, body))
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("tokensource: unmarshal %s response: %w", r.op, err)
	}
	return nil
}

func sanitizeVaultError(statusCode int, body []byte) string {
	var errResp struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && len(errResp.Errors) > 0 {
		return strings.Join(errResp.Errors, ", ")
	}
	return http.StatusText(statusCode)
}

func validateVaultKVConfig(cfg VaultKVConfig) error {
	if cfg.VaultAddr == "" {
		return errors.New("tokensource: vault address is required")
	}
	if cfg.Role == "" {
		return errors.New("tokensource: vault role is required")
	}
	if cfg.JWT == "" {
		return errors.New("tokensource: jwt token is required")
	}
	if cfg.MountPath == "" {
		return errors.New("tokensource: vault mount path is required")
	}
	if cfg.SecretPath == "" {
		return errors.New("tokensource: vault secret path is required")
	}
	if cfg.SecretField == "" {
		return errors.New("tokensource: vault secret field is required")
	}
	return nil
}

func buildHTTPClient(cfg VaultKVConfig) (*http.Client, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	if cfg.CACertPath == "" {
		return client, nil
	}

	caPool, err := loadCACertPool(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	transport := cloneTransportWithCA(client.Transport, caPool)
	if transport == nil {
		return client, nil
	}

	return &http.Client{
		Transport:     transport,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}, nil
}

func loadCACertPool(path string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tokensource: read ca cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("tokensource: failed to append ca cert to pool")
	}
	return caPool, nil
}

func cloneTransportWithCA(rt http.RoundTripper, caPool *x509.CertPool) *http.Transport {
	var transport *http.Transport
	switch t := rt.(type) {
	case *http.Transport:
		if t != nil {
			transport = t.Clone()
		}
	case nil:
		if defT, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = defT.Clone()
		}
	}

	if transport == nil {
		return nil
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.RootCAs = caPool
	return transport
}
