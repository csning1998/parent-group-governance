package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

const (
	issuedProxyDir      = ".config/vault-proxy"
	issuedAdminIdentity = "administrator"
)

// issuedVault serves the KV v2 read and write endpoints of the administrator Vault Proxy.
type issuedVault struct {
	mu      sync.Mutex
	secrets map[string]map[string]any
	writes  []string
}

func (v *issuedVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	mount, path, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), "/data/")
	key := mount + "/" + path
	if r.Method == http.MethodGet {
		data, found := v.secrets[key]
		if !found {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}})
		return
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v.secrets[key] = body.Data
	v.writes = append(v.writes, key)
	writeJSON(w, map[string]any{"data": map[string]any{"version": 2}})
}

// writeJSON answers with value. An encoding failure reaches the client under test as a malformed response body,
// which the test then reports.
func writeJSON(w http.ResponseWriter, value any) {
	_ = json.NewEncoder(w).Encode(value)
}

// issuedServices records the GitLab and SonarQube requests of one test and answers each with a fixed success.
type issuedServices struct {
	mu       sync.Mutex
	requests []string
	tokens   []string
}

func (s *issuedServices) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.requests = append(s.requests, r.Method+" "+r.URL.EscapedPath())
	switch r.URL.Path {
	case "/api/user_tokens/generate":
		writeJSON(w, map[string]string{"token": "squ_issued"})
	case "/api/user_tokens/search":
		entries := make([]map[string]string, 0, len(s.tokens))
		for _, name := range s.tokens {
			entries = append(entries, map[string]string{"name": name, "type": "GLOBAL_ANALYSIS_TOKEN"})
		}
		writeJSON(w, map[string]any{"userTokens": entries})
	case "/user/runners":
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"id": 9171, "token": "glrt-issued"})
	default:
		writeJSON(w, map[string]any{})
	}
}

func (s *issuedServices) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// newIssuedTokensApp wires an app to a TLS Vault Proxy fake and a plain GitLab and SonarQube fake.
func newIssuedTokensApp(t *testing.T, projects []string) (*app, *issuedVault, *issuedServices) {
	t.Helper()
	vault := &issuedVault{secrets: map[string]map[string]any{
		"secret/parent-group-governance/sonarqube/admin-account":               {"sonarqube_admin_password": "admin-password"},
		"secret/parent-group-governance/terraform/state-backend":               {"token": "pat"},
		"registry/platform/gitlab-group/top-level":                             {"group_id": "42"},
		"secret/gitlab-ci-with-code-reviewer/integration/code-reviewer-bot":    {"token": "reviewer-token"},
		"secret/gitlab-ci-with-code-reviewer/integration/auto-version-tag-bot": {"token": "tag-token"},
	}}
	vaultSrv := httptest.NewTLSServer(vault)
	t.Cleanup(vaultSrv.Close)
	services := &issuedServices{tokens: []string{"gitlab-ci-analysis"}}
	servicesSrv := httptest.NewServer(services)
	t.Cleanup(servicesSrv.Close)

	home := t.TempDir()
	writeProxyCertificates(t, home, vaultSrv)
	a := &app{
		root:         t.TempDir(),
		home:         home,
		out:          ui.New(io.Discard, io.Discard),
		topology:     issuedTopology(t, vaultSrv.URL, projects),
		credentials:  []credentials.Credential{{Key: "sonarqube-admin-password", AdminUsername: "admin", Spec: secretrotate.Spec{Mount: "secret", Path: "parent-group-governance/sonarqube/admin-account", Field: "sonarqube_admin_password"}}},
		issuedTokens: issuedConfig(servicesSrv.URL),
		resolveOrigin: func(context.Context) (gitlabOrigin, error) {
			return gitlabOrigin{WebURL: "https://gitlab.example.com", APIURL: servicesSrv.URL, TopLevelGroup: "example-group"}, nil
		},
	}
	return a, vault, services
}

func issuedTopology(t *testing.T, vaultURL string, projects []string) topology.VaultTopology {
	t.Helper()
	parsed, err := url.Parse(vaultURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	return topology.VaultTopology{
		BastionVault: topology.BastionVault{LoopbackAddress: "127.0.0.1", PublishAddress: "192.0.2.10", APIPort: 8200},
		OperatorVaultProxy: topology.OperatorVaultProxy{
			GovernanceOwnerCode: "parent-group-governance",
			UserConfigDir:       issuedProxyDir,
			PlaceholderToken:    "proxy-supplied",
			StateBackend:        topology.StateBackend{VaultKVMount: "secret", VaultKVField: "token"},
			Identities: map[string]topology.ProxyIdentity{
				issuedAdminIdentity: {ListenPort: port},
				"credential-distributor-parent-group-governance": {CodeReviewerVariableProjects: projects},
			},
		},
	}
}

func issuedConfig(servicesURL string) issuedtokens.Config {
	return issuedtokens.Config{
		GitLabGroupRegistry: issuedtokens.VaultField{Mount: "registry", Path: "platform/gitlab-group/top-level", Field: "group_id"},
		SonarQubeAnalysisToken: issuedtokens.SonarQubeAnalysisTokenConfig{
			UserTokensEndpoint:     servicesURL + "/api/user_tokens",
			AdminPasswordKey:       "sonarqube-admin-password",
			TokenNamePrefix:        "gitlab-ci-analysis",
			Vault:                  issuedtokens.VaultField{Mount: "secret", Path: "parent-group-governance/sonarqube/ci-analysis-bot", Field: "sonarqube_ci_token"},
			GitLabGroupVariableKey: "SONAR_TOKEN",
		},
		GitLabGroupRunner: issuedtokens.GitLabGroupRunnerConfig{
			Description: "shared-runner",
			TagList:     []string{"podman"},
			ConfigPath:  "gitlab-runner-configs/config.toml",
		},
		CodeReviewerVariables: issuedtokens.CodeReviewerVariablesConfig{BotTokens: []issuedtokens.ReviewerBotToken{
			{Vault: issuedtokens.VaultField{Mount: "secret", Path: "gitlab-ci-with-code-reviewer/integration/code-reviewer-bot", Field: "token"}, VariableKeys: []string{"REVIEW_MR_REVIEWER"}},
			{Vault: issuedtokens.VaultField{Mount: "secret", Path: "gitlab-ci-with-code-reviewer/integration/auto-version-tag-bot", Field: "token"}, VariableKeys: []string{"TAG_PUSH_TOKEN"}},
		}},
	}
}

// writeProxyCertificates writes the certificate of the TLS server into ca.pem.
// The function writes a self-signed client certificate into client.pem and client-key.pem below the directory of the administrator identity.
func writeProxyCertificates(t *testing.T, home string, srv *httptest.Server) {
	t.Helper()
	base := filepath.Join(home, issuedProxyDir)
	identityDir := filepath.Join(base, issuedAdminIdentity)
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(base, "ca.pem"), "CERTIFICATE", srv.Certificate().Raw)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "operator-" + issuedAdminIdentity},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(identityDir, "client.pem"), "CERTIFICATE", der)
	writePEM(t, filepath.Join(identityDir, "client-key.pem"), "EC PRIVATE KEY", keyDER)
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestIssueSonarQubeAnalysisToken asserts the Vault write, the group variable update, and the revocation, and the refusal of an unknown admin key.
func TestIssueSonarQubeAnalysisToken(t *testing.T) {
	t.Run("rotates the token through the Vault Proxy and GitLab", func(t *testing.T) {
		a, vault, services := newIssuedTokensApp(t, nil)
		if err := a.issueSonarQubeAnalysisToken(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := vault.secrets["secret/parent-group-governance/sonarqube/ci-analysis-bot"]["sonarqube_ci_token"]; got != "squ_issued" {
			t.Fatalf("the Bastion Vault holds %v, want squ_issued", got)
		}
		assertRequestsInclude(t, services.recorded(), "PUT /groups/42/variables/SONAR_TOKEN", "POST /api/user_tokens/revoke")
	})
	t.Run("refuses an unknown admin password key", func(t *testing.T) {
		a, _, _ := newIssuedTokensApp(t, nil)
		a.issuedTokens.SonarQubeAnalysisToken.AdminPasswordKey = "absent-password"
		assertOperationError(t, a.issueSonarQubeAnalysisToken(context.Background()), "names no service_admin_passwords key")
	})
}

// TestRegisterGitLabGroupRunner asserts the written config.toml and the refusal of an existing config.toml.
func TestRegisterGitLabGroupRunner(t *testing.T) {
	t.Run("writes the runner token into config.toml", func(t *testing.T) {
		a, _, services := newIssuedTokensApp(t, nil)
		if err := a.registerGitLabGroupRunner(context.Background()); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(filepath.Join(a.root, "gitlab-runner-configs/config.toml"))
		if err != nil || !strings.Contains(string(content), `token        = "glrt-issued"`) || !strings.Contains(string(content), `url          = "https://gitlab.example.com"`) {
			t.Fatalf("config.toml = %q, %v", content, err)
		}
		assertRequestsInclude(t, services.recorded(), "POST /user/runners")
	})
	t.Run("reports a missing administrator identity", func(t *testing.T) {
		a, _, _ := newIssuedTokensApp(t, nil)
		delete(a.topology.OperatorVaultProxy.Identities, issuedAdminIdentity)
		assertOperationError(t, a.registerGitLabGroupRunner(context.Background()), "access_tier administrator")
	})
}

// TestPublishCodeReviewerVariables asserts the variable writes, the refusal without a listed project, and a missing Vault field.
func TestPublishCodeReviewerVariables(t *testing.T) {
	cases := map[string]struct {
		projects      []string
		dropSecret    string
		emptyBotToken bool
		wantErr       string
		wantRequests  []string
	}{
		"writes both variables into the listed project below the top-level group": {
			projects:     []string{"example-subgroup/example-project"},
			wantRequests: []string{"PUT /projects/example-group%2Fexample-subgroup%2Fexample-project/variables/REVIEW_MR_REVIEWER", "PUT /projects/example-group%2Fexample-subgroup%2Fexample-project/variables/TAG_PUSH_TOKEN"},
		},
		"refuses an empty project list": {
			wantErr: "lists code_reviewer_variable_projects",
		},
		"reports a missing GitLab token": {
			projects:   []string{"example-subgroup/example-project"},
			dropSecret: "secret/parent-group-governance/terraform/state-backend",
			wantErr:    "read secret/parent-group-governance/terraform/state-backend",
		},
		"refuses an empty bot token list": {
			projects:      []string{"example-subgroup/example-project"},
			emptyBotToken: true,
			wantErr:       "lists no bot_tokens",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a, vault, services := newIssuedTokensApp(t, tc.projects)
			delete(vault.secrets, tc.dropSecret)
			if tc.emptyBotToken {
				a.issuedTokens.CodeReviewerVariables.BotTokens = nil
			}
			assertOperationError(t, a.publishCodeReviewerVariables(context.Background()), tc.wantErr)
			assertRequestsInclude(t, services.recorded(), tc.wantRequests...)
		})
	}
}

// TestVaultKVReadField asserts the rejection of a secret without the requested field.
func TestVaultKVReadField(t *testing.T) {
	a, _, _ := newIssuedTokensApp(t, nil)
	kv, err := a.newAdministratorKV()
	if err != nil {
		t.Fatal(err)
	}
	_, err = kv.ReadField(context.Background(), issuedtokens.VaultField{Mount: "registry", Path: "platform/gitlab-group/top-level", Field: "full_path"})
	assertOperationError(t, err, "holds no field full_path")
}

func assertRequestsInclude(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, request := range want {
		if !slices.Contains(got, request) {
			t.Fatalf("requests %v lack %s", got, request)
		}
	}
}
