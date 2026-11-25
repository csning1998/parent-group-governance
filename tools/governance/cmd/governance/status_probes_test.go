package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
)

type testCtxKey struct{}

func TestObserveVaultMountAndKVProbes(t *testing.T) {
	srv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, srv, "example-root-token")
	ctx := context.Background()

	secretMounted, err := a.hasSecretMount(ctx)
	if err != nil || !secretMounted {
		t.Fatalf("hasSecretMount = (%t, %v), want (true, nil)", secretMounted, err)
	}
	certMounted, err := a.hasOperatorCertMount(ctx)
	if err != nil || !certMounted {
		t.Fatalf("hasOperatorCertMount = (%t, %v), want (true, nil)", certMounted, err)
	}
	if err := a.writeVaultKVMap(ctx, "secret", "example/path", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("writeVaultKVMap: %v", err)
	}
	got, found, err := a.readVaultKVMap(ctx, "secret", "example/path")
	if err != nil || !found || got["k"] != "v" {
		t.Fatalf("readVaultKVMap(existing) = (%v, %t, %v), want k=v", got, found, err)
	}
	if _, missing, err := a.readVaultKVMap(ctx, "secret", "missing/path"); err != nil || missing {
		t.Fatalf("readVaultKVMap(missing) = (%t, %v), want (false, nil)", missing, err)
	}
	if active, err := a.verifyAdminProxy(ctx); err != nil || active {
		t.Fatalf("verifyAdminProxy without proxy cfg = (%t, %v), want (false, nil)", active, err)
	}
}

func TestObserveVaultSonarQubeCredentialProbes(t *testing.T) {
	srv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, srv, "example-root-token")
	ctx := context.Background()

	sonarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pw, _ := r.BasicAuth()
		if pw == "example-rotated" {
			_, _ = w.Write([]byte(`{"valid":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"valid":false}`))
	}))
	t.Cleanup(sonarSrv.Close)

	a.credentials = loadExampleCredential(t, sonarSrv.URL+"/api/authentication/validate")
	a.issuedTokens.SonarQubeAnalysisToken.AdminPasswordKey = "sonarqube-admin-password"
	_ = a.writeVaultKVMap(ctx, "secret", "parent-group-governance/sonarqube/admin-account", map[string]string{"sonarqube_admin_password": "example-rotated"})

	fresh, retained, err := a.verifyFactoryDefault(ctx)
	if err != nil || fresh || retained != "sonarqube-admin-password" {
		t.Fatalf("verifyFactoryDefault = (%t, %q, %v), want (false, sonarqube-admin-password, nil)", fresh, retained, err)
	}
	ok, err := a.verifySonarQubeAdmin(ctx)
	if err != nil || !ok {
		t.Fatalf("verifySonarQubeAdmin = (%t, %v), want (true, nil)", ok, err)
	}
}

func TestVaultProbesPropagateAPIAndTransportErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	a := newFakeVaultApp(t, srv, "example-root-token")
	ctx := context.Background()

	if _, err := a.hasSecretMount(ctx); err == nil {
		t.Errorf("hasSecretMount on 500 expected error, got nil")
	}
	if _, err := a.hasOperatorCertMount(ctx); err == nil {
		t.Errorf("hasOperatorCertMount on 500 expected error, got nil")
	}
	if _, _, err := a.readVaultKVMap(ctx, "secret", "example/path"); err == nil {
		t.Errorf("readVaultKVMap on 500 expected error, got nil")
	}

	if err := os.Remove(filepath.Join(a.root, "vault", "tls", "ca-ml-dsa-87.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.hasOperatorCertMount(ctx); err == nil {
		t.Errorf("hasOperatorCertMount with missing CA file expected error, got nil")
	}
}

func TestVerifyFactoryDefaultFailsClosedOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	srv.Close()

	a := &app{credentials: loadExampleCredential(t, srv.URL+"/api/authentication/validate")}
	ready, _, err := a.verifyFactoryDefault(context.Background())
	if err == nil || ready {
		t.Fatalf("verifyFactoryDefault on unreachable endpoint = (%t, %v), want (false, non-nil error)", ready, err)
	}
}

func TestObserveGitLabProbes(t *testing.T) {
	vaultSrv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, vaultSrv, "example-root-token")
	ctx := context.Background()

	gitlabSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/api/v4/projects/example-group%2Fparent-group-governance",
			"/api/v4/groups/42/variables/SONAR_HOST_URL",
			"/api/v4/groups/42/variables/SONAR_TOKEN",
			"/api/v4/projects/example-group%2Fexample-app/variables/TAG_PUSH_TOKEN":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(gitlabSrv.Close)

	a.resolveOrigin = func(context.Context) (gitlabOrigin, error) {
		return gitlabOrigin{WebURL: gitlabSrv.URL, APIURL: gitlabSrv.URL + "/api/v4", TopLevelGroup: "example-group"}, nil
	}
	a.topology.OperatorVaultProxy.StateBackend = topology.StateBackend{VaultKVMount: "secret", VaultKVField: "token"}
	a.topology.OperatorVaultProxy.Identities = map[string]topology.ProxyIdentity{
		"credential-distributor-parent-group-governance": {CodeReviewerVariableProjects: []string{"example-app"}},
	}
	a.issuedTokens = issuedtokens.Config{
		GitLabGroupRegistry: issuedtokens.VaultField{Mount: "registry", Path: "platform/gitlab-group/top-level", Field: "group_id"},
		CodeReviewerVariables: issuedtokens.CodeReviewerVariablesConfig{
			BotTokens: []issuedtokens.ReviewerBotToken{{VariableKeys: []string{"TAG_PUSH_TOKEN"}}},
		},
	}

	_ = a.writeVaultKVMap(ctx, "secret", "parent-group-governance/terraform/state-backend", map[string]string{"token": "pat"})
	_ = a.writeVaultKVMap(ctx, "registry", "platform/gitlab-group/top-level", map[string]string{"group_id": "42"})

	if applied, err := a.inspectGitLabLayerApplied(ctx, filepath.Join(a.root, "terraform", "layers", "administration-gitlab-project")); err != nil || !applied {
		t.Fatalf("inspectGitLabLayerApplied(admin) = (%t, %v), want (true, nil)", applied, err)
	}
	if applied, err := a.inspectGitLabLayerApplied(ctx, filepath.Join(a.root, "terraform", "layers", "group-gitlab-configuration")); err != nil || !applied {
		t.Fatalf("inspectGitLabLayerApplied(config) = (%t, %v), want (true, nil)", applied, err)
	}
	if applied, err := a.inspectGitLabLayerApplied(ctx, filepath.Join(a.root, "terraform", "layers", "other")); err != nil || applied {
		t.Fatalf("inspectGitLabLayerApplied(other) = (%t, %v), want (false, nil)", applied, err)
	}
	if hasVar, err := a.verifyGroupVariable(ctx, "SONAR_TOKEN"); err != nil || !hasVar {
		t.Fatalf("verifyGroupVariable = (%t, %v), want (true, nil)", hasVar, err)
	}
	if present, total, err := a.verifyProjectVariables(ctx); err != nil || present != 1 || total != 1 {
		t.Fatalf("verifyProjectVariables = (%d, %d, %v), want (1, 1, nil)", present, total, err)
	}

	noTokenApp := newFakeVaultApp(t, vaultSrv, "")
	noTokenApp.resolveOrigin = a.resolveOrigin
	noTokenApp.topology.OperatorVaultProxy.Identities = a.topology.OperatorVaultProxy.Identities
	noTokenApp.issuedTokens = a.issuedTokens
	if present, total, err := noTokenApp.verifyProjectVariables(ctx); err != nil || present != 0 || total != 1 {
		t.Fatalf("verifyProjectVariables(no vault) = (%d, %d, %v), want (0, 1, nil)", present, total, err)
	}
}

func TestVerifyProjectVariablesPropagatesOriginAndGitLabErrors(t *testing.T) {
	vaultSrv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, vaultSrv, "")
	ctx := context.WithValue(context.Background(), testCtxKey{}, "caller")

	var seenCallerCtx any
	a.resolveOrigin = func(gotCtx context.Context) (gitlabOrigin, error) {
		seenCallerCtx = gotCtx.Value(testCtxKey{})
		return gitlabOrigin{}, errors.New("git remote failed")
	}
	if _, _, err := a.verifyProjectVariables(ctx); err == nil {
		t.Errorf("verifyProjectVariables when resolveOrigin fails expected error, got nil")
	}
	if seenCallerCtx != "caller" {
		t.Errorf("resolveOrigin received ctx value = %v, want caller", seenCallerCtx)
	}

	gitlabSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(gitlabSrv.Close)
	authedApp := newFakeVaultApp(t, vaultSrv, "example-root-token")
	authedApp.resolveOrigin = func(context.Context) (gitlabOrigin, error) {
		return gitlabOrigin{WebURL: gitlabSrv.URL, APIURL: gitlabSrv.URL + "/api/v4", TopLevelGroup: "example-group"}, nil
	}
	authedApp.topology.OperatorVaultProxy.StateBackend = topology.StateBackend{VaultKVMount: "secret", VaultKVField: "token"}
	authedApp.topology.OperatorVaultProxy.Identities = map[string]topology.ProxyIdentity{
		"credential-distributor-parent-group-governance": {CodeReviewerVariableProjects: []string{"example-app"}},
	}
	authedApp.issuedTokens = issuedtokens.Config{
		GitLabGroupRegistry: issuedtokens.VaultField{Mount: "registry", Path: "platform/gitlab-group/top-level", Field: "group_id"},
		CodeReviewerVariables: issuedtokens.CodeReviewerVariablesConfig{
			BotTokens: []issuedtokens.ReviewerBotToken{{VariableKeys: []string{"TAG_PUSH_TOKEN"}}},
		},
	}
	_ = authedApp.writeVaultKVMap(ctx, "secret", "parent-group-governance/terraform/state-backend", map[string]string{"token": "pat"})
	_ = authedApp.writeVaultKVMap(ctx, "registry", "platform/gitlab-group/top-level", map[string]string{"group_id": "42"})
	if _, _, err := authedApp.verifyProjectVariables(ctx); err == nil {
		t.Errorf("verifyProjectVariables on GitLab 500 expected error, got nil")
	}
}

func newFakeObserveVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	kv := make(map[string]map[string]any)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/mounts":
			_, _ = w.Write([]byte(`{"data":{"secret/":{"type":"kv"}}}`))
		case r.URL.Path == "/v1/sys/auth":
			_, _ = w.Write([]byte(`{"data":{"operator-cert/":{"type":"cert"}}}`))
		case strings.Contains(r.URL.Path, "/data/") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			var body struct {
				Data map[string]any `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			kv[r.URL.Path] = body.Data
			_, _ = w.Write([]byte(`{"data":{"version":1}}`))
		case strings.Contains(r.URL.Path, "/data/") && r.Method == http.MethodGet:
			data, ok := kv[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newFakeVaultApp(t *testing.T, srv *httptest.Server, token string) *app {
	t.Helper()
	root, home := t.TempDir(), t.TempDir()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	writePlainFile(t, filepath.Join(root, "vault", "tls", "ca-ml-dsa-87.pem"), string(caPEM))
	writePlainFile(t, filepath.Join(home, ".vault-token"), token)
	return &app{
		root: root,
		home: home,
		topology: topology.VaultTopology{
			BastionVault:       topology.BastionVault{LoopbackIP: "127.0.0.1", PublishIP: "192.0.2.10", APIPort: port},
			OperatorVaultProxy: topology.OperatorVaultProxy{GovernanceOwnerCode: "parent-group-governance", CertAuthMount: "operator-cert"},
		},
		out: ui.New(io.Discard, io.Discard),
	}
}

func loadExampleCredential(t *testing.T, verifyURL string) []credentials.Credential {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "topo.yaml")
	writePlainFile(t, cfgPath, "service_admin_passwords:\n  - key: sonarqube-admin-password\n    vault_kv_mount: secret\n    vault_kv_path: parent-group-governance/sonarqube/admin-account\n    length: 24\n    service:\n      mechanism: http_form\n      rotate_endpoint: "+verifyURL+"\n      verify_endpoint: "+verifyURL+"\n      admin_username: admin\n      factory_default_password: admin\n")
	cfg, err := credentials.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatal(err)
	}
	return creds
}
