package vaultops

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", path, err)
	}
	return cert
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want)
	}
}

type fakeEnv struct {
	mu sync.Mutex
	kv map[string]string
}

func newFakeEnv() *fakeEnv { return &fakeEnv{kv: map[string]string{}} }

func (e *fakeEnv) Set(k, v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.kv[k] = v
}

func (e *fakeEnv) get(k string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.kv[k]
}

func discardOut() *ui.Printer { return ui.New(io.Discard, io.Discard) }

const (
	fakeAdminToken    = "s.admin"
	fakeAmbientToken  = "s.ambient"
	fakeWrappingToken = "s.wrapping"
	fakeTenantToken   = "s.tenant"
	fakeTenantAccess  = "accessor-tenant"
	fakeRoleID        = "role-id-meta-platform"
	fakeSecretID      = "secret-id-single-use"
	fakeOperatorRole  = "meta-platform-terraform-operator"
)

// tenantCall records one request which the fake Bastion Vault received.
type tenantCall struct {
	path    string
	token   string
	wrapTTL string
	body    map[string]interface{}
}

// fakeTenantVault serves the AppRole, wrapping, and token endpoints which a tenant session touches.
type fakeTenantVault struct {
	mu       sync.Mutex
	calls    []tenantCall
	mount    string
	consumed bool
	// faults maps an endpoint suffix to the HTTP status which replaces the success response.
	faults map[string]int
	// emptyData lists endpoint suffixes which answer with an empty data block.
	emptyData map[string]bool
	// unwrappedMint returns the secret ID in clear even when the request asks for response wrapping.
	unwrappedMint bool
}

func (f *fakeTenantVault) injectFault(suffix string, status int) {
	if f.faults == nil {
		f.faults = map[string]int{}
	}
	f.faults[suffix] = status
}

func (f *fakeTenantVault) injectEmptyData(suffix string) {
	if f.emptyData == nil {
		f.emptyData = map[string]bool{}
	}
	f.emptyData[suffix] = true
}

// serveInjected answers a request whose path matches an injected fault or empty data block.
func (f *fakeTenantVault) serveInjected(w http.ResponseWriter, c tenantCall) bool {
	for suffix, status := range f.faults {
		if strings.HasSuffix(c.path, suffix) {
			writeVaultErrors(w, status, "injected fault")
			return true
		}
	}
	for suffix := range f.emptyData {
		if strings.HasSuffix(c.path, suffix) {
			writeVaultJSON(w, map[string]interface{}{"data": map[string]interface{}{}})
			return true
		}
	}
	return false
}

func newFakeTenantVault(t *testing.T, mount string) (*fakeTenantVault, *httptest.Server) {
	t.Helper()
	fv := &fakeTenantVault{mount: mount}
	srv := httptest.NewServer(http.HandlerFunc(fv.serve))
	t.Cleanup(srv.Close)
	return fv, srv
}

func (f *fakeTenantVault) record(r *http.Request) tenantCall {
	c := tenantCall{
		path:    r.URL.Path,
		token:   r.Header.Get("X-Vault-Token"),
		wrapTTL: r.Header.Get("X-Vault-Wrap-TTL"),
	}
	// An empty or non-JSON body leaves c.body nil, which the assertions treat as absent.
	_ = json.NewDecoder(r.Body).Decode(&c.body)
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	return c
}

func (f *fakeTenantVault) snapshot() []tenantCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tenantCall(nil), f.calls...)
}

func (f *fakeTenantVault) serve(w http.ResponseWriter, r *http.Request) {
	c := f.record(r)
	if f.serveInjected(w, c) {
		return
	}
	rolePath := "/v1/auth/" + f.mount + "/role/" + fakeOperatorRole
	switch c.path {
	case rolePath + "/role-id":
		f.serveRoleID(w, c)
	case rolePath + "/secret-id":
		f.serveSecretID(w, c)
	case "/v1/sys/wrapping/unwrap":
		f.serveUnwrap(w, c)
	case "/v1/auth/" + f.mount + "/login":
		f.serveLogin(w, c)
	case "/v1/auth/token/revoke-self":
		w.WriteHeader(http.StatusNoContent)
	default:
		writeVaultErrors(w, http.StatusNotFound, "no handler for "+c.path)
	}
}

func (f *fakeTenantVault) serveRoleID(w http.ResponseWriter, c tenantCall) {
	if c.token != fakeAdminToken {
		writeVaultErrors(w, http.StatusForbidden, "permission denied")
		return
	}
	writeVaultJSON(w, map[string]interface{}{"data": map[string]interface{}{"role_id": fakeRoleID}})
}

// serveSecretID returns the secret ID in clear unless the request asks for response wrapping.
func (f *fakeTenantVault) serveSecretID(w http.ResponseWriter, c tenantCall) {
	if c.token != fakeAdminToken {
		writeVaultErrors(w, http.StatusForbidden, "permission denied")
		return
	}
	if c.wrapTTL == "" || f.unwrappedMint {
		writeVaultJSON(w, map[string]interface{}{"data": map[string]interface{}{"secret_id": fakeSecretID}})
		return
	}
	writeVaultJSON(w, map[string]interface{}{"wrap_info": map[string]interface{}{"token": fakeWrappingToken, "ttl": 60}})
}

// serveUnwrap honors one unwrap per wrapping token, as Vault does.
func (f *fakeTenantVault) serveUnwrap(w http.ResponseWriter, c tenantCall) {
	f.mu.Lock()
	rejected := f.consumed || c.token != fakeWrappingToken
	f.consumed = true
	f.mu.Unlock()
	if rejected {
		writeVaultErrors(w, http.StatusBadRequest, "wrapping token is not valid or does not exist")
		return
	}
	writeVaultJSON(w, map[string]interface{}{"data": map[string]interface{}{"secret_id": fakeSecretID}})
}

func (f *fakeTenantVault) serveLogin(w http.ResponseWriter, c tenantCall) {
	if c.body["role_id"] != fakeRoleID || c.body["secret_id"] != fakeSecretID {
		writeVaultErrors(w, http.StatusBadRequest, "invalid role or secret ID")
		return
	}
	writeVaultJSON(w, map[string]interface{}{"auth": map[string]interface{}{"client_token": fakeTenantToken, "accessor": fakeTenantAccess}})
}

func writeVaultJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// An encode failure on the test server surfaces as a parse error at the client under test.
	_ = json.NewEncoder(w).Encode(v)
}

func writeVaultErrors(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// An encode failure on the test server surfaces as a parse error at the client under test.
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{msg}})
}

// newFakeAdminClient returns a client which holds the operator token, with the ambient VAULT_TOKEN set to a decoy.
func newFakeAdminClient(t *testing.T, addr string) *vaultapi.Client {
	t.Helper()
	t.Setenv("VAULT_TOKEN", fakeAmbientToken)
	t.Setenv("VAULT_CACERT", "")
	client, err := newClient(addr, "", fakeAdminToken)
	if err != nil {
		t.Fatalf("new admin client: %v", err)
	}
	client.SetMaxRetries(0)
	return client
}

func findTenantCall(calls []tenantCall, suffix string) (tenantCall, bool) {
	for _, c := range calls {
		if strings.HasSuffix(c.path, suffix) {
			return c, true
		}
	}
	return tenantCall{}, false
}
