package vaultops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInitFailsWithoutUnsealKeysInTheInitResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeInitHandler("hvs.faketoken", nil))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := prepareTestPaths(t)
	op := newTestOperator(t, p, srv.URL)

	err := op.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the init response does not contain unseal keys") {
		t.Fatalf("Init = %v, want error containing %q", err, "the init response does not contain unseal keys")
	}
	if _, statErr := os.Stat(p.RootTokenFile()); statErr == nil {
		t.Error("RootTokenFile was written despite a failed initialization")
	}
}

func TestInitFailsWhenVaultInitAPIErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeVaultErrorHandler(http.StatusInternalServerError))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := prepareTestPaths(t)
	op := newTestOperator(t, p, srv.URL)

	err := op.Init(context.Background())
	if err == nil {
		t.Fatal("Init: want error, got nil")
	}
	if _, statErr := os.Stat(p.InitFile()); statErr == nil {
		t.Error("InitFile was created despite a failed Vault init API call")
	}
	if _, statErr := os.Stat(p.RootTokenFile()); statErr == nil {
		t.Error("RootTokenFile was written despite a failed initialization")
	}
}

func TestInitWritesTheBootstrapRootToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeInitHandler("hvs.faketoken", []string{"a2V5MQ==", "a2V5Mg==", "a2V5Mw=="}))
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(false))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := prepareTestPaths(t)
	op := newTestOperator(t, p, srv.URL)

	if err := op.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	data, err := os.ReadFile(p.RootTokenFile())
	if err != nil || string(data) != "hvs.faketoken" {
		t.Errorf("RootTokenFile content = %q, err %v, want hvs.faketoken", data, err)
	}
}

func TestUnsealAlreadyUnsealedDoesNotSyncToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(false))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := prepareTestPaths(t)
	if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.UnsealKeyFile(), []byte("key1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.InitFile(), []byte(`{"root_token":"hvs.shouldnotsync"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, srv.URL)
	if err := op.Unseal(context.Background()); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, statErr := os.Stat(p.RootTokenFile()); statErr == nil {
		t.Error("RootTokenFile was written on the already-unsealed fast path")
	}
}

func TestUnsealFailsWhenUnsealAPIErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true))
	mux.HandleFunc("/v1/sys/unseal", fakeVaultErrorHandler(http.StatusInternalServerError))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := prepareTestPaths(t)
	if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.UnsealKeyFile(), []byte("key1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, srv.URL)
	err := op.Unseal(context.Background())
	if err == nil || !strings.Contains(err.Error(), "vaultops: unseal:") {
		t.Fatalf("Unseal = %v, want error containing %q", err, "vaultops: unseal:")
	}
}

func TestUnsealKeepsTheTokenHelperFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true, false))
	mux.HandleFunc("/v1/sys/unseal", fakeUnsealHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := prepareTestPaths(t)
	if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.UnsealKeyFile(), []byte("key1\nkey2\nkey3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.InitFile(), []byte(`{"root_token":"hvs.freshtoken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.RootTokenFile(), []byte("hvs.staletoken"), 0o600); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, srv.URL)
	if err := op.Unseal(context.Background()); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	// An unseal MUST NOT restore a root token to ~/.vault-token after revocation.
	data, err := os.ReadFile(p.RootTokenFile())
	if err != nil || string(data) != "hvs.staletoken" {
		t.Errorf("RootTokenFile content = %q, err %v, want the untouched hvs.staletoken", data, err)
	}
}

func fakeInitHandler(rootToken string, unsealKeys []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": unsealKeys, "keys_base64": unsealKeys, "root_token": rootToken,
		})
	}
}

func fakeSealStatusHandler(sequence ...bool) http.HandlerFunc {
	var call int32
	return func(w http.ResponseWriter, r *http.Request) {
		idx := int(atomic.AddInt32(&call, 1)) - 1
		sealed := sequence[len(sequence)-1]
		if idx < len(sequence) {
			sealed = sequence[idx]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": sealed})
	}
}

func fakeUnsealHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sealed": false})
	}
}

func fakeVaultErrorHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"boom"}})
	}
}

func prepareTestPaths(t *testing.T) Paths {
	t.Helper()
	p := Paths{
		ProjectRoot: t.TempDir(),
		Home:        t.TempDir(),
	}
	if err := GenerateTLS(p.TLSDir(), testListeners); err != nil {
		t.Fatalf("GenerateTLS: %v", err)
	}
	return p
}
