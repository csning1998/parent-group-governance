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

func newLiveTestPaths(t *testing.T, bastionAddr string) Paths {
	t.Helper()
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir(), bastionVaultAddr: bastionAddr}
	if err := GenerateTLS(context.Background(), p, discardOut()); err != nil {
		t.Fatalf("GenerateTLS: %v", err)
	}
	return p
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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": sealed})
	}
}

func fakeInitHandler(rootToken string, unsealKeys []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": unsealKeys, "keys_base64": unsealKeys, "root_token": rootToken,
		})
	}
}

func fakeUnsealHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"sealed": false})
	}
}

func fakeVaultErrorHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"boom"}})
	}
}

func TestInitSyncsTokenOnSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeInitHandler("hvs.faketoken", []string{"a2V5MQ==", "a2V5Mg==", "a2V5Mw=="}))
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(false))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)
	env := newFakeEnv()

	if err := Init(context.Background(), p, discardOut(), env); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if env.kv["VAULT_TOKEN"] != "hvs.faketoken" {
		t.Errorf("env.Set(VAULT_TOKEN) = %v, want hvs.faketoken", env.kv)
	}
	data, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil || string(data) != "hvs.faketoken" {
		t.Errorf("resolveRootTokenFile content = %q, err %v, want hvs.faketoken", data, err)
	}
}

func TestInitFailsWhenVaultInitAPIErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeVaultErrorHandler(http.StatusInternalServerError))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)
	env := newFakeEnv()

	err := Init(context.Background(), p, discardOut(), env)
	if err == nil {
		t.Fatal("Init: want error, got nil")
	}
	if _, statErr := os.Stat(p.resolveInitFile()); statErr == nil {
		t.Error("resolveInitFile was created despite a failed Vault init API call")
	}
	if len(env.kv) != 0 {
		t.Errorf("env.Set was called: %v", env.kv)
	}
}

func TestInitFailsWhenInitResponseHasNoUnsealKeys(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeInitHandler("hvs.faketoken", nil))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)
	env := newFakeEnv()

	err := Init(context.Background(), p, discardOut(), env)
	if err == nil || !strings.Contains(err.Error(), "no unseal keys in init response") {
		t.Fatalf("Init = %v, want error containing %q", err, "no unseal keys in init response")
	}
	if len(env.kv) != 0 {
		t.Errorf("env.Set was called: %v", env.kv)
	}
}

func TestUnsealBastionAlreadyUnsealedDoesNotSyncToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(false))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte("key1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"hvs.shouldnotsync"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	if err := UnsealBastion(context.Background(), p, discardOut(), env); err != nil {
		t.Fatalf("UnsealBastion: %v", err)
	}
	if len(env.kv) != 0 {
		t.Errorf("env.Set was called on the already-unsealed fast path: %v", env.kv)
	}
}

func TestUnsealBastionSyncsTokenAfterActuallyUnsealing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true, false))
	mux.HandleFunc("/v1/sys/unseal", fakeUnsealHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte("key1\nkey2\nkey3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"hvs.freshtoken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveRootTokenFile(), []byte("hvs.staletoken"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	if err := UnsealBastion(context.Background(), p, discardOut(), env); err != nil {
		t.Fatalf("UnsealBastion: %v", err)
	}
	if env.kv["VAULT_TOKEN"] != "hvs.freshtoken" {
		t.Errorf("env.Set(VAULT_TOKEN) = %v, want hvs.freshtoken", env.kv)
	}
	data, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil || string(data) != "hvs.freshtoken" {
		t.Errorf("resolveRootTokenFile content = %q, err %v, want hvs.freshtoken", data, err)
	}
}

func TestUnsealBastionFailsWhenUnsealAPIErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true))
	mux.HandleFunc("/v1/sys/unseal", fakeVaultErrorHandler(http.StatusInternalServerError))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte("key1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	err := UnsealBastion(context.Background(), p, discardOut(), env)
	if err == nil || !strings.Contains(err.Error(), "vaultops: unseal:") {
		t.Fatalf("UnsealBastion = %v, want error containing %q", err, "vaultops: unseal:")
	}
}

func TestProbeBastionStateUnreachableConnectionRefused(t *testing.T) {
	p := newLiveTestPaths(t, "http://127.0.0.1:1")

	running, sealed, err := ProbeBastionState(context.Background(), p)
	if err != nil {
		t.Fatalf("ProbeBastionState: want nil error, got %v", err)
	}
	if running || sealed {
		t.Errorf("ProbeBastionState = (%v, %v), want (false, false)", running, sealed)
	}
}

func TestInspectBastionStatusUnreachableReturnsZeroValue(t *testing.T) {
	p := newLiveTestPaths(t, "http://127.0.0.1:1")

	got := InspectBastionStatus(context.Background(), p)
	if got != (SealStatus{}) {
		t.Errorf("InspectBastionStatus = %+v, want zero value", got)
	}
}

func TestInspectBastionStatusReachableSealed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newLiveTestPaths(t, srv.URL)

	got := InspectBastionStatus(context.Background(), p)
	want := SealStatus{Reachable: true, Initialized: true, Sealed: true}
	if got != want {
		t.Errorf("InspectBastionStatus = %+v, want %+v", got, want)
	}
}
