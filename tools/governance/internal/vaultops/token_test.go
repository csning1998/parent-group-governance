package vaultops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestDecodeRootToken_RejectsMalformedInput(t *testing.T) {
	for name, encoded := range map[string]string{"not base64": "!!!", "length mismatch": base64.RawStdEncoding.EncodeToString([]byte("short"))} {
		if _, err := decodeRootToken(encoded, "0123456789"); err == nil {
			t.Errorf("decodeRootToken(%s) error = nil, want a rejection", name)
		}
	}
}

func TestGenerateRoot_CancelsBelowTheThreshold(t *testing.T) {
	srv, cancelled := generateRootServer(t, false, 3, "hvs.example-break-glass-token000")
	p := newGenerateRootPaths(t, srv.URL, "key1\nkey2\n")
	op := newTestOperator(t, p, srv.URL)

	if err := op.GenerateRoot(context.Background()); err == nil {
		t.Fatal("GenerateRoot error = nil, want the threshold failure")
	}
	if !cancelled.Load() || vaultclient.ReadTokenFile(p.Home) != "" {
		t.Errorf("cancelled = %v, token file = %q, want a cancelled attempt without a token", cancelled.Load(), vaultclient.ReadTokenFile(p.Home))
	}
}

func TestGenerateRoot_RefusesAnAttemptInProgress(t *testing.T) {
	srv, _ := generateRootServer(t, true, 3, "hvs.example-break-glass-token000")
	p := newGenerateRootPaths(t, srv.URL, "key1\n")
	op := newTestOperator(t, p, srv.URL)

	if err := op.GenerateRoot(context.Background()); !errors.Is(err, ErrGenerateRootInProgress) {
		t.Errorf("GenerateRoot error = %v, want ErrGenerateRootInProgress", err)
	}
}

func TestGenerateRoot_RefusesAnExistingTokenFile(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	if err := vaultclient.PersistTokenFile(p.Home, "s.existing"); err != nil {
		t.Fatal(err)
	}
	op := newTestOperator(t, p, "http://127.0.0.1:8200")
	if err := op.GenerateRoot(context.Background()); !errors.Is(err, ErrRootTokenPresent) {
		t.Errorf("GenerateRoot error = %v, want ErrRootTokenPresent", err)
	}
}

func TestGenerateRoot_WritesTheDecodedToken(t *testing.T) {
	const token = "hvs.example-break-glass-token000"
	srv, _ := generateRootServer(t, false, 3, token)
	p := newGenerateRootPaths(t, srv.URL, "key1\nkey2\nkey3\nkey4\nkey5\n")
	op := newTestOperator(t, p, srv.URL)

	if err := op.GenerateRoot(context.Background()); err != nil {
		t.Fatalf("GenerateRoot: %v", err)
	}
	if got := vaultclient.ReadTokenFile(p.Home); got != token {
		t.Errorf("token file = %q, want %q", got, token)
	}
	assertMode(t, p.RootTokenFile(), 0o600)
}

func TestRevokeRoot_KeepsRootWithoutASuccessorLogin(t *testing.T) {
	var revoked atomic.Bool
	target := tokenServer(t, []string{"root"}, &revoked)
	successor := tokenServer(t, []string{"default"}, new(atomic.Bool))
	p := prepareTestPaths(t)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, target.URL)
	err := op.RevokeRoot(context.Background(), vaultclient.Config{Address: successor.URL, Token: "proxy-supplied"}, "successor-policy")
	if !errors.Is(err, ErrSuccessorNotReady) {
		t.Fatalf("RevokeRoot error = %v, want ErrSuccessorNotReady", err)
	}
	if revoked.Load() || vaultclient.ReadTokenFile(p.Home) != "s.root" {
		t.Error("RevokeRoot revoked or removed the root token without a successor login")
	}
}

func TestRevokeRoot_RefusesATokenOtherThanRoot(t *testing.T) {
	var revoked atomic.Bool
	target := tokenServer(t, []string{"default"}, &revoked)
	successor := tokenServer(t, []string{"successor-policy"}, new(atomic.Bool))
	p := prepareTestPaths(t)
	if err := vaultclient.PersistTokenFile(p.Home, "s.other"); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, target.URL)
	err := op.RevokeRoot(context.Background(), vaultclient.Config{Address: successor.URL}, "successor-policy")
	if !errors.Is(err, ErrNoRootToken) || revoked.Load() {
		t.Errorf("RevokeRoot error = %v, revoked = %v, want ErrNoRootToken without a revocation", err, revoked.Load())
	}
}

func TestRevokeRoot_RequiresATokenFile(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	op := newTestOperator(t, p, "http://127.0.0.1:8200")
	if err := op.RevokeRoot(context.Background(), vaultclient.Config{}, "successor-policy"); !errors.Is(err, ErrNoRootToken) {
		t.Errorf("RevokeRoot error = %v, want ErrNoRootToken", err)
	}
}

func TestRevokeRoot_RevokesOnceTheSuccessorIdentityLogsIn(t *testing.T) {
	var revoked atomic.Bool
	target := tokenServer(t, []string{"root"}, &revoked)
	successor := tokenServer(t, []string{"default", "successor-policy"}, new(atomic.Bool))
	p := prepareTestPaths(t)
	writeInitFile(t, p, `{"root_token":"s.root","unseal_keys_b64":["key1"]}`)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, target.URL)
	err := op.RevokeRoot(context.Background(), vaultclient.Config{Address: successor.URL, Token: "proxy-supplied"}, "successor-policy")
	if err != nil {
		t.Fatalf("RevokeRoot: %v", err)
	}
	if !revoked.Load() {
		t.Error("revoke-self was not called")
	}
	if got := vaultclient.ReadTokenFile(p.Home); got != "" {
		t.Errorf("token file = %q, want removed", got)
	}
	data, err := os.ReadFile(p.InitFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s.root") || !strings.Contains(string(data), "key1") {
		t.Errorf("init file = %s, want the root token cleared and the unseal keys kept", data)
	}
}

// generateRootServer completes an attempt after threshold keys and encodes the token with the one-time password.
func generateRootServer(t *testing.T, started bool, threshold int, token string) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	const otp = "0123456789abcdefghijklmnopqrstuv"
	var progress atomic.Int32
	cancelled := new(atomic.Bool)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/generate-root/attempt", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": started, "progress": int(progress.Load()), "required": threshold})
		case http.MethodDelete:
			cancelled.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": true, "nonce": "example-nonce", "otp": otp, "otp_length": len(otp)})
		}
	})
	mux.HandleFunc("/v1/sys/generate-root/update", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["nonce"] != "example-nonce" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if int(progress.Add(1)) < threshold {
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": false})
			return
		}
		encoded := make([]byte, len(otp))
		for i := range encoded {
			encoded[i] = token[i] ^ otp[i]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "encoded_token": base64.RawStdEncoding.EncodeToString(encoded)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, cancelled
}

func newGenerateRootPaths(t *testing.T, addr, keys string) Paths {
	t.Helper()
	p := prepareTestPaths(t)
	if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.UnsealKeyFile(), []byte(keys), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tokenServer answers lookup-self with policies and records a revoke-self call.
func tokenServer(t *testing.T, policies []string, revoked *atomic.Bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": policies}})
	})
	mux.HandleFunc("/v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		revoked.Store(true)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeInitFile(t *testing.T, p Paths, content string) {
	t.Helper()
	if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.InitFile(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
