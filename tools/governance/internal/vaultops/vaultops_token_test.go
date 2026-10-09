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

	if err := GenerateRoot(context.Background(), p, discardOut()); err == nil {
		t.Fatal("GenerateRoot error = nil, want the threshold failure")
	}
	if !cancelled.Load() || vaultclient.ReadTokenFile(p.Home) != "" {
		t.Errorf("cancelled = %v, token file = %q, want a cancelled attempt without a token", cancelled.Load(), vaultclient.ReadTokenFile(p.Home))
	}
}

func TestGenerateRoot_RefusesAnAttemptInProgress(t *testing.T) {
	srv, _ := generateRootServer(t, true, 3, "hvs.example-break-glass-token000")
	p := newGenerateRootPaths(t, srv.URL, "key1\n")

	if err := GenerateRoot(context.Background(), p, discardOut()); !errors.Is(err, ErrGenerateRootInProgress) {
		t.Errorf("GenerateRoot error = %v, want ErrGenerateRootInProgress", err)
	}
}

func TestGenerateRoot_RefusesAnExistingTokenFile(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	if err := vaultclient.PersistTokenFile(p.Home, "s.existing"); err != nil {
		t.Fatal(err)
	}
	if err := GenerateRoot(context.Background(), p, discardOut()); !errors.Is(err, ErrRootTokenPresent) {
		t.Errorf("GenerateRoot error = %v, want ErrRootTokenPresent", err)
	}
}

func TestGenerateRoot_WritesTheDecodedToken(t *testing.T) {
	const token = "hvs.example-break-glass-token000"
	srv, _ := generateRootServer(t, false, 3, token)
	p := newGenerateRootPaths(t, srv.URL, "key1\nkey2\nkey3\nkey4\nkey5\n")

	if err := GenerateRoot(context.Background(), p, discardOut()); err != nil {
		t.Fatalf("GenerateRoot: %v", err)
	}
	if got := vaultclient.ReadTokenFile(p.Home); got != token {
		t.Errorf("token file = %q, want %q", got, token)
	}
	assertMode(t, p.resolveRootTokenFile(), 0o600)
}

func TestPersistBootstrapRootToken(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	writeInitFile(t, p, `{"root_token":"s.abc123"}`)

	if err := persistBootstrapRootToken(p); err != nil {
		t.Fatalf("persistBootstrapRootToken: %v", err)
	}
	if got := vaultclient.ReadTokenFile(p.Home); got != "s.abc123" {
		t.Errorf("token file = %q, want s.abc123", got)
	}
	assertMode(t, p.resolveRootTokenFile(), 0o600)
}

func TestPersistBootstrapRootToken_RejectsAnUnusableInitFile(t *testing.T) {
	for name, content := range map[string]string{"malformed": "not json", "empty token": `{"root_token":""}`} {
		t.Run(name, func(t *testing.T) {
			p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
			writeInitFile(t, p, content)
			if err := persistBootstrapRootToken(p); err == nil {
				t.Error("persistBootstrapRootToken error = nil, want a rejection")
			}
			if got := vaultclient.ReadTokenFile(p.Home); got != "" {
				t.Errorf("token file = %q, want none", got)
			}
		})
	}
}

func TestRevokeRoot_KeepsRootWithoutAFoundationLogin(t *testing.T) {
	var revoked atomic.Bool
	bastion := tokenServer(t, []string{"root"}, &revoked)
	foundation := tokenServer(t, []string{"default"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	if !errors.Is(err, ErrFoundationNotReady) {
		t.Fatalf("RevokeRoot error = %v, want ErrFoundationNotReady", err)
	}
	if revoked.Load() || vaultclient.ReadTokenFile(p.Home) != "s.root" {
		t.Error("RevokeRoot revoked or removed the root token without a foundation login")
	}
}

func TestRevokeRoot_RefusesATokenOtherThanRoot(t *testing.T) {
	var revoked atomic.Bool
	bastion := tokenServer(t, []string{"default"}, &revoked)
	foundation := tokenServer(t, []string{"operator-example-foundation"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	if err := vaultclient.PersistTokenFile(p.Home, "s.other"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL}, "operator-example-foundation", discardOut())
	if !errors.Is(err, ErrNoRootToken) || revoked.Load() {
		t.Errorf("RevokeRoot error = %v, revoked = %v, want ErrNoRootToken without a revocation", err, revoked.Load())
	}
}

func TestRevokeRoot_RequiresATokenFile(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	if err := RevokeRoot(context.Background(), p, vaultclient.Config{}, "operator-example-foundation", discardOut()); !errors.Is(err, ErrNoRootToken) {
		t.Errorf("RevokeRoot error = %v, want ErrNoRootToken", err)
	}
}

func TestRevokeRoot_RevokesOnceTheFoundationIdentityLogsIn(t *testing.T) {
	var revoked atomic.Bool
	bastion := tokenServer(t, []string{"root"}, &revoked)
	foundation := tokenServer(t, []string{"default", "operator-example-foundation"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	writeInitFile(t, p, `{"root_token":"s.root","unseal_keys_b64":["key1"]}`)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	if err != nil {
		t.Fatalf("RevokeRoot: %v", err)
	}
	if !revoked.Load() {
		t.Error("revoke-self was not called")
	}
	if got := vaultclient.ReadTokenFile(p.Home); got != "" {
		t.Errorf("token file = %q, want removed", got)
	}
	data, err := os.ReadFile(p.resolveInitFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s.root") || !strings.Contains(string(data), "key1") {
		t.Errorf("init file = %s, want the root token cleared and the unseal keys kept", data)
	}
}

// generateRootServer completes an attempt after threshold keys and encodes token with the one-time password.
func generateRootServer(t *testing.T, started bool, threshold int, token string) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	const otp = "0123456789abcdefghijklmnopqrstuv"
	var progress atomic.Int32
	cancelled := new(atomic.Bool)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/generate-root/attempt", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": started})
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
	p := newLiveTestPaths(t, addr)
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte(keys), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tokenServer answers lookup-self with policies and records a revoke-self.
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
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
