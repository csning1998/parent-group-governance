package vaultops

import (
	"context"
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

func TestClearInitRootToken(t *testing.T) {
	t.Run("absent file", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
		if err := clearInitRootToken(p); err != nil {
			t.Fatalf("clearInitRootToken: %v", err)
		}
	})
	t.Run("unreadable path", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
		if err := os.MkdirAll(p.resolveInitFile(), 0o700); err != nil {
			t.Fatal(err)
		}
		err := clearInitRootToken(p)
		if err == nil || !strings.Contains(err.Error(), "vaultops: read") {
			t.Fatalf("clearInitRootToken = %v, want a read error", err)
		}
	})
	t.Run("malformed document", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
		writeInitFile(t, p, "not json")
		err := clearInitRootToken(p)
		if err == nil || !strings.Contains(err.Error(), "vaultops: parse") {
			t.Fatalf("clearInitRootToken = %v, want a parse error", err)
		}
	})
	t.Run("read only file", func(t *testing.T) {
		skipWhenRoot(t)
		p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
		writeInitFile(t, p, `{"root_token":"s.root","keys":["a"]}`)
		if err := os.Chmod(p.resolveInitFile(), 0o444); err != nil {
			t.Fatal(err)
		}
		err := clearInitRootToken(p)
		if err == nil || !strings.Contains(err.Error(), "vaultops: write") {
			t.Fatalf("clearInitRootToken = %v, want a write error", err)
		}
	})
}

func TestGenerateRoot_ReportsAClientFailure(t *testing.T) {
	p := newGenerateRootPaths(t, "https://127.0.0.1:8200", "key1\n")
	if err := os.RemoveAll(p.ResolveTLSDir()); err != nil {
		t.Fatal(err)
	}
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || strings.Contains(err.Error(), "unseal keys not found") {
		t.Fatalf("GenerateRoot = %v, want the client failure", err)
	}
}

func TestGenerateRoot_ReportsADecodeFailure(t *testing.T) {
	const otp = "0123456789abcdefghijklmnopqrstuv"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": false})
		case strings.HasSuffix(r.URL.Path, "/update"):
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "encoded_token": "!!!"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": true, "nonce": "example-nonce", "otp": otp})
		}
	}))
	t.Cleanup(srv.Close)
	p := newGenerateRootPaths(t, srv.URL, "key1\n")
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "decode the encoded root token") {
		t.Fatalf("GenerateRoot = %v, want the decode error", err)
	}
}

func TestGenerateRoot_ReportsAStatusFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	p := newGenerateRootPaths(t, srv.URL, "key1\n")
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "generate-root status") {
		t.Fatalf("GenerateRoot = %v, want the status error", err)
	}
}

func TestGenerateRoot_ReportsATokenFileFailure(t *testing.T) {
	skipWhenRoot(t)
	const token = "hvs.example-break-glass-token000"
	srv, _ := generateRootServer(t, false, 1, token)
	p := newGenerateRootPaths(t, srv.URL, "key1\n")
	if err := os.Chmod(p.Home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p.Home, 0o700) })
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "vaultclient:") {
		t.Fatalf("GenerateRoot = %v, want the token-file error", err)
	}
}

func TestGenerateRoot_ReportsAnInitFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"started": false})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	p := newGenerateRootPaths(t, srv.URL, "key1\n")
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "generate-root init") {
		t.Fatalf("GenerateRoot = %v, want the init error", err)
	}
}

func TestGenerateRoot_ReportsAnUpdateFailure(t *testing.T) {
	const otp = "0123456789abcdefghijklmnopqrstuv"
	var cancelled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": false})
		case r.Method == http.MethodDelete:
			cancelled.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/update"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"started": true, "nonce": "example-nonce", "otp": otp})
		}
	}))
	t.Cleanup(srv.Close)
	p := newGenerateRootPaths(t, srv.URL, "key1\n")
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "generate-root update") || !cancelled.Load() {
		t.Fatalf("GenerateRoot = %v, cancelled = %v, want the update failure and a cancelled attempt", err, cancelled.Load())
	}
}

func TestGenerateRoot_ReportsMissingUnsealKeys(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	err := GenerateRoot(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "unseal keys not found") {
		t.Fatalf("GenerateRoot = %v, want the missing-keys error", err)
	}
}

func TestGenerateRoot_SkipsABlankUnsealKey(t *testing.T) {
	const token = "hvs.example-break-glass-token000"
	srv, _ := generateRootServer(t, false, 3, token)
	p := newGenerateRootPaths(t, srv.URL, "key1\n\nkey2\nkey3\n")
	if err := GenerateRoot(context.Background(), p, discardOut()); err != nil {
		t.Fatalf("GenerateRoot: %v", err)
	}
	if got := vaultclient.ReadTokenFile(p.Home); got != token {
		t.Errorf("token file = %q, want %q", got, token)
	}
}

func TestHoldsPolicyRejectsANilSecret(t *testing.T) {
	if holdsPolicy(nil, "root") {
		t.Fatal("holdsPolicy(nil) = true, want false")
	}
}

func TestRevokeRoot_ClearsAnAbsentInitFile(t *testing.T) {
	var revoked atomic.Bool
	bastion := tokenServer(t, []string{"root"}, &revoked)
	foundation := tokenServer(t, []string{"operator-example-foundation"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	if err != nil {
		t.Fatalf("RevokeRoot: %v", err)
	}
	if !revoked.Load() || vaultclient.ReadTokenFile(p.Home) != "" {
		t.Fatalf("revoked = %v, token = %q, want the token removed", revoked.Load(), vaultclient.ReadTokenFile(p.Home))
	}
}

func TestRevokeRoot_ReportsABastionClientFailure(t *testing.T) {
	foundation := tokenServer(t, []string{"operator-example-foundation"}, new(atomic.Bool))
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir(), bastionVaultAddr: "https://127.0.0.1:8200"}
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}
	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	if err == nil || errors.Is(err, ErrFoundationNotReady) || errors.Is(err, ErrNoRootToken) {
		t.Fatalf("RevokeRoot error = %v, want the bastion client failure", err)
	}
}

func TestRevokeRoot_ReportsAFoundationClientFailure(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}
	err := RevokeRoot(context.Background(), p, vaultclient.Config{
		Address:    "https://127.0.0.1:8200",
		CACertPath: t.TempDir() + "/missing-ca.pem",
		Token:      "proxy-supplied",
	}, "operator-example-foundation", discardOut())
	if !errors.Is(err, ErrFoundationNotReady) {
		t.Fatalf("RevokeRoot error = %v, want ErrFoundationNotReady", err)
	}
}

func TestRevokeRoot_ReportsARevocationFailure(t *testing.T) {
	bastion := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": []string{"root"}}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(bastion.Close)
	foundation := tokenServer(t, []string{"operator-example-foundation"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	needle := "revoke" + " the root token"
	if err == nil || !strings.Contains(err.Error(), needle) {
		t.Fatalf("RevokeRoot error = %v, want the revocation failure", err)
	}
	if vaultclient.ReadTokenFile(p.Home) != "s.root" {
		t.Error("token file changed, want the root token kept after revocation fails")
	}
}

func TestRevokeRoot_ReportsATokenFileWhichCannotBeRemoved(t *testing.T) {
	skipWhenRoot(t)
	var home string
	bastion := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": []string{"root"}}})
		case "/v1/auth/token/revoke-self":
			if err := os.Chmod(home, 0o500); err != nil {
				t.Errorf("chmod home: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(bastion.Close)
	foundation := tokenServer(t, []string{"operator-example-foundation"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	home = p.Home
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	if err == nil || !strings.Contains(err.Error(), "vaultclient: remove") {
		t.Fatalf("RevokeRoot error = %v, want the token-file removal failure", err)
	}
}

func TestRevokeRoot_ReportsAnInitFileFailure(t *testing.T) {
	skipWhenRoot(t)
	var initPath string
	bastion := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": []string{"root"}}})
		case "/v1/auth/token/revoke-self":
			if err := os.Chmod(initPath, 0); err != nil {
				t.Errorf("chmod init file: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(bastion.Close)
	foundation := tokenServer(t, []string{"operator-example-foundation"}, new(atomic.Bool))
	p := newLiveTestPaths(t, bastion.URL)
	writeInitFile(t, p, `{"root_token":"s.root"}`)
	initPath = p.resolveInitFile()
	t.Cleanup(func() { _ = os.Chmod(initPath, 0o600) })
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}

	err := RevokeRoot(context.Background(), p, vaultclient.Config{Address: foundation.URL, Token: "proxy-supplied"}, "operator-example-foundation", discardOut())
	if err == nil || !strings.Contains(err.Error(), "vaultops: read") {
		t.Fatalf("RevokeRoot error = %v, want the init-file read failure", err)
	}
}

func skipWhenRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-bit test when running as root")
	}
}
