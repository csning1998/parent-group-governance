package vaultops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestEnableKVEngine(t *testing.T) {
	t.Run("missing token", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
		err := EnableKVEngine(context.Background(), p, discardOut())
		if err == nil || !strings.Contains(err.Error(), "root token not found") {
			t.Fatalf("EnableKVEngine = %v, want the missing-token error", err)
		}
	})
	t.Run("client failure", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir(), bastionVaultAddr: "https://127.0.0.1:8200"}
		if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
			t.Fatal(err)
		}
		err := EnableKVEngine(context.Background(), p, discardOut())
		if err == nil || strings.Contains(err.Error(), "root token not found") {
			t.Fatalf("EnableKVEngine = %v, want the client failure", err)
		}
	})
	t.Run("already enabled", func(t *testing.T) {
		p := newKVPaths(t, kvMountServer(t, true, true))
		if err := EnableKVEngine(context.Background(), p, discardOut()); err != nil {
			t.Fatalf("EnableKVEngine: %v", err)
		}
	})
	t.Run("enables a missing mount", func(t *testing.T) {
		p := newKVPaths(t, kvMountServer(t, false, false))
		if err := EnableKVEngine(context.Background(), p, discardOut()); err != nil {
			t.Fatalf("EnableKVEngine: %v", err)
		}
	})
	t.Run("mount failure", func(t *testing.T) {
		p := newKVPaths(t, kvMountServer(t, false, true))
		err := EnableKVEngine(context.Background(), p, discardOut())
		if err == nil || !strings.Contains(err.Error(), "enable kv-v2") {
			t.Fatalf("EnableKVEngine = %v, want the mount failure", err)
		}
	})
}

func TestInitReportsAClientFailure(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir(), bastionVaultAddr: "https://127.0.0.1:8200"}
	err := Init(context.Background(), p, discardOut())
	if err == nil || strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Init = %v, want the client failure", err)
	}
}

func TestInitReportsAnEmptyRootToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeInitHandler("", []string{"a2V5MQ=="}))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := newLiveTestPaths(t, srv.URL)

	err := Init(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "empty root_token") {
		t.Fatalf("Init = %v, want the empty root token error", err)
	}
	if _, statErr := os.Stat(p.resolveRootTokenFile()); statErr == nil {
		t.Error("token file exists, want none")
	}
}

func TestInitReportsAnUnsealFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/init", fakeInitHandler("hvs.faketoken", []string{"a2V5MQ=="}))
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true))
	mux.HandleFunc("/v1/sys/unseal", fakeVaultErrorHandler(http.StatusInternalServerError))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := newLiveTestPaths(t, srv.URL)

	err := Init(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "auto-unseal after init") {
		t.Fatalf("Init = %v, want the unseal failure", err)
	}
}

func TestPersistBootstrapRootTokenReportsAMissingInitFile(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir()}
	err := persistBootstrapRootToken(p)
	if err == nil || !strings.Contains(err.Error(), "vaultops: read") {
		t.Fatalf("persistBootstrapRootToken = %v, want a read error", err)
	}
}

func TestPersistInitOutputReportsFilesystemFailures(t *testing.T) {
	t.Run("keys directory parent is a file", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "vault"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := persistInitOutput(Paths{ProjectRoot: root}, &vaultapi.InitResponse{KeysB64: []string{"key"}})
		if err == nil || !strings.Contains(err.Error(), "vaultops: mkdir") {
			t.Fatalf("persistInitOutput = %v, want a mkdir error", err)
		}
	})
	t.Run("init path is a directory", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir()}
		if err := os.MkdirAll(p.resolveInitFile(), 0o700); err != nil {
			t.Fatal(err)
		}
		err := persistInitOutput(p, &vaultapi.InitResponse{KeysB64: []string{"key"}})
		if err == nil || !strings.Contains(err.Error(), "vaultops: write "+p.resolveInitFile()) {
			t.Fatalf("persistInitOutput = %v, want an init-file write error", err)
		}
	})
	t.Run("unseal path is a directory", func(t *testing.T) {
		p := Paths{ProjectRoot: t.TempDir()}
		if err := os.MkdirAll(p.resolveUnsealKeyFile(), 0o700); err != nil {
			t.Fatal(err)
		}
		err := persistInitOutput(p, &vaultapi.InitResponse{KeysB64: []string{"key"}})
		if err == nil || !strings.Contains(err.Error(), "vaultops: write "+p.resolveUnsealKeyFile()) {
			t.Fatalf("persistInitOutput = %v, want an unseal-file write error", err)
		}
	})
}

func TestProbeBastionStateReportsAClientFailure(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), bastionVaultAddr: "https://127.0.0.1:8200"}
	_, _, err := ProbeBastionState(context.Background(), p)
	if err == nil {
		t.Fatal("ProbeBastionState error = nil, want the client failure")
	}
}

func TestUnsealBastionReportsAClientFailure(t *testing.T) {
	p := Paths{ProjectRoot: t.TempDir(), Home: t.TempDir(), bastionVaultAddr: "https://127.0.0.1:8200"}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte("key1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := UnsealBastion(context.Background(), p, discardOut())
	if err == nil || strings.Contains(err.Error(), "unseal keys not found") {
		t.Fatalf("UnsealBastion = %v, want the client failure", err)
	}
}

func TestUnsealBastionReportsADeadline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true))
	mux.HandleFunc("/v1/sys/unseal", fakeUnsealHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := newLiveTestPaths(t, srv.URL)
	if err := os.MkdirAll(p.resolveKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveUnsealKeyFile(), []byte("key1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := UnsealBastion(context.Background(), p, discardOut())
	if err == nil || !strings.Contains(err.Error(), "still reporting sealed") {
		t.Fatalf("UnsealBastion = %v, want the deadline error", err)
	}
}

func TestWaitUntilUnsealedReportsTheDeadline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", fakeSealStatusHandler(true))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := newLiveTestPaths(t, srv.URL)

	err := waitUntilUnsealed(context.Background(), p, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "still reporting sealed") {
		t.Fatalf("waitUntilUnsealed = %v, want the deadline error", err)
	}
}

func kvMountServer(t *testing.T, alreadyEnabled, failMount bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
			if alreadyEnabled {
				_, _ = w.Write([]byte(`{"data":{"secret/":{"type":"kv"}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"cubbyhole/":{"type":"cubbyhole"}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/secret":
			if failMount {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"errors":["boom"]}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newKVPaths(t *testing.T, addr string) Paths {
	t.Helper()
	p := newLiveTestPaths(t, addr)
	if err := vaultclient.PersistTokenFile(p.Home, "s.root"); err != nil {
		t.Fatal(err)
	}
	return p
}
