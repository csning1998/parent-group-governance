package vaultops

import (
	"context"
	"os"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

func TestInitRefusesReinitWhenInitFileExists(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Init(context.Background(), p, discardOut(), newFakeEnv())
	if err == nil {
		t.Fatal("Init: want error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists, refusing to re-init") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "already exists, refusing to re-init")
	}
}

func TestPersistInitOutputRestrictsPermissions(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, Home: t.TempDir()}
	resp := &vaultapi.InitResponse{RootToken: "s.root", KeysB64: []string{"key1", "key2"}}

	if err := persistInitOutput(p, resp); err != nil {
		t.Fatalf("persistInitOutput: %v", err)
	}

	assertMode(t, p.resolveKeysDir(), 0o700)
	assertMode(t, p.resolveInitFile(), 0o600)
	assertMode(t, p.resolveUnsealKeyFile(), 0o600)
}

func TestPersistInitOutputRejectsEmptyUnsealKeys(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, Home: t.TempDir()}
	resp := &vaultapi.InitResponse{RootToken: "s.root"}

	err := persistInitOutput(p, resp)
	if err == nil || !strings.Contains(err.Error(), "no unseal keys in init response") {
		t.Fatalf("persistInitOutput with no keys = %v, want error containing %q", err, "no unseal keys in init response")
	}
}

func TestUnsealBastionFailsWhenUnsealKeyFileMissing(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}

	err := UnsealBastion(context.Background(), p, discardOut(), newFakeEnv())
	if err == nil {
		t.Fatal("UnsealBastion: want error, got nil")
	}
	if !strings.Contains(err.Error(), "unseal keys not found at") ||
		!strings.Contains(err.Error(), p.resolveUnsealKeyFile()) ||
		!strings.Contains(err.Error(), "run Init first") {
		t.Errorf("error = %q, want it to contain resolveUnsealKeyFile path, %q and %q",
			err.Error(), "unseal keys not found at", "run Init first")
	}
}

func TestNewAuthenticatedBastionClientRootTokenFileNotFound(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}

	_, err := NewAuthenticatedBastionClient(p)
	if err == nil {
		t.Fatal("NewAuthenticatedBastionClient: want error, got nil")
	}
	if !strings.Contains(err.Error(), "root token not found at") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "root token not found at")
	}
}
