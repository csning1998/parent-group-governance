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
	if err := os.MkdirAll(p.KeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.InitFile(), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	op := newTestOperator(t, p, "http://127.0.0.1:8200")
	err := op.Init(context.Background())
	if err == nil {
		t.Fatal("Init: want error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists, refusing to re-init") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "already exists, refusing to re-init")
	}
}

func TestPersistInitOutputRejectsEmptyUnsealKeys(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, Home: t.TempDir()}
	resp := &vaultapi.InitResponse{RootToken: "s.root"}
	op := &Operator{paths: p}

	err := op.persistInitOutput(resp)
	if err == nil || !strings.Contains(err.Error(), "the init response does not contain unseal keys") {
		t.Fatalf("persistInitOutput without unseal keys = %v, want error containing %q", err, "the init response does not contain unseal keys")
	}
}

func TestPersistInitOutputRestrictsPermissions(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, Home: t.TempDir()}
	resp := &vaultapi.InitResponse{RootToken: "s.root", KeysB64: []string{"key1", "key2"}}
	op := &Operator{paths: p}

	if err := op.persistInitOutput(resp); err != nil {
		t.Fatalf("persistInitOutput: %v", err)
	}

	assertMode(t, p.KeysDir(), 0o700)
	assertMode(t, p.InitFile(), 0o600)
	assertMode(t, p.UnsealKeyFile(), 0o600)
}

func TestUnsealFailsWhenUnsealKeyFileMissing(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}

	op := newTestOperator(t, p, "http://127.0.0.1:8200")
	err := op.Unseal(context.Background())
	if err == nil {
		t.Fatal("Unseal: want error, got nil")
	}
	if !strings.Contains(err.Error(), "unseal keys not found at") ||
		!strings.Contains(err.Error(), p.UnsealKeyFile()) ||
		!strings.Contains(err.Error(), "run Init first") {
		t.Errorf("error = %q, want it to contain UnsealKeyFile path, %q and %q",
			err.Error(), "unseal keys not found at", "run Init first")
	}
}
