package vaultops

import (
	"os"
	"strings"
	"testing"
)

func TestTokenSyncNeitherFileExists(t *testing.T) {
	home := t.TempDir()
	p := Paths{ProjectRoot: t.TempDir(), Home: home}
	env := newFakeEnv()

	token, err := SyncVaultToken(p, env)
	if err != nil {
		t.Fatalf("TokenSync: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}
	if len(env.kv) != 0 {
		t.Errorf("env.Set was called: %v", env.kv)
	}
}

func TestTokenSyncFromInitFile(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"s.abc123"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	token, err := SyncVaultToken(p, env)
	if err != nil {
		t.Fatalf("TokenSync: %v", err)
	}
	if token != "s.abc123" {
		t.Errorf("token = %q, want s.abc123", token)
	}
	if env.kv["VAULT_TOKEN"] != "s.abc123" {
		t.Errorf("env.Set(VAULT_TOKEN) = %v, want s.abc123", env.kv)
	}

	data, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil {
		t.Fatalf("read resolveRootTokenFile: %v", err)
	}
	if string(data) != "s.abc123" {
		t.Errorf("resolveRootTokenFile content = %q, want s.abc123", data)
	}
	info, err := os.Stat(p.resolveRootTokenFile())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("resolveRootTokenFile mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestTokenSyncInitFileMalformedJSON(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	token, err := SyncVaultToken(p, env)
	if err == nil {
		t.Fatal("TokenSync: want error, got nil")
	}
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}
	if !strings.Contains(err.Error(), "parse") || !strings.Contains(err.Error(), p.resolveInitFile()) {
		t.Errorf("error = %q, want it to contain %q and %q", err.Error(), "parse", p.resolveInitFile())
	}
	if len(env.kv) != 0 {
		t.Errorf("env.Set was called: %v", env.kv)
	}
}

func TestTokenSyncInitFileEmptyToken(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":""}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	_, err := SyncVaultToken(p, env)
	if err == nil {
		t.Fatal("TokenSync: want error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to extract a valid token") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "failed to extract a valid token")
	}
}

func TestTokenSyncFromRootTokenFileFallbackTrimsAndRewrites(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.WriteFile(p.resolveRootTokenFile(), []byte("  s.xyz  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	token, err := SyncVaultToken(p, env)
	if err != nil {
		t.Fatalf("TokenSync: %v", err)
	}
	if token != "s.xyz" {
		t.Errorf("token = %q, want s.xyz", token)
	}
	if env.kv["VAULT_TOKEN"] != "s.xyz" {
		t.Errorf("env.Set(VAULT_TOKEN) = %v, want s.xyz", env.kv)
	}
	data, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "s.xyz" {
		t.Errorf("resolveRootTokenFile content = %q, want %q", data, "s.xyz")
	}
}

func TestTokenSyncInitFileTakesPriorityOverRootTokenFile(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"s.from-init"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveRootTokenFile(), []byte("s.from-fallback"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	token, err := SyncVaultToken(p, env)
	if err != nil {
		t.Fatalf("TokenSync: %v", err)
	}
	if token != "s.from-init" {
		t.Errorf("token = %q, want s.from-init (resolveInitFile priority)", token)
	}
}

func TestTokenSyncWritesToFreshHomeWithoutMkdirAll(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"s.fresh"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	if _, err := SyncVaultToken(p, env); err != nil {
		t.Fatalf("SyncVaultToken: %v", err)
	}
	if _, err := os.Stat(p.resolveRootTokenFile()); err != nil {
		t.Errorf("resolveRootTokenFile was not created: %v", err)
	}
}
