package vaultops

import (
	"os"
	"strings"
	"sync"
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
	if env.get("VAULT_TOKEN") != "s.abc123" {
		t.Errorf("env.Set(VAULT_TOKEN) = %q, want s.abc123", env.get("VAULT_TOKEN"))
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

func TestTokenSyncWhitespaceRootTokenFileErrors(t *testing.T) {
	home := t.TempDir()
	p := Paths{ProjectRoot: t.TempDir(), Home: home}
	if err := os.WriteFile(p.resolveRootTokenFile(), []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncVaultToken(p, newFakeEnv()); err == nil {
		t.Fatal("SyncVaultToken on whitespace-only token file: want error, got nil")
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
	if !strings.Contains(err.Error(), "failed to extract a valid token") && !strings.Contains(err.Error(), "contains empty root_token") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "failed to extract a valid token")
	}
}

func TestTokenSyncInitFileEmptyTokenWithExistingRootTokenFails(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":""}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveRootTokenFile(), []byte("s.stale-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()

	_, err := SyncVaultToken(p, env)
	if err == nil {
		t.Fatal("TokenSync with empty init root_token and existing token: want error, got nil")
	}
	if !strings.Contains(err.Error(), "empty root_token") && !strings.Contains(err.Error(), "failed to extract a valid token") {
		t.Errorf("error = %q, want empty root_token error", err.Error())
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
	if env.get("VAULT_TOKEN") != "s.xyz" {
		t.Errorf("env.Set(VAULT_TOKEN) = %q, want s.xyz", env.get("VAULT_TOKEN"))
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

func TestTokenSyncInitFileWriteFailsOnReadOnlyHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping read-only directory test when running as root")
	}
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"s.abc123"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })

	if _, err := SyncVaultToken(p, newFakeEnv()); err == nil {
		t.Fatal("SyncVaultToken on read-only home: want error, got nil")
	}
}

func TestTokenSyncConcurrentWriters(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	p := Paths{ProjectRoot: root, Home: home}
	if err := os.MkdirAll(p.resolveKeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.resolveInitFile(), []byte(`{"root_token":"s.race"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()
	const writers = 32
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			_, err := SyncVaultToken(p, env)
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("SyncVaultToken concurrent writer: %v", err)
		}
	}
	if env.get("VAULT_TOKEN") != "s.race" {
		t.Errorf("env VAULT_TOKEN = %q, want s.race", env.get("VAULT_TOKEN"))
	}
	data, err := os.ReadFile(p.resolveRootTokenFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "s.race" {
		t.Errorf("token file = %q, want s.race", data)
	}
}
