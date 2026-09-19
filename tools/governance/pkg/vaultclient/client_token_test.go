package vaultclient_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestReadTokenFile(t *testing.T) {
	home := t.TempDir()
	if got := vaultclient.ReadTokenFile(home); got != "" {
		t.Errorf("ReadTokenFile on nonexistent file = %q, want empty", got)
	}

	tokenPath := filepath.Join(home, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("  s.my-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := vaultclient.ReadTokenFile(home); got != "s.my-token" {
		t.Errorf("ReadTokenFile = %q, want s.my-token", got)
	}
}

func TestSyncSessionToken(t *testing.T) {
	home := t.TempDir()
	env := &fakeEnv{}

	token, err := vaultclient.SyncSessionToken(home, env)
	if err != nil {
		t.Fatalf("SyncSessionToken on missing token file returned error: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}

	tokenPath := filepath.Join(home, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("  s.synced-token  \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err = vaultclient.SyncSessionToken(home, env)
	if err != nil {
		t.Fatalf("SyncSessionToken: %v", err)
	}
	if token != "s.synced-token" {
		t.Errorf("token = %q, want s.synced-token", token)
	}
	if env.get("VAULT_TOKEN") != "s.synced-token" {
		t.Errorf("env VAULT_TOKEN = %q, want s.synced-token", env.get("VAULT_TOKEN"))
	}

	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file permissions = %v, want 0600", info.Mode().Perm())
	}

	emptyHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(emptyHome, ".vault-token"), []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vaultclient.SyncSessionToken(emptyHome, env); err == nil {
		t.Error("SyncSessionToken on whitespace-only token file: want error, got nil")
	}
}

func TestSyncSessionTokenNilEnvStillRewritesFile(t *testing.T) {
	home := t.TempDir()
	tokenPath := filepath.Join(home, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("  s.nil-env  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := vaultclient.SyncSessionToken(home, nil)
	if err != nil {
		t.Fatalf("SyncSessionToken(nil env): %v", err)
	}
	if token != "s.nil-env" {
		t.Errorf("token = %q, want s.nil-env", token)
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "s.nil-env" {
		t.Errorf("token file = %q, want s.nil-env", data)
	}
}

func TestSyncSessionTokenWriteFailsOnReadOnlyHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping read-only directory test when running as root")
	}
	home := t.TempDir()
	tokenPath := filepath.Join(home, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("s.locked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })

	_, err := vaultclient.SyncSessionToken(home, &fakeEnv{})
	if err == nil {
		t.Fatal("SyncSessionToken on read-only home: want error, got nil")
	}
}

func TestPersistTokenFileAndConcurrentSyncSessionToken(t *testing.T) {
	home := t.TempDir()
	if err := vaultclient.PersistTokenFile(home, "s.shared-token"); err != nil {
		t.Fatalf("PersistTokenFile: %v", err)
	}
	if got := vaultclient.ReadTokenFile(home); got != "s.shared-token" {
		t.Fatalf("ReadTokenFile after PersistTokenFile = %q, want s.shared-token", got)
	}

	env := &fakeEnv{}
	const writers = 32
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			_, err := vaultclient.SyncSessionToken(home, env)
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("SyncSessionToken concurrent writer: %v", err)
		}
	}
	if got := vaultclient.ReadTokenFile(home); got != "s.shared-token" {
		t.Errorf("token file after concurrent writers = %q, want s.shared-token", got)
	}
	if env.get("VAULT_TOKEN") != "s.shared-token" {
		t.Errorf("env VAULT_TOKEN = %q, want s.shared-token", env.get("VAULT_TOKEN"))
	}
}

func TestPersistTokenFileFailsOnReadOnlyHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping read-only directory test when running as root")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	if err := vaultclient.PersistTokenFile(home, "s.cannot-write"); err == nil {
		t.Fatal("PersistTokenFile on read-only home: want error, got nil")
	}
}
