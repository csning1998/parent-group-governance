package vaultclient_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestPersistTokenFileConcurrentWriters(t *testing.T) {
	home := t.TempDir()
	const writers = 32
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			errCh <- vaultclient.PersistTokenFile(home, "s.shared-token")
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("PersistTokenFile concurrent writer: %v", err)
		}
	}
	if got := vaultclient.ReadTokenFile(home); got != "s.shared-token" {
		t.Errorf("token file after concurrent writers = %q, want s.shared-token", got)
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

func TestRemoveTokenFile(t *testing.T) {
	home := t.TempDir()
	if err := vaultclient.RemoveTokenFile(home); err != nil {
		t.Fatalf("RemoveTokenFile on an absent file: %v", err)
	}
	if err := vaultclient.PersistTokenFile(home, "s.removed"); err != nil {
		t.Fatalf("PersistTokenFile: %v", err)
	}
	if err := vaultclient.RemoveTokenFile(home); err != nil {
		t.Fatalf("RemoveTokenFile: %v", err)
	}
	if got := vaultclient.ReadTokenFile(home); got != "" {
		t.Errorf("ReadTokenFile after RemoveTokenFile = %q, want empty", got)
	}
}

func TestRemoveTokenFileReportsAPathWhichCannotBeRemoved(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "not-a-directory")
	if err := os.WriteFile(home, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := vaultclient.RemoveTokenFile(home)
	if err == nil || !strings.Contains(err.Error(), "vaultclient: remove") {
		t.Fatalf("RemoveTokenFile = %v, want a remove error", err)
	}
}
