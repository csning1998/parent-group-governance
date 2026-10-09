package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

func TestBootstrapEnvReportsASaveFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-bit test when running as root")
	}
	root := t.TempDir()
	content := KeyProjectRoot + "=\"/tmp\"\n" + KeySonarQubeDBPassword + "=\"already-set\"\n"
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	_, err := BootstrapEnv(root, ui.New(io.Discard, io.Discard))
	if err == nil || !strings.Contains(err.Error(), "config: write") {
		t.Fatalf("BootstrapEnv = %v, want a write error", err)
	}
}

func TestBootstrapEnvReportsAnUnreadableEnvFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".env"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := BootstrapEnv(root, ui.New(io.Discard, io.Discard))
	if err == nil || !strings.Contains(err.Error(), "config:") {
		t.Fatalf("BootstrapEnv = %v, want a config read error", err)
	}
}
