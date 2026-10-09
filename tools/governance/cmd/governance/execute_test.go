package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
)

const topologyMinimum = `bastion_vault:
  loopback_address: "127.0.0.1"
  publish_address: "172.16.0.1"
  api_port: 8200
`

func TestExecuteQuitsTheRootMenu(t *testing.T) {
	writeProject(t, topologyMinimum)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("13\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = original
		_ = reader.Close()
	})

	if code := execute(nil); code != 0 {
		t.Errorf("execute = %d, want 0 after Quit", code)
	}
}

func TestExecuteRejectsACredentialTheTopologyCannotBuild(t *testing.T) {
	writeProject(t, topologyMinimum+`service_admin_passwords:
  - key: broken-password
    vault_kv_mount: secret
    vault_kv_path: app/infra
    length: 16
    service:
      mechanism: unknown
`)
	if code := execute([]string{"--help"}); code != 1 {
		t.Errorf("execute = %d, want 1", code)
	}
}

func TestExecuteReportsAMissingWorkingDirectory(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}

	if code := execute(nil); code != 1 {
		t.Errorf("execute = %d, want 1", code)
	}
}

func TestExecuteReportsAProjectWithoutGit(t *testing.T) {
	t.Chdir(t.TempDir())
	if code := execute(nil); code != 1 {
		t.Errorf("execute = %d, want 1", code)
	}
}

func TestExecuteReportsAVaultCommandFailure(t *testing.T) {
	writeProject(t, topologyMinimum)
	if code := execute([]string{"vault", "unseal"}); code != 1 {
		t.Errorf("execute(vault unseal) = %d, want 1", code)
	}
}

func TestExecuteReportsAnEnvSaveFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-bit test when running as root")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, topology.FileName), []byte(topologyMinimum), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	t.Chdir(root)

	if code := execute([]string{"env", "verify"}); code != 1 {
		t.Errorf("execute = %d, want 1", code)
	}
}

func TestResolveProjectRootReportsADirectoryWithoutGit(t *testing.T) {
	_, err := resolveProjectRoot(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no .git entry found") {
		t.Fatalf("resolveProjectRoot error = %v, want no .git entry", err)
	}
}

func TestResolveProjectRootReportsAStatFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not stop the superuser")
	}
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	_, err := resolveProjectRoot(child)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("resolveProjectRoot error = %v, want the stat failure", err)
	}
}

func writeProject(t *testing.T, topologyYAML string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, topology.FileName), []byte(topologyYAML), 0o644); err != nil {
		t.Fatalf("write topology: %v", err)
	}
	t.Chdir(root)
}
