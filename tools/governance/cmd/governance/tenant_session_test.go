package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

// writeFakeShell writes an executable script which stands in for $SHELL.
func writeFakeShell(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-shell")
	err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700)
	if err != nil {
		t.Fatalf("write fake shell: %v", err)
	}
	return path
}

func TestRunInteractiveShell_PassesTheSessionEnvironment(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "env.txt")
	t.Setenv("SHELL", writeFakeShell(t, `env > "$DUMP"`))

	env := []string{"DUMP=" + dump, "VAULT_TOKEN=s.tenant", "PATH=" + os.Getenv("PATH")}
	if err := runInteractiveShell(context.Background(), env); err != nil {
		t.Fatalf("runInteractiveShell: %v", err)
	}
	got, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("read env dump: %v", err)
	}
	if !strings.Contains(string(got), "VAULT_TOKEN=s.tenant\n") {
		t.Errorf("shell env = %q, want VAULT_TOKEN=s.tenant", got)
	}
}

func TestRunInteractiveShell_ReturnsTheShellExitStatus(t *testing.T) {
	t.Setenv("SHELL", writeFakeShell(t, "exit 3"))

	err := runInteractiveShell(context.Background(), []string{"PATH=" + os.Getenv("PATH")})
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Errorf("runInteractiveShell error = %v, want exit status 3", err)
	}
}

func TestRunInteractiveShell_FallsBackToBinSh(t *testing.T) {
	t.Setenv("SHELL", "")
	if got := resolveSessionShell(); got != "/bin/sh" {
		t.Errorf("resolveSessionShell = %q, want /bin/sh", got)
	}
}

func TestNewVaultCmd_TenantSessionTakesOneTenant(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	cmd, _, err := a.newVaultCmd().Find([]string{"tenant-session"})
	if err != nil || cmd.Name() != "tenant-session" {
		t.Fatalf("Find(tenant-session) = %q, %v, want the tenant-session command", cmd.Name(), err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "no tenant", args: nil, wantErr: true},
		{name: "one tenant", args: []string{"meta-platform"}, wantErr: false},
		{name: "two tenants", args: []string{"meta-platform", "other"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cmd.Args(cmd, tt.args); (err != nil) != tt.wantErr {
				t.Errorf("Args(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestRunTenantSession_RequiresTheOperatorToken(t *testing.T) {
	a := &app{root: t.TempDir(), home: t.TempDir(), out: ui.New(io.Discard, io.Discard)}

	err := a.runTenantSession(context.Background(), "meta-platform")
	if err == nil || !strings.Contains(err.Error(), "root token not found") {
		t.Errorf("runTenantSession error = %v, want the missing root token", err)
	}
}
