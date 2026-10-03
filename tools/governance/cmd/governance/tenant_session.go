package main

import (
	"cmp"
	"context"
	"os"
	"os/exec"
	"os/signal"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
)

// runTenantSession opens a Bastion Vault session for tenant and hands the operator a shell which holds the tenant token.
func (a *app) runTenantSession(ctx context.Context, tenant string) error {
	p := a.newVaultPaths()
	admin, err := vaultops.NewAuthenticatedBastionClient(p)
	if err != nil {
		return err
	}
	req := vaultops.TenantSessionRequest{Tenant: tenant}
	return vaultops.RunTenantSession(ctx, p, admin, req, a.out, vaultops.TenantShell{Base: os.Environ(), Run: runInteractiveShell})
}

// resolveSessionShell returns $SHELL, or /bin/sh when $SHELL is empty.
func resolveSessionShell() string {
	return cmp.Or(os.Getenv("SHELL"), "/bin/sh")
}

// runInteractiveShell runs the session shell with env and returns after the shell exits.
func runInteractiveShell(ctx context.Context, env []string) error {
	// A caught SIGINT keeps governance alive for the revoke, while exec resets the disposition inside the shell.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)

	cmd := exec.CommandContext(ctx, resolveSessionShell())
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
