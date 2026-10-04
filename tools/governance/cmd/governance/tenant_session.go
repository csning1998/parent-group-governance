package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
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
	return vaultops.RunTenantSession(ctx, p, admin, req, a.out, vaultops.TenantShell{Base: os.Environ(), Run: a.runSessionShell})
}

// runTenantSessionMenu lists the tenants of the Bastion Vault and opens a session for the chosen tenant.
func (a *app) runTenantSessionMenu(ctx context.Context) error {
	admin, err := vaultops.NewAuthenticatedBastionClient(a.newVaultPaths())
	if err != nil {
		return err
	}
	tenants, err := vaultops.ListTenantCodes(ctx, admin, "")
	if err != nil {
		return err
	}
	if len(tenants) == 0 {
		a.out.Print(ui.Warn, "No tenant Terraform operator role exists on the Bastion Vault.")
		return nil
	}
	index, ok := a.out.PromptSelect(a.in, "Select the tenant whose operator session to open:", tenants)
	if !ok {
		a.out.Print(ui.Error, msgInvalidOption)
		return nil
	}
	return a.runTenantSession(ctx, tenants[index])
}

// runSessionShell runs the session shell and reports the exit status of the shell as information.
func (a *app) runSessionShell(ctx context.Context, env []string) error {
	err := runInteractiveShell(ctx, env)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		a.out.Print(ui.Info, fmt.Sprintf("Session shell exited with status %d.", exitErr.ExitCode()))
		return nil
	}
	return err
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
