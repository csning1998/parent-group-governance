package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/apenella/go-ansible/v2/pkg/playbook"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ansibleops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

func (a *app) generateVaultTLS(ctx context.Context) error {
	if !a.out.PromptConfirm(a.in, "Type 'Y' or 'y' to confirm execution: ") {
		a.out.Print(ui.Info, "Cancelled.")
		return nil
	}
	return vaultops.GenerateTLS(ctx, a.newVaultPaths(), a.out)
}

func (a *app) initVault(ctx context.Context) error {
	if err := vaultops.Init(ctx, a.newVaultPaths(), a.out, a.env); err != nil {
		return err
	}
	return a.env.Save()
}

func (a *app) unsealVault(ctx context.Context) error {
	if err := vaultops.UnsealBastion(ctx, a.newVaultPaths(), a.out, a.env); err != nil {
		return err
	}
	return a.env.Save()
}

func (a *app) enableVaultKV(ctx context.Context) error {
	return vaultops.EnableKVEngine(ctx, a.newVaultPaths(), a.out)
}

// rotateCredential runs the a.credentials entry identified by key against Bastion Vault.
func (a *app) rotateCredential(ctx context.Context, key string) error {
	cred, ok := credentials.Lookup(a.credentials, key)
	if !ok {
		return fmt.Errorf("no registered credential %q", key)
	}
	client, err := vaultops.NewAuthenticatedBastionClient(a.newVaultPaths())
	if err != nil {
		return err
	}
	log := func(msg string) { a.out.Print(ui.OK, msg) }
	_, err = secretrotate.Rotate(ctx, client, cred.Spec, log)
	return err
}

// reconcileCredential pushes the value Vault already holds for key out to the live service,
// prompting for the current live credential needed to authenticate the call. Leaving the
// prompt blank lets Reconcile guess instead of failing outright.
func (a *app) reconcileCredential(ctx context.Context, key string) error {
	cred, ok := credentials.Lookup(a.credentials, key)
	if !ok {
		return fmt.Errorf("no registered credential %q", key)
	}
	client, err := vaultops.NewAuthenticatedBastionClient(a.newVaultPaths())
	if err != nil {
		return err
	}
	previous, err := a.out.PromptSecret(a.in, int(os.Stdin.Fd()), "Current live password for "+key+" (leave blank to let governance guess): ")
	if err != nil {
		return fmt.Errorf("read live password for %s: %w", key, err)
	}
	if err := secretrotate.Reconcile(ctx, client, cred.Spec, previous); err != nil {
		return err
	}
	a.out.Print(ui.OK, key+": reconciled with the live service.")
	return nil
}

func (a *app) verifyEnvironment() error {
	var missing []string
	group := ""
	for _, c := range config.VerifyHostEnvironment() {
		if c.Group != group {
			a.out.Print(ui.Step, "Checking "+c.Group+"...")
			group = c.Group
		}
		if c.Installed {
			a.out.Print(ui.Info, c.Name+": Installed")
		} else {
			a.out.Print(ui.Warn, c.Name+": Missing")
			missing = append(missing, c.Name)
		}
	}
	a.out.PrintDivider("")
	if len(missing) > 0 {
		return fmt.Errorf("verification failed: missing required tools: %s", strings.Join(missing, ", "))
	}
	a.out.Print(ui.OK, "Verification successful: required tools are installed.")
	return nil
}

func (a *app) runHostSELinuxPlaybook(ctx context.Context) error {
	becomePass, err := a.out.PromptSecret(a.in, int(os.Stdin.Fd()), "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		return fmt.Errorf("read ANSIBLE_BECOME_PASS: %w", err)
	}
	if becomePass == "" {
		a.out.Print(ui.Info, "Cancelled.")
		return nil
	}

	ansibleDir := a.resolveHostAnsibleDir()
	opts := &playbook.AnsiblePlaybookOptions{
		Inventory: "inventory/localhost.yaml",
		ExtraVars: map[string]interface{}{
			"workstation_selinux_home": a.home,
		},
	}
	extraEnv := map[string]string{
		"ANSIBLE_BECOME_PASS": becomePass,
	}
	if err := ansibleops.RunPlaybook(ctx, ansibleDir, ansibleDir, "playbooks/workstation_selinux.yaml", opts, extraEnv); err != nil {
		return fmt.Errorf("ansible-playbook: %w", err)
	}
	a.out.Print(ui.OK, "Workstation SELinux policy and file contexts applied.")
	return nil
}
