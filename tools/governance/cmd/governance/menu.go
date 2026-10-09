package main

import (
	"context"
	"strings"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// msgInvalidOption is the single rejection message every prompt in this menu reports.
const msgInvalidOption = "Invalid option"

type menuOption struct {
	label string
	run   func(ctx context.Context) error
}

// buildMenuOptions returns the interactive menu entries, ending with Quit.
func (a *app) buildMenuOptions() []menuOption {
	options := []menuOption{
		{"[Host] Apply All Workstation Prerequisites", func(ctx context.Context) error { return a.runHostAll(ctx) }},
		{"[Host] Verify Host IaC Tools", func(ctx context.Context) error { return a.verifyEnvironment() }},
		{"[Host] Apply Workstation SELinux Policy and File Contexts", func(ctx context.Context) error { return a.runHostSELinuxPlaybook(ctx) }},
		{"[Host] Apply Workstation Libvirt Network and Bastion Vault Prerequisites", func(ctx context.Context) error { return a.runHostLibvirtPlaybook(ctx) }},
		{"[Host] Apply Workstation Vault Proxies", func(ctx context.Context) error { return a.runHostVaultProxyPlaybook(ctx) }},
		{"[Vault] Set up TLS for Bastion Vault", func(ctx context.Context) error { return a.generateVaultTLS(ctx) }},
		{"[Vault] Initialize Bastion Vault", func(ctx context.Context) error { return a.initVault(ctx) }},
		{"[Vault] Enable KV-v2 Engine", func(ctx context.Context) error { return a.enableVaultKV(ctx) }},
		{"[Vault] Unseal Bastion Vault", func(ctx context.Context) error { return a.unsealVault(ctx) }},
		{"[Vault] Revoke Root Token After Bootstrap", func(ctx context.Context) error { return a.revokeRoot(ctx) }},
		{"[Vault] Generate Root Token for Break-Glass", func(ctx context.Context) error { return a.generateRoot(ctx) }},
	}
	if len(a.credentials) > 0 {
		options = append(options,
			menuOption{"[Credentials] Rotate Service Admin Passwords", func(ctx context.Context) error { return a.runRotateCredentialMenu(ctx) }},
			menuOption{"[Credentials] Reconcile Service Admin Passwords with the Live Service", func(ctx context.Context) error { return a.runReconcileCredentialMenu(ctx) }},
		)
	}
	options = append(options,
		menuOption{"[Terraform] Audit State Secrets", func(ctx context.Context) error { return a.runStateAuditMenu(ctx) }},
		menuOption{"Quit", nil},
	)
	return options
}

func (a *app) printVaultStatusBanner(ctx context.Context) {
	if len(a.credentials) > 0 {
		keys := make([]string, len(a.credentials))
		for i, cred := range a.credentials {
			keys[i] = cred.Key
		}
		a.out.Print(ui.Info, "Declared credentials: "+strings.Join(keys, ", "))
		a.out.PrintDivider("")
	}

	bastion := vaultops.InspectBastionStatus(ctx, a.newVaultPaths())
	switch {
	case !bastion.Reachable:
		a.out.Print(ui.Error, "Bastion Vault: Stopped")
	case !bastion.Initialized:
		a.out.Print(ui.Warn, "Bastion Vault: Running (Not Initialized)")
	case bastion.Sealed:
		a.out.Print(ui.Warn, "Bastion Vault: Running (Sealed)")
	default:
		a.out.Print(ui.OK, "Bastion Vault: Running (Unsealed)")
		if vaultclient.ReadTokenFile(a.home) != "" {
			a.out.Print(ui.Warn, "Root token present in ~/.vault-token. Run [Vault] Revoke Root Token After Bootstrap once bootstrap ends.")
		}
	}

	a.out.PrintDivider("")
}

func (a *app) runMenu(ctx context.Context) error {
	options := a.buildMenuOptions()

	a.out.Print(ui.Info, "======= Governance executor =======")
	a.out.PrintDivider("")

	env, err := config.BootstrapEnv(a.root, a.out)
	if err != nil {
		return err
	}
	a.env = env
	a.printVaultStatusBanner(ctx)

	labels := make([]string, len(options))
	for i, opt := range options {
		labels[i] = opt.label
	}

	for {
		index, ok := a.out.PromptSelect(a.in, "Please select an action:", labels)
		if !ok {
			a.out.Print(ui.Error, msgInvalidOption)
			continue
		}
		chosen := options[index]
		if chosen.run == nil {
			a.out.Print(ui.Info, "Exiting.")
			return nil
		}
		return chosen.run(ctx)
	}
}

// runReconcileCredentialMenu prompts for one or more credentials that already have a value in
// Vault and reconciles each chosen credential in turn, asking for its current live password.
// A failure on one credential does not stop the rest.
func (a *app) runReconcileCredentialMenu(ctx context.Context) error {
	client, err := a.newRotationClient()
	if err != nil {
		return err
	}

	var keys []string
	for _, cred := range a.credentials {
		if secretrotate.Exists(ctx, client, cred.Spec) {
			keys = append(keys, cred.Key)
		}
	}
	if len(keys) == 0 {
		a.out.Print(ui.Warn, "No credentials have a value in Vault yet; nothing to reconcile.")
		return nil
	}

	a.out.PrintDivider("")
	a.out.Print(ui.Info, "Credentials with a value in Vault:")
	indices, ok := a.out.PromptMultiSelect(a.in, "Select credentials to reconcile (e.g. 1,2,3 or 1 2 3):", keys)
	if !ok {
		a.out.Print(ui.Error, msgInvalidOption)
		return nil
	}

	var lastErr error
	for _, index := range indices {
		if err := a.reconcileCredential(ctx, keys[index]); err != nil {
			a.out.Print(ui.Error, keys[index]+": "+err.Error())
			lastErr = err
		}
	}
	return lastErr
}

// runRotateCredentialMenu prompts for one or more of the declared credential keys and rotates
// each chosen credential in turn. A failure on one credential does not stop the rest. Each
// listed key is marked with whether Vault already holds a value for that credential.
func (a *app) runRotateCredentialMenu(ctx context.Context) error {
	keys := make([]string, len(a.credentials))
	labels := make([]string, len(a.credentials))

	client, err := a.newRotationClient()
	for i, cred := range a.credentials {
		keys[i] = cred.Key
		status := "status unknown"
		if err == nil && secretrotate.Exists(ctx, client, cred.Spec) {
			status = "created"
		} else if err == nil {
			status = "not created"
		}
		labels[i] = cred.Key + " [" + status + "]"
	}

	a.out.PrintDivider("")
	a.out.Print(ui.Info, "Current credential status:")
	indices, ok := a.out.PromptMultiSelect(a.in, "Select credentials to rotate (e.g. 1,2,3 or 1 2 3):", labels)
	if !ok {
		a.out.Print(ui.Error, msgInvalidOption)
		return nil
	}

	var lastErr error
	for _, index := range indices {
		if err := a.rotateCredential(ctx, keys[index]); err != nil {
			a.out.Print(ui.Error, keys[index]+": "+err.Error())
			lastErr = err
		}
	}
	return lastErr
}
