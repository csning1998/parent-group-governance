package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/apenella/go-ansible/v2/pkg/playbook"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ansibleops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
)

// hostPlaybook is one workstation playbook with the extra vars injected by the CLI.
type hostPlaybook struct {
	file      string
	extraVars map[string]any
	doneMsg   string
}

// hostStep executes one workstation bootstrap action with the become password of the run.
type hostStep func(ctx context.Context, becomePass string) error

func (a *app) playbookStep(build func() (hostPlaybook, error)) hostStep {
	return func(ctx context.Context, becomePass string) error {
		pb, err := build()
		if err != nil {
			return err
		}
		return a.executePlaybook(ctx, pb, becomePass)
	}
}

// runHostSteps prompts once for the privilege escalation password, cancelling on a blank answer,
// and executes each step in order.
func (a *app) runHostSteps(ctx context.Context, steps ...hostStep) error {
	becomePass, err := a.out.PromptSecret(a.in, int(os.Stdin.Fd()), "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		return fmt.Errorf("read ANSIBLE_BECOME_PASS: %w", err)
	}
	if becomePass == "" {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	for _, step := range steps {
		if err := step(ctx, becomePass); err != nil {
			return err
		}
	}
	return nil
}

// runHostAll applies workstation prerequisites in bootstrap order: SELinux, local CA generation,
// libvirt configuration, and Vault Proxy deployment. The operator enters privilege escalation credentials once.
func (a *app) runHostAll(ctx context.Context) error {
	return a.runHostSteps(
		ctx,
		a.playbookStep(a.buildSELinuxPlaybook),
		func(ctx context.Context, _ string) error { return a.ensureLocalCA(ctx) },
		a.playbookStep(a.buildLibvirtPlaybook),
		a.playbookStep(func() (hostPlaybook, error) { return a.buildVaultProxyPlaybook(ctx) }),
	)
}

func (a *app) runHostSELinuxPlaybook(ctx context.Context) error {
	return a.runHostSteps(ctx, a.playbookStep(a.buildSELinuxPlaybook))
}

func (a *app) runHostLibvirtPlaybook(ctx context.Context) error {
	return a.runHostSteps(ctx, a.playbookStep(a.buildLibvirtPlaybook))
}

func (a *app) runHostVaultProxyPlaybook(ctx context.Context) error {
	return a.runHostSteps(ctx, a.playbookStep(func() (hostPlaybook, error) { return a.buildVaultProxyPlaybook(ctx) }))
}

func (a *app) runHostTelemetryPlaybook(ctx context.Context) error {
	return a.runHostSteps(ctx, a.playbookStep(func() (hostPlaybook, error) { return a.buildHostTelemetryPlaybook(ctx) }))
}

// runHostVaultAuditPlaybook omits privilege escalation because the audit systemd units are managed under the operator user session.
func (a *app) runHostVaultAuditPlaybook(ctx context.Context) error {
	return a.executePlaybook(ctx, a.buildVaultAuditPlaybook(), "")
}

// executePlaybook runs one workstation playbook with injected become password.
func (a *app) executePlaybook(ctx context.Context, pb hostPlaybook, becomePass string) error {
	opts := &playbook.AnsiblePlaybookOptions{Inventory: "inventory/localhost.yaml", ExtraVars: pb.extraVars}
	extraEnv := map[string]string{"ANSIBLE_BECOME_PASS": becomePass}
	if err := ansibleops.RunPlaybook(ctx, a.ansibleDir, a.ansibleDir, pb.file, opts, extraEnv); err != nil {
		return fmt.Errorf("ansible-playbook %s: %w", pb.file, err)
	}
	a.out.Print(ui.OK, pb.doneMsg)
	return nil
}

func (a *app) buildSELinuxPlaybook() (hostPlaybook, error) {
	return hostPlaybook{
		file:      "playbooks/workstation_selinux.yaml",
		extraVars: map[string]any{"workstation_selinux_home": a.home, "workstation_selinux_repository": a.root},
		doneMsg:   "Workstation SELinux policy and file contexts applied.",
	}, nil
}

func (a *app) buildLibvirtPlaybook() (hostPlaybook, error) {
	facts, err := config.DetectHostFacts()
	if err != nil {
		return hostPlaybook{}, err
	}
	return hostPlaybook{
		file: "playbooks/workstation_libvirt.yaml",
		extraVars: map[string]any{
			"workstation_libvirt_operator_user":     facts.CurrentUname,
			"workstation_libvirt_vault_config_path": filepath.Join(a.root, "vault", "vault.hcl"),
		},
		doneMsg: "Workstation libvirt prerequisites for Bastion Vault applied.",
	}, nil
}

// buildVaultProxyPlaybook resolves the GitLab origin endpoints and injects the endpoints for rendering into vault-proxy-env.
func (a *app) buildVaultProxyPlaybook(ctx context.Context) (hostPlaybook, error) {
	facts, err := config.DetectHostFacts()
	if err != nil {
		return hostPlaybook{}, err
	}
	origin, err := a.resolveOrigin(ctx)
	if err != nil {
		return hostPlaybook{}, err
	}
	return hostPlaybook{
		file: "playbooks/workstation_vault_proxy.yaml",
		extraVars: map[string]any{
			"workstation_vault_proxy_operator_user":               facts.CurrentUname,
			"workstation_vault_proxy_ca_dir":                      a.newVaultPaths().TLSDir(),
			"workstation_vault_proxy_gitlab_url":                  origin.WebURL,
			"workstation_vault_proxy_gitlab_top_level_group_path": origin.TopLevelGroup,
		},
		doneMsg: "Workstation Vault Proxies applied.",
	}, nil
}

// buildHostTelemetryPlaybook reads the allocated scrape subnet from the Vault registry and prepares the host telemetry playbook.
func (a *app) buildHostTelemetryPlaybook(ctx context.Context) (hostPlaybook, error) {
	kv, err := a.newAdministratorKV()
	if err != nil {
		return hostPlaybook{}, err
	}
	registry := a.topology.HostTelemetryScrape.Registry
	cidr, err := kv.ReadField(ctx, issuedtokens.VaultField{Mount: registry.Mount, Path: registry.Path, Field: registry.CIDRField})
	if err != nil {
		return hostPlaybook{}, err
	}
	address, err := kv.ReadField(ctx, issuedtokens.VaultField{Mount: registry.Mount, Path: registry.Path, Field: registry.AddressField})
	if err != nil {
		return hostPlaybook{}, err
	}
	// Reissues the publish listener certificate to include the scrape IP in its SAN before HAProxy binds the metrics frontend.
	if _, err := vaultops.EnsurePublishCertCovers(a.newVaultPaths().TLSDir(), net.ParseIP(address)); err != nil {
		return hostPlaybook{}, err
	}
	facts, err := config.DetectHostFacts()
	if err != nil {
		return hostPlaybook{}, err
	}
	return hostPlaybook{
		file: "playbooks/workstation_host_telemetry.yaml",
		extraVars: map[string]any{
			"workstation_host_telemetry_scrape_cidr":    cidr,
			"workstation_host_telemetry_scrape_address": address,
			"workstation_libvirt_operator_user":         facts.CurrentUname,
			"workstation_libvirt_vault_config_path":     filepath.Join(a.root, "vault", "vault.hcl"),
		},
		doneMsg: "Host telemetry scrape network applied.",
	}, nil
}

func (a *app) buildVaultAuditPlaybook() hostPlaybook {
	return hostPlaybook{
		file: "playbooks/workstation_vault_audit.yaml",
		extraVars: map[string]any{
			"workstation_vault_audit_home":       a.home,
			"workstation_vault_audit_repository": a.root,
		},
		doneMsg: "Workstation Vault audit check applied.",
	}
}
