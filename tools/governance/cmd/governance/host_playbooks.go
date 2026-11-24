package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/apenella/go-ansible/v2/pkg/playbook"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ansible"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vault"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
)

type hostPlaybook struct {
	file      string
	extraVars map[string]any
	doneMsg   string
}

type hostStep func(ctx context.Context, becomePass string) error

// runHostAll runs workstation prerequisites in bootstrap order under a single privilege escalation prompt.
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
	return a.runHostSteps(
		ctx,
		a.playbookStep(func() (hostPlaybook, error) { return a.buildHostTelemetryPlaybook(ctx) }),
		a.playbookStep(a.buildLibvirtPlaybook),
	)
}

// runHostVaultAuditPlaybook omits privilege escalation because the audit systemd units are managed under the operator user session.
func (a *app) runHostVaultAuditPlaybook(ctx context.Context) error {
	return a.executePlaybook(ctx, a.buildVaultAuditPlaybook(), "")
}

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

func (a *app) playbookStep(build func() (hostPlaybook, error)) hostStep {
	return func(ctx context.Context, becomePass string) error {
		pb, err := build()
		if err != nil {
			return err
		}
		return a.executePlaybook(ctx, pb, becomePass)
	}
}

func (a *app) executePlaybook(ctx context.Context, pb hostPlaybook, becomePass string) error {
	opts := &playbook.AnsiblePlaybookOptions{Inventory: "inventory/localhost.yaml", ExtraVars: pb.extraVars}
	err := ansible.ExecutePlaybook(ctx, ansible.PlaybookRequest{
		AnsibleDir:   a.ansibleDir,
		RunDir:       a.ansibleDir,
		PlaybookFile: pb.file,
		Options:      opts,
		ExtraEnv:     map[string]string{"ANSIBLE_BECOME_PASS": becomePass},
	})
	if err != nil {
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
	scrapeIP, err := kv.ReadField(ctx, issuedtokens.VaultField{Mount: registry.Mount, Path: registry.Path, Field: registry.IPField})
	if err != nil {
		return hostPlaybook{}, err
	}
	// Reissue the publish listener certificate to include the scrape IP in its SAN before HAProxy binds the metrics frontend.
	if _, err := vault.EnsurePublishCertCovers(a.newVaultPaths().TLSDir(), net.ParseIP(scrapeIP)); err != nil {
		return hostPlaybook{}, err
	}
	return hostPlaybook{
		file: "playbooks/workstation_host_telemetry.yaml",
		extraVars: map[string]any{
			"workstation_host_telemetry_scrape_cidr": cidr,
			"workstation_host_telemetry_scrape_ip":   scrapeIP,
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
