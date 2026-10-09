package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apenella/go-ansible/v2/pkg/playbook"
	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ansibleops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// accessFoundation and accessRotation name the operator identities of workstation-topology.yaml which this CLI uses.
const (
	accessFoundation = topology.AccessRoleFoundation
	accessRotation   = topology.AccessRoleRotation
)

const msgCancelled = "Cancelled."

// serviceReadyTimeout bounds the wait for the services of service_admin_passwords, which start with the Bastion Vault.
const serviceReadyTimeout = 5 * time.Minute

// errRetainedServiceState reports a service which retains a rotated password, which a fresh Bastion Vault cannot hold.
var errRetainedServiceState = errors.New("a service retains a rotated password, which a fresh Bastion Vault cannot hold")

// hostPlaybook is one workstation playbook with the extra vars which the CLI injects.
type hostPlaybook struct {
	file      string
	extraVars map[string]any
	doneMsg   string
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

// buildProxyConfig resolves the Vault Proxy configuration of the identity with role, which holds the login of the
// identity, hence the CLI never reads a token.
func (a *app) buildProxyConfig(role topology.AccessRole) (vaultclient.Config, error) {
	ep, err := a.topology.ResolveProxyEndpoint(a.home, role)
	if err != nil {
		return vaultclient.Config{}, err
	}
	return vaultclient.Config{Address: ep.Address, CACertPath: ep.CACert, ClientCert: ep.ClientCert, ClientKey: ep.ClientKey, Token: ep.Token}, nil
}

func (a *app) buildSELinuxPlaybook() (hostPlaybook, error) {
	return hostPlaybook{
		file:      "playbooks/workstation_selinux.yaml",
		extraVars: map[string]any{"workstation_selinux_home": a.home},
		doneMsg:   "Workstation SELinux policy and file contexts applied.",
	}, nil
}

func (a *app) buildVaultProxyPlaybook() (hostPlaybook, error) {
	facts, err := config.DetectHostFacts()
	if err != nil {
		return hostPlaybook{}, err
	}
	return hostPlaybook{
		file: "playbooks/workstation_vault_proxy.yaml",
		extraVars: map[string]any{
			"workstation_vault_proxy_operator_user": facts.CurrentUname,
			"workstation_vault_proxy_ca_dir":        a.newVaultPaths().TLSDir(),
		},
		doneMsg: "Workstation Vault Proxies applied.",
	}, nil
}

func (a *app) enableVaultKV(ctx context.Context) error {
	return vaultops.EnableKVEngine(ctx, a.newVaultPaths(), a.out)
}

// ensureLocalCA generates the local CA when vault/tls holds none, since a new CA invalidates every issued certificate.
func (a *app) ensureLocalCA(ctx context.Context) error {
	p := a.newVaultPaths()
	if _, err := os.Stat(filepath.Join(p.TLSDir(), "ca.pem")); err == nil {
		return nil
	}
	return vaultops.GenerateTLS(ctx, p, a.out)
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

func (a *app) generateRoot(ctx context.Context) error {
	return a.generateRootToken(ctx)
}

func (a *app) generateRootToken(ctx context.Context) error {
	if !a.out.PromptConfirm(a.in, "Generate a break-glass root token from the stored unseal keys? Type 'Y' or 'y' to confirm: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	return vaultops.GenerateRoot(ctx, a.newVaultPaths(), a.out)
}

func (a *app) generateVaultTLS(ctx context.Context) error {
	if !a.out.PromptConfirm(a.in, "Type 'Y' or 'y' to confirm execution: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	return vaultops.GenerateTLS(ctx, a.newVaultPaths(), a.out)
}

// initVault refuses a fresh Bastion Vault while a declared service rejects its factory default password, since no
// tool recovers the rotated password from the hash which the service stores.
func (a *app) initVault(ctx context.Context) error {
	waitCtx, cancel := context.WithTimeout(ctx, serviceReadyTimeout)
	defer cancel()
	var retained []string
	for _, cred := range a.credentials {
		if cred.Spec.FactoryDefaultPassword == "" {
			continue
		}
		a.out.Print(ui.Info, "Waiting for the service of "+cred.Key+" to answer.")
		fresh, err := secretrotate.AwaitFactoryDefault(waitCtx, cred.Spec, 5*time.Second)
		if err != nil {
			return fmt.Errorf("%s: %w", cred.Key, err)
		}
		if !fresh {
			retained = append(retained, cred.Key)
		}
	}
	if len(retained) > 0 {
		return fmt.Errorf("%w: rebuild the service of %s, as README Section 4 Item D describes, before vault init",
			errRetainedServiceState, strings.Join(retained, ", "))
	}
	return vaultops.Init(ctx, a.newVaultPaths(), a.out)
}

func (a *app) newRotationClient() (*vaultapi.Client, error) {
	cfg, err := a.buildProxyConfig(accessRotation)
	if err != nil {
		return nil, err
	}
	return vaultclient.NewClient(cfg)
}

// reconcileCredential pushes the value Vault already holds for key out to the live service,
// prompting for the current live credential needed to authenticate the call. Leaving the
// prompt blank lets Reconcile guess instead of failing outright.
func (a *app) reconcileCredential(ctx context.Context, key string) error {
	cred, ok := credentials.Lookup(a.credentials, key)
	if !ok {
		return fmt.Errorf("no registered credential %q", key)
	}
	client, err := a.newRotationClient()
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
	a.out.Print(ui.OK, key+": the live service holds the Vault value.")
	return nil
}

func (a *app) revokeRoot(ctx context.Context) error {
	return a.revokeRootToken(ctx)
}

func (a *app) revokeRootToken(ctx context.Context) error {
	if !a.out.PromptConfirm(a.in, "Revoke the root token of ~/.vault-token? Type 'Y' or 'y' to confirm: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	cfg, err := a.buildProxyConfig(accessFoundation)
	if err != nil {
		return err
	}
	ep, err := a.topology.ResolveProxyEndpoint(a.home, accessFoundation)
	if err != nil {
		return err
	}
	return vaultops.RevokeRoot(ctx, a.newVaultPaths(), cfg, "operator-"+ep.Identity, a.out)
}

// rotateCredential runs the a.credentials entry identified by key against Bastion Vault.
func (a *app) rotateCredential(ctx context.Context, key string) error {
	cred, ok := credentials.Lookup(a.credentials, key)
	if !ok {
		return fmt.Errorf("no registered credential %q", key)
	}
	client, err := a.newRotationClient()
	if err != nil {
		return err
	}
	log := func(msg string) { a.out.Print(ui.OK, msg) }
	_, err = secretrotate.Rotate(ctx, client, cred.Spec, log)
	return err
}

// runHostAll applies every workstation prerequisite in bootstrap order: SELinux, libvirt, the local CA when absent,
// and the Vault Proxies, which the local CA signs. The operator enters the privilege escalation password once.
func (a *app) runHostAll(ctx context.Context) error {
	becomePass, err := a.out.PromptSecret(a.in, int(os.Stdin.Fd()), "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		return fmt.Errorf("read ANSIBLE_BECOME_PASS: %w", err)
	}
	if becomePass == "" {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	selinuxPB, err := a.buildSELinuxPlaybook()
	if err != nil {
		return err
	}
	if err := a.executePlaybook(ctx, selinuxPB, becomePass); err != nil {
		return err
	}

	libvirtPB, err := a.buildLibvirtPlaybook()
	if err != nil {
		return err
	}
	if err := a.executePlaybook(ctx, libvirtPB, becomePass); err != nil {
		return err
	}

	if err := a.ensureLocalCA(ctx); err != nil {
		return err
	}

	proxyPB, err := a.buildVaultProxyPlaybook()
	if err != nil {
		return err
	}
	return a.executePlaybook(ctx, proxyPB, becomePass)
}

func (a *app) runHostLibvirtPlaybook(ctx context.Context) error {
	return a.runHostPlaybooks(ctx, a.buildLibvirtPlaybook)
}

// runHostPlaybooks prompts once for the privilege escalation password, where a blank answer cancels, and resolves
// and runs each step in order against the local inventory.
func (a *app) runHostPlaybooks(ctx context.Context, steps ...func() (hostPlaybook, error)) error {
	becomePass, err := a.out.PromptSecret(a.in, int(os.Stdin.Fd()), "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		return fmt.Errorf("read ANSIBLE_BECOME_PASS: %w", err)
	}
	if becomePass == "" {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	for _, step := range steps {
		pb, err := step()
		if err != nil {
			return err
		}
		if err := a.executePlaybook(ctx, pb, becomePass); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) runHostSELinuxPlaybook(ctx context.Context) error {
	return a.runHostPlaybooks(ctx, a.buildSELinuxPlaybook)
}

func (a *app) runHostVaultProxyPlaybook(ctx context.Context) error {
	return a.runHostPlaybooks(ctx, a.buildVaultProxyPlaybook)
}

func (a *app) unsealVault(ctx context.Context) error {
	return vaultops.UnsealBastion(ctx, a.newVaultPaths(), a.out)
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
