package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// accessAdministrator and accessCredentialRotator name the operator identities of workstation-topology.yaml used by this CLI.
const (
	accessAdministrator     = topology.AccessRoleAdministrator
	accessCredentialRotator = topology.AccessRoleCredentialRotator
)

const msgCancelled = "Cancelled."

// serviceReadyTimeout bounds the wait for the services of service_admin_passwords, which start with the Bastion Vault.
const serviceReadyTimeout = 5 * time.Minute

// errRetainedServiceState indicates a target service rejecting its factory default password before Vault initialization.
var errRetainedServiceState = errors.New("a service retains a rotated password absent from a fresh Bastion Vault")

// buildProxyConfig resolves the Vault Proxy configuration for the requested role.
// Because the local proxy manages identity credentials, the CLI does not handle raw tokens.
func (a *app) buildProxyConfig(role topology.AccessRole) (vaultclient.Config, error) {
	ep, err := a.topology.ResolveProxyEndpoint(a.home, role)
	if err != nil {
		return vaultclient.Config{}, err
	}
	return vaultclient.Config{Address: ep.Address, CACertPath: ep.CACert, ClientCert: ep.ClientCert, ClientKey: ep.ClientKey, Token: ep.Token}, nil
}

func (a *app) enableVaultKV(ctx context.Context) error {
	op, err := a.newVaultOperator()
	if err != nil {
		return err
	}
	return op.EnableKVEngine(ctx)
}

// ensureLocalCA generates the local CA when vault/tls holds none, since a new CA invalidates every issued certificate.
// An existing CA keeps its certificates, and only a missing terminator client certificate is issued.
func (a *app) ensureLocalCA(_ context.Context) error {
	if _, err := os.Stat(a.newVaultPaths().TransportRootMLDSA87CACertFile()); err != nil {
		return a.issueVaultTLS()
	}
	issued, err := vaultops.EnsureTerminatorClientCert(a.newVaultPaths().TLSDir())
	if err != nil {
		return err
	}
	if issued {
		a.out.Print(ui.OK, "Vault TLS terminator client certificate generated.")
	}
	return nil
}

func (a *app) issueVaultTLS() error {
	if err := vaultops.GenerateTLS(a.newVaultPaths().TLSDir(), a.newBastionVaultListeners()); err != nil {
		return err
	}
	a.out.Print(ui.OK, "Vault TLS certificates generated.")
	return nil
}

func (a *app) generateRootToken(ctx context.Context) error {
	if !a.out.PromptConfirm(a.in, "Generate a break-glass root token from the stored unseal keys? Type 'Y' or 'y' to confirm: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	op, err := a.newVaultOperator()
	if err != nil {
		return err
	}
	if err := op.GenerateRoot(ctx); err != nil {
		return err
	}
	a.out.Print(ui.Warn, "Run ./governance vault revoke-root after the break-glass work.")
	return nil
}

func (a *app) generateVaultTLS(_ context.Context) error {
	if !a.out.PromptConfirm(a.in, "Type 'Y' or 'y' to confirm execution: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	return a.issueVaultTLS()
}

// initVault aborts when a configured service rejects its factory default password because the service stores only an
// irreversible password hash once Bastion Vault state is wiped.
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
	op, err := a.newVaultOperator()
	if err != nil {
		return err
	}
	return op.Init(ctx)
}

func (a *app) newRotationClient() (*vaultapi.Client, error) {
	cfg, err := a.buildProxyConfig(accessCredentialRotator)
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

func (a *app) revokeRootToken(ctx context.Context) error {
	if !a.out.PromptConfirm(a.in, "Revoke the root token of ~/.vault-token? Type 'Y' or 'y' to confirm: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}
	cfg, err := a.buildProxyConfig(accessAdministrator)
	if err != nil {
		return err
	}
	ep, err := a.topology.ResolveProxyEndpoint(a.home, accessAdministrator)
	if err != nil {
		return err
	}
	op, err := a.newVaultOperator()
	if err != nil {
		return err
	}
	if err := op.RevokeRoot(ctx, cfg, "operator-"+ep.Identity); err != nil {
		return err
	}
	a.out.Print(ui.Info, "./governance vault generate-root restores a root token for break-glass.")
	return nil
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

func (a *app) unsealVault(ctx context.Context) error {
	op, err := a.newVaultOperator()
	if err != nil {
		return err
	}
	return op.Unseal(ctx)
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
