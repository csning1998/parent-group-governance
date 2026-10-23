package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
)

// newOperationsApp constructs an operational test app with predetermined prompt answers and proxy identities.
// The Vault operator client MUST receive local CA fixtures via withLocalCA because offline client initialization requires TLS files.
func newOperationsApp(t *testing.T, answer string, withLocalCA bool, identities map[string]topology.ProxyIdentity) *app {
	t.Helper()
	a := &app{
		root: t.TempDir(),
		home: t.TempDir(),
		topology: topology.VaultTopology{
			BastionVault: topology.BastionVault{LoopbackAddress: "127.0.0.1", PublishAddress: "192.0.2.10", APIPort: 8200},
			OperatorVaultProxy: topology.OperatorVaultProxy{
				UserConfigDir:    ".config/vault-proxy",
				PlaceholderToken: "proxy-supplied",
				Identities:       identities,
			},
		},
		out: ui.New(io.Discard, io.Discard),
		in:  bufio.NewReader(strings.NewReader(answer + "\n")),
	}
	if withLocalCA {
		if err := vaultops.GenerateTLS(a.newVaultPaths().TLSDir(), a.newBastionVaultListeners()); err != nil {
			t.Fatalf("GenerateTLS: %v", err)
		}
	}
	return a
}

func administratorOnly() map[string]topology.ProxyIdentity {
	return map[string]topology.ProxyIdentity{"example-administrator": {ListenPort: 8212, AccessTier: string(topology.AccessRoleAdministrator)}}
}

func rotatorOnly() map[string]topology.ProxyIdentity {
	return map[string]topology.ProxyIdentity{"example-rotator": {ListenPort: 8213, AccessTier: string(topology.AccessRoleCredentialRotator)}}
}

func assertOperationError(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("error = %v, want nil", err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Fatalf("error = %v, want a message containing %q", err, want)
	}
}

func TestRevokeRootTokenStopsAtTheFirstMissingPrerequisite(t *testing.T) {
	tests := []struct {
		name        string
		answer      string
		withLocalCA bool
		identities  map[string]topology.ProxyIdentity
		want        string
	}{
		{name: "cancelled", answer: "n", identities: administratorOnly()},
		{name: "no administrator identity", answer: "y", identities: rotatorOnly(), want: "access_tier administrator"},
		{name: "no local CA", answer: "y", identities: administratorOnly(), want: "vaultops: build client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newOperationsApp(t, tt.answer, tt.withLocalCA, tt.identities)
			assertOperationError(t, a.revokeRootToken(context.Background()), tt.want)
		})
	}
}

func TestRevokeRootTokenRequiresTheStoredRootToken(t *testing.T) {
	a := newOperationsApp(t, "y", true, administratorOnly())
	if err := a.revokeRootToken(context.Background()); !errors.Is(err, vaultops.ErrNoRootToken) {
		t.Fatalf("revokeRootToken error = %v, want vaultops.ErrNoRootToken", err)
	}
}

func TestNewRotationClientResolvesTheCredentialRotatorIdentity(t *testing.T) {
	tests := []struct {
		name       string
		identities map[string]topology.ProxyIdentity
		want       string
	}{
		{name: "no credential-rotator identity", identities: administratorOnly(), want: "access_tier credential-rotator"},
		{name: "no client certificate", identities: rotatorOnly(), want: "example-rotator/client.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newOperationsApp(t, "", false, tt.identities).newRotationClient()
			assertOperationError(t, err, tt.want)
		})
	}
}

func TestGenerateRootTokenStopsAtTheFirstMissingPrerequisite(t *testing.T) {
	tests := []struct {
		name        string
		answer      string
		withLocalCA bool
		want        string
	}{
		{name: "cancelled", answer: "n"},
		{name: "no local CA", answer: "y", want: "vaultops: build client"},
		{name: "no unseal keys", answer: "y", withLocalCA: true, want: "vaultops: unseal keys not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newOperationsApp(t, tt.answer, tt.withLocalCA, administratorOnly())
			assertOperationError(t, a.generateRootToken(context.Background()), tt.want)
		})
	}
}

func TestGenerateVaultTLSIssuesTheLocalCAOnConfirmation(t *testing.T) {
	a := newOperationsApp(t, "y", false, administratorOnly())
	if err := a.generateVaultTLS(context.Background()); err != nil {
		t.Fatalf("generateVaultTLS: %v", err)
	}
	if _, err := os.Stat(a.newVaultPaths().TransportRootMLDSA87CACertFile()); err != nil {
		t.Errorf("ML-DSA-87 CA stat error = %v, want the issued CA", err)
	}
}

func TestGenerateVaultTLSReportsMissingListenerAddresses(t *testing.T) {
	a := newOperationsApp(t, "y", false, administratorOnly())
	a.topology.BastionVault = topology.BastionVault{}
	assertOperationError(t, a.generateVaultTLS(context.Background()), "valid loopback and publish IP addresses")
}

func TestVaultOperationsStopAtTheFirstMissingPrerequisite(t *testing.T) {
	operations := []struct {
		name          string
		run           func(*app, context.Context) error
		withoutSecret string
	}{
		{name: "enableVaultKV", run: (*app).enableVaultKV, withoutSecret: "vaultops: root token not found"},
		{name: "unsealVault", run: (*app).unsealVault, withoutSecret: "vaultops: unseal keys not found"},
	}
	for _, op := range operations {
		t.Run(op.name+" without a local CA", func(t *testing.T) {
			err := op.run(newOperationsApp(t, "", false, administratorOnly()), context.Background())
			assertOperationError(t, err, "vaultops: build client")
		})
		t.Run(op.name+" without a stored secret", func(t *testing.T) {
			err := op.run(newOperationsApp(t, "", true, administratorOnly()), context.Background())
			assertOperationError(t, err, op.withoutSecret)
		})
	}
}
