package main

import (
	"net"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vault"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func (a *app) newVaultPaths() vault.Paths {
	return vault.NewPaths(a.root, a.home)
}

func (a *app) newBastionVaultConfig() vaultclient.Config {
	return vaultclient.Config{
		Address:    a.topology.BastionVault.APIEndpoint(),
		CACertPath: a.newVaultPaths().TransportRootMLDSA87CACertFile(),
	}
}

func (a *app) newBastionVaultListeners() vault.Listeners {
	return vault.Listeners{
		Loopback: net.ParseIP(a.topology.BastionVault.LoopbackIP),
		Publish:  net.ParseIP(a.topology.BastionVault.PublishIP),
	}
}

func (a *app) newVaultOperator() (*vault.Operator, error) {
	return vault.NewOperator(a.newVaultPaths(), a.newBastionVaultConfig(), a.out)
}
