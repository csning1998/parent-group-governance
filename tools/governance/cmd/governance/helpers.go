package main

import (
	"net"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func (a *app) newVaultPaths() vaultops.Paths {
	return vaultops.NewPaths(a.root, a.home)
}

func (a *app) newBastionVaultConfig() vaultclient.Config {
	return vaultclient.Config{
		Address:    a.topology.BastionVault.APIEndpoint(),
		CACertPath: a.newVaultPaths().CACertFile(),
	}
}

func (a *app) newBastionVaultListeners() vaultops.Listeners {
	return vaultops.Listeners{
		Loopback: net.ParseIP(a.topology.BastionVault.LoopbackAddress),
		Publish:  net.ParseIP(a.topology.BastionVault.PublishAddress),
	}
}

func (a *app) newVaultOperator() (*vaultops.Operator, error) {
	return vaultops.NewOperator(a.newVaultPaths(), a.newBastionVaultConfig(), a.out)
}
