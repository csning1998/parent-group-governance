package main

import (
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
)

func (a *app) newVaultPaths() vaultops.Paths {
	return vaultops.NewPaths(a.root, a.ansibleDir, a.home, a.topology.BastionVault)
}
