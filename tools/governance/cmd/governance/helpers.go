package main

import (
	// "gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
)

func (a *app) newVaultPaths() vaultops.Paths {
	return vaultops.NewPaths(a.root, a.ansibleDir, a.home, a.topology.BastionVault)
}

func (a *app) resolveHostAnsibleDir() string {
	return a.ansibleDir
}

// Deprecated: resolveBastionVaultAddr is superseded by a.topology.BastionVault.
// func (a *app) resolveBastionVaultAddr() string {
// 	if a.bastionVaultAddr != "" {
// 		return a.bastionVaultAddr
// 	}
// 	return ""
// }
