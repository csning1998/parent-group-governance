package main

import (
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
)

func (a *app) newVaultPaths() vaultops.Paths {
	return vaultops.NewPaths(a.root, a.ansibleDir, a.home, a.resolveBastionVaultAddr())
}

func (a *app) resolveHostAnsibleDir() string {
	return a.ansibleDir
}

func (a *app) resolveBastionVaultAddr() string {
	if a.bastionVaultAddr != "" {
		return a.bastionVaultAddr
	}
	if a.env != nil {
		return a.env.Get(config.KeyDevVaultAddr)
	}
	return ""
}
