package main

import (
	"cmp"
	"context"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/stateaudit"
)

func (a *app) newStateAuditCmd() *cobra.Command {
	cmd := stateaudit.NewCommand(a.resolveStateAuditConfig)
	cmd.Hidden = true
	return cmd
}

func (a *app) newTerraformCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "terraform", Short: "Terraform governance and state operations"}
	auditCmd := stateaudit.NewCommand(a.resolveStateAuditConfig)
	auditCmd.Use = "audit-state"
	auditCmd.Aliases = []string{"audit", "state-audit"}
	cmd.AddCommand(auditCmd)
	return cmd
}

// resolveStateAuditConfig audits the terraform directory of this repository unless opts names another one.
func (a *app) resolveStateAuditConfig(opts stateaudit.Options) (stateaudit.Config, error) {
	dir := cmp.Or(opts.TerraformDir, filepath.Join(a.root, "terraform"))
	return stateaudit.ConfigFromEnv(dir, os.Getenv, opts.History)
}

// runStateAuditMenu scans every historical version, as the acceptance of a merge request does.
func (a *app) runStateAuditMenu(ctx context.Context) error {
	cfg, err := a.resolveStateAuditConfig(stateaudit.Options{History: true})
	if err != nil {
		return err
	}
	return stateaudit.Run(ctx, cfg, os.Stdout)
}
