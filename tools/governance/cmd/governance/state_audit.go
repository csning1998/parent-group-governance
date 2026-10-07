package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/stateaudit"
)

func (a *app) resolveStateAudit(history bool) (stateaudit.Config, error) {
	return stateaudit.ConfigFromEnv(filepath.Join(a.root, "terraform"), os.Getenv, history)
}

func (a *app) newStateAuditCmd() *cobra.Command {
	return stateaudit.NewCommand(a.resolveStateAudit)
}

// runStateAuditMenu scans every historical version, as the acceptance of a merge request does.
func (a *app) runStateAuditMenu(ctx context.Context) error {
	cfg, err := a.resolveStateAudit(true)
	if err != nil {
		return err
	}
	return stateaudit.Run(ctx, cfg, os.Stdout)
}
