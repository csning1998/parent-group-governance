package main

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/stateaudit"
)

const labelStateAudit = "[Terraform] Audit State Secrets"

func TestBuildMenuOptions_OffersStateAudit(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	options := a.buildMenuOptions()
	index := slices.IndexFunc(options, func(o menuOption) bool { return o.label == labelStateAudit })
	if index < 0 || options[index].run == nil || index == len(options)-1 {
		t.Errorf("menu offers %q at %d, want an action before Quit", labelStateAudit, index)
	}
}

func TestNewStateAuditCmd(t *testing.T) {
	a := &app{root: t.TempDir(), out: ui.New(io.Discard, io.Discard)}
	cmd := a.newStateAuditCmd()
	flag := cmd.Flags().Lookup("history")
	if cmd.Name() != "state-audit" || flag == nil {
		t.Fatalf("command %q, flag %v, want state-audit with --history", cmd.Name(), flag)
	}

	t.Setenv("TF_HTTP_USERNAME", "")
	t.Setenv("TF_HTTP_PASSWORD", "")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if !errors.Is(err, stateaudit.ErrCredentialsMissing) {
		t.Errorf("Execute error = %v, want ErrCredentialsMissing", err)
	}
}

// TestRunStateAuditMenu covers the menu entry, which scans the history as the acceptance of a merge request.
func TestRunStateAuditMenu(t *testing.T) {
	a := &app{root: t.TempDir(), out: ui.New(io.Discard, io.Discard)}
	t.Setenv("TF_HTTP_USERNAME", "")
	t.Setenv("TF_HTTP_PASSWORD", "")
	err := a.runStateAuditMenu(context.Background())
	if !errors.Is(err, stateaudit.ErrCredentialsMissing) {
		t.Errorf("runStateAuditMenu error = %v, want ErrCredentialsMissing", err)
	}
}
