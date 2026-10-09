package main

import (
	"io"
	"slices"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
)

const labelApplyAll = "[Host] Apply All Workstation Prerequisites"

func TestBuildMenuOptions_NamesTheServiceAdminPasswords(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard), credentials: []credentials.Credential{{Key: "example-admin-password"}}}
	labels := menuLabels(a.buildMenuOptions())

	for _, want := range []string{
		"[Credentials] Rotate Service Admin Passwords",
		"[Credentials] Reconcile Service Admin Passwords with the Live Service",
	} {
		if !slices.Contains(labels, want) {
			t.Errorf("menu labels = %q, want %q", labels, want)
		}
	}
}

func TestBuildMenuOptions_OffersEachHostStepAlone(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	labels := menuLabels(a.buildMenuOptions())

	for _, want := range []string{
		"[Host] Apply Workstation SELinux Policy and File Contexts",
		"[Host] Apply Workstation Libvirt Network and Bastion Vault Prerequisites",
		"[Host] Apply Workstation Vault Proxies",
	} {
		if !slices.Contains(labels, want) {
			t.Errorf("menu labels = %q, want %q", labels, want)
		}
	}
}

func TestBuildMenuOptions_OpensWithApplyAllAndEndsWithQuit(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	options := a.buildMenuOptions()

	if first := options[0]; first.label != labelApplyAll || first.run == nil {
		t.Errorf("first menu option = %q, want %q with an action", first.label, labelApplyAll)
	}
	if last := options[len(options)-1]; last.label != "Quit" || last.run != nil {
		t.Errorf("last menu option = %q, want Quit without an action", last.label)
	}
}

func menuLabels(options []menuOption) []string {
	labels := make([]string, len(options))
	for i, opt := range options {
		labels[i] = opt.label
	}
	return labels
}
