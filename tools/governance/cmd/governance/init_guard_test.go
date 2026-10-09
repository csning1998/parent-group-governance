package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

func TestInitVault_ProceedsWhenEveryServiceAcceptsTheFactoryDefault(t *testing.T) {
	a := &app{
		root:        t.TempDir(),
		home:        t.TempDir(),
		out:         ui.New(io.Discard, io.Discard),
		credentials: []credentials.Credential{credentialAccepting("example-fresh", true)},
	}

	// vaultops.Init then fails against the absent Vault, which proves the check passed.
	if err := a.initVault(context.Background()); errors.Is(err, errRetainedServiceState) {
		t.Errorf("initVault error = %v, want the check to pass", err)
	}
}

func TestInitVault_RefusesAServiceWhichRejectsTheFactoryDefault(t *testing.T) {
	a := &app{
		root:        t.TempDir(),
		home:        t.TempDir(),
		out:         ui.New(io.Discard, io.Discard),
		credentials: []credentials.Credential{credentialAccepting("example-fresh", true), credentialAccepting("example-retained", false)},
	}

	err := a.initVault(context.Background())
	if !errors.Is(err, errRetainedServiceState) {
		t.Fatalf("initVault error = %v, want errRetainedServiceState", err)
	}
	if !strings.Contains(err.Error(), "example-retained") || strings.Contains(err.Error(), "example-fresh") {
		t.Errorf("initVault error = %v, want the retained credential alone", err)
	}
}

func credentialAccepting(key string, acceptsDefault bool) credentials.Credential {
	return credentials.Credential{Key: key, Spec: secretrotate.Spec{
		FactoryDefaultPassword: "example-default",
		Verify:                 func(context.Context, string) (bool, error) { return acceptsDefault, nil },
	}}
}
