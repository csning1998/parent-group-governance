package vaultclient_test

import (
	"fmt"
	"os"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultenv"
)

// Clears ambient Vault environment variables to isolate test clients from the developer shell.
func TestMain(m *testing.M) {
	err := vaultenv.Clear()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
