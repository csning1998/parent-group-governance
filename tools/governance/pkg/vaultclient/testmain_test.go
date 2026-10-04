package vaultclient_test

import (
	"fmt"
	"os"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultenv"
)

// The suite builds Vault clients, hence the ambient Vault environment of the developer shell MUST NOT reach the clients.
func TestMain(m *testing.M) {
	err := vaultenv.Clear()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
