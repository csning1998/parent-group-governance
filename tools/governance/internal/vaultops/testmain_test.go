package vaultops

import (
	"fmt"
	"os"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultenv"
)

// TestMain MUST clear ambient Vault environment variables before any tests run.
func TestMain(m *testing.M) {
	err := vaultenv.Clear()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
