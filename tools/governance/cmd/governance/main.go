// Package main provides the governance CLI for Bastion Vault and host Ansible operations.
package main

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultenv"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
)

type app struct {
	root             string
	home             string
	ansibleDir       string
	bastionVaultAddr string
	credentials      []credentials.Credential
	env              *config.Env
	out              *ui.Printer
	in               *bufio.Reader
}

func main() {
	os.Exit(execute(os.Args[1:]))
}

func resolveProjectRoot(start string) (string, error) {
	dir := start
	for {
		_, err := os.Stat(filepath.Join(dir, ".git"))
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no .git entry found upward from " + start)
		}
		dir = parent
	}
}

func execute(args []string) int {
	out := ui.New(os.Stdout, os.Stderr)

	// A stale VAULT_CACERT of a wiped TLS directory otherwise fails every client, and VAULT_SKIP_VERIFY disables verification.
	err := vaultenv.Clear()
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}

	cwd, err := os.Getwd()
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}
	root, err := resolveProjectRoot(cwd)
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}
	home, err := os.UserHomeDir()
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}

	a := &app{
		root:       root,
		home:       home,
		ansibleDir: filepath.Join(root, "ansible"),
		out:        out,
		in:         bufio.NewReader(os.Stdin),
	}

	credsConfig, err := credentials.Load(filepath.Join(root, "credentials.yaml"))
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}
	creds, err := credsConfig.BuildCredentials()
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}
	a.credentials = creds
	if credsConfig.Vault.Address != "" {
		a.bastionVaultAddr = credsConfig.Vault.Address
	}

	var rootCmd *cobra.Command
	rootCmd = &cobra.Command{
		Use:           "governance",
		Short:         "Bastion Vault and host Ansible operations for parent-group-governance",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd == rootCmd {
				return nil
			}
			env, err := config.BootstrapEnv(a.root, a.out)
			if err != nil {
				return err
			}
			a.env = env
			a.applyEnvPaths()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runMenu(cmd.Context())
		},
	}

	rootCmd.AddCommand(
		a.newVaultCmd(),
		a.newAnsibleCmd(),
		a.newEnvCmd(),
		a.newStateAuditCmd(),
	)

	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		out.Print(ui.Error, err.Error())
		return 1
	}
	return 0
}

func (a *app) applyEnvPaths() {
	if a.env == nil {
		return
	}
	if a.bastionVaultAddr == "" {
		a.bastionVaultAddr = a.env.Get(config.KeyBastionVaultAddr)
	}
}
