// Package main provides the governance CLI for Bastion Vault and host Ansible operations.
package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/gitremote"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultenv"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
)

type app struct {
	root         string
	home         string
	ansibleDir   string
	topology     topology.VaultTopology
	credentials  []credentials.Credential
	issuedTokens issuedtokens.Config
	env          *config.Env
	out          *ui.Printer
	in           *bufio.Reader
	stdout       io.Writer
	stderr       io.Writer

	// Overridable in tests to avoid invoking git, DAG assembly, or TTY prompts.
	resolveOrigin func(context.Context) (gitlabOrigin, error)
	buildGraph    func() (*converge.Graph, error)
	promptBecome  func(context.Context) (converge.BecomePassword, error)
}

type gitlabOrigin struct {
	WebURL        string
	APIURL        string
	TopLevelGroup string
}

func main() {
	os.Exit(execute(os.Args[1:]))
}

func execute(args []string) int {
	out := ui.New(os.Stdout, os.Stderr)
	a, err := loadApp(out)
	if err != nil {
		out.Print(ui.Fatal, err.Error())
		return 1
	}

	rootCmd := a.newRootCmd()
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		out.Print(ui.Error, err.Error())
		return 1
	}
	return 0
}

func loadApp(out *ui.Printer) (*app, error) {
	// Unset ambient Vault variables because a missing CA file fails client construction
	// and VAULT_SKIP_VERIFY disables certificate verification.
	if err := vaultenv.Clear(); err != nil {
		return nil, err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root, err := resolveProjectRoot(cwd)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	topologyPath := filepath.Join(root, topology.FileName)
	topo, err := topology.Load(topologyPath)
	if err != nil {
		return nil, err
	}
	credsConfig, err := credentials.Load(topologyPath)
	if err != nil {
		return nil, err
	}
	creds, err := credsConfig.BuildCredentials()
	if err != nil {
		return nil, err
	}
	issued, err := issuedtokens.Load(topologyPath)
	if err != nil {
		return nil, err
	}

	return &app{
		root:         root,
		home:         home,
		ansibleDir:   filepath.Join(root, "ansible"),
		topology:     topo,
		credentials:  creds,
		issuedTokens: issued,
		out:          out,
		in:           bufio.NewReader(os.Stdin),
		stdout:       os.Stdout,
		stderr:       os.Stderr,
		resolveOrigin: func(ctx context.Context) (gitlabOrigin, error) {
			remote, err := gitremote.Resolve(ctx, root)
			if err != nil {
				return gitlabOrigin{}, err
			}
			return gitlabOrigin{WebURL: remote.WebURL(), APIURL: remote.APIURL(), TopLevelGroup: remote.TopLevelGroup()}, nil
		},
	}, nil
}

func (a *app) newRootCmd() *cobra.Command {
	var rootCmd *cobra.Command
	rootCmd = &cobra.Command{
		Use:           "governance",
		Short:         "Bastion Vault and host Ansible operations for parent-group-governance",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd == rootCmd || cmd.Name() == "status" || cmd.Name() == "converge" {
				return nil
			}
			env, err := config.BootstrapEnv(a.root, a.out)
			if err != nil {
				return err
			}
			a.env = env
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runMenu(cmd.Context())
		},
	}

	rootCmd.AddCommand(
		a.newStatusCmd(),
		a.newConvergeCmd(),
		a.newHostCmd(),
		a.newVaultCmd(),
		a.newCredentialsCmd(),
		a.newTerraformCmd(),
		a.newStateAuditCmd(),
		a.newEnvCmd(),
	)
	return rootCmd
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
