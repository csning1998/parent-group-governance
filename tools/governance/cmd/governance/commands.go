package main

import (
	"context"

	"github.com/spf13/cobra"
)

const (
	prefixReconcile = "Reconcile "
	prefixRotate    = "Rotate "
)

func (a *app) newCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "credentials", Short: "Service credential lifecycle operations"}

	cmd.AddCommand(a.newRotateCredentialsCmd("Rotate service admin passwords"))
	cmd.AddCommand(a.newReconcileCredentialsCmd("Apply a stored credential to a drifted live service"))

	issueCmd := &cobra.Command{Use: "issue", Short: "Issue service tokens into the Bastion Vault and GitLab"}
	issueCmd.AddCommand(&cobra.Command{
		Use:   "sonarqube-analysis-token",
		Short: "Issue the SonarQube analysis token of the group CI jobs and revoke the earlier tokens",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.issueSonarQubeAnalysisToken(cmd.Context()) },
	})
	issueCmd.AddCommand(&cobra.Command{
		Use:   "gitlab-group-runner",
		Short: "Register the group runner and write its config.toml, refusing an existing config.toml",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.registerGitLabGroupRunner(cmd.Context()) },
	})
	issueCmd.AddCommand(&cobra.Command{
		Use:   "code-reviewer-variables",
		Short: "Write the code reviewer bot tokens into the variables of every listed project",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.publishCodeReviewerVariables(cmd.Context()) },
	})
	cmd.AddCommand(issueCmd)

	return cmd
}

func (a *app) newEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "env",
		Hidden: true,
		Short:  "Environment verification",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "[Host] Verify Terraform, Vault, and Ansible on PATH",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.verifyEnvironment() },
	})
	return cmd
}

func (a *app) newHostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "host",
		Aliases: []string{"ansible"},
		Short:   "Workstation host operations",
	}
	cmd.AddCommand(&cobra.Command{
		Use:     "apply-all",
		Aliases: []string{"all"},
		Short:   "[Host] Apply all workstation prerequisites: SELinux, the local CA when absent, libvirt, and the Vault Proxies",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.runHostAll(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "apply-selinux",
		Aliases: []string{"selinux"},
		Short:   "[Host] Apply workstation SELinux policy and file contexts",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.runHostSELinuxPlaybook(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "apply-libvirt",
		Aliases: []string{"libvirt"},
		Short:   "[Host] Apply workstation Libvirt network and Bastion Vault prerequisites",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.runHostLibvirtPlaybook(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "apply-vault-proxy",
		Aliases: []string{"vault-proxy"},
		Short:   "[Host] Apply workstation Vault Proxies",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.runHostVaultProxyPlaybook(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "apply-vault-audit",
		Aliases: []string{"vault-audit"},
		Short:   "[Host] Apply the workstation Vault audit check",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.runHostVaultAuditPlaybook(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "apply-host-telemetry",
		Aliases: []string{"host-telemetry"},
		Short:   "[Host] Apply the host telemetry scrape network after foundation-vault-bastion",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.runHostTelemetryPlaybook(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "verify",
		Aliases: []string{"verify-tools"},
		Short:   "[Host] Verify Terraform, Vault, and Ansible on PATH",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.verifyEnvironment() },
	})
	return cmd
}

func (a *app) newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "vault", Short: "Bastion Vault operations"}

	cmd.AddCommand(&cobra.Command{
		Use:     "generate-tls",
		Aliases: []string{"tls-generate"},
		Short:   "[Vault] Generate TLS certificates for Bastion Vault (destroys existing files)",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.generateVaultTLS(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "[Vault] Initialize Bastion Vault",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.initVault(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "enable-kv",
		Short: "[Vault] Enable KV-v2 engine",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.enableVaultKV(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "unseal",
		Short: "[Vault] Unseal Bastion Vault",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.unsealVault(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "revoke-root",
		Aliases: []string{"revoke-root-token"},
		Short:   "[Vault] Revoke the root token after bootstrap, once the administrator Vault Proxy logs in",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.revokeRootToken(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "generate-root",
		Aliases: []string{"generate-root-token"},
		Short:   "[Vault] Generate a break-glass root token from the stored unseal keys",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.generateRootToken(cmd.Context()) },
	})

	cmd.AddCommand(a.newRotateCredentialsCmd("Rotate credentials in Bastion Vault"))
	for _, cred := range a.credentials {
		key := cred.Key
		// Hidden alias directly under vault for backward compatibility.
		cmd.AddCommand(&cobra.Command{
			Use:    key,
			Hidden: true,
			Short:  prefixRotate + key,
			RunE:   func(cmd *cobra.Command, args []string) error { return a.rotateCredential(cmd.Context(), key) },
		})
	}

	cmd.AddCommand(a.newReconcileCredentialsCmd("Apply a Vault-stored credential to a drifted live service"))

	return cmd
}

func (a *app) newRotateCredentialsCmd(short string) *cobra.Command {
	return a.newCredentialActionCmd("rotate", short, prefixRotate, a.rotateCredential)
}

func (a *app) newReconcileCredentialsCmd(short string) *cobra.Command {
	return a.newCredentialActionCmd("reconcile", short, prefixReconcile, a.reconcileCredential)
}

func (a *app) newCredentialActionCmd(use, short, prefix string, run func(context.Context, string) error) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short}
	for _, cred := range a.credentials {
		key := cred.Key
		cmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: prefix + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return run(cmd.Context(), key) },
		})
	}
	return cmd
}
