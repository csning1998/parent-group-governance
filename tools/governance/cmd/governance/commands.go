package main

import "github.com/spf13/cobra"

const (
	prefixReconcile = "Reconcile "
	prefixRotate    = "Rotate "
)

func (a *app) newCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "credentials", Short: "Service credential lifecycle operations"}

	rotateCmd := &cobra.Command{Use: "rotate", Short: "Rotate service admin passwords"}
	for _, cred := range a.credentials {
		key := cred.Key
		rotateCmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: prefixRotate + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return a.rotateCredential(cmd.Context(), key) },
		})
	}
	cmd.AddCommand(rotateCmd)

	reconcileCmd := &cobra.Command{Use: "reconcile", Short: "Push a stored credential out to a drifted live service"}
	for _, cred := range a.credentials {
		key := cred.Key
		reconcileCmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: prefixReconcile + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return a.reconcileCredential(cmd.Context(), key) },
		})
	}
	cmd.AddCommand(reconcileCmd)

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
		Short:   "[Host] Apply all workstation prerequisites: SELinux, libvirt, the local CA when absent, and the Vault Proxies",
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
		Short:   "[Vault] Revoke the root token after bootstrap, once the foundation Vault Proxy logs in",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.revokeRootToken(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "generate-root",
		Aliases: []string{"generate-root-token"},
		Short:   "[Vault] Generate a break-glass root token from the stored unseal keys",
		RunE:    func(cmd *cobra.Command, args []string) error { return a.generateRootToken(cmd.Context()) },
	})

	rotateCmd := &cobra.Command{Use: "rotate", Short: "Rotate credentials in Bastion Vault"}
	for _, cred := range a.credentials {
		key := cred.Key
		rotateCmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: prefixRotate + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return a.rotateCredential(cmd.Context(), key) },
		})
		// Root-level alias under vault for backward compatibility.
		cmd.AddCommand(&cobra.Command{
			Use:    key,
			Hidden: true,
			Short:  prefixRotate + key,
			RunE:   func(cmd *cobra.Command, args []string) error { return a.rotateCredential(cmd.Context(), key) },
		})
	}
	cmd.AddCommand(rotateCmd)

	reconcileCmd := &cobra.Command{Use: "reconcile", Short: "Push a Vault-stored credential out to a drifted live service"}
	for _, cred := range a.credentials {
		key := cred.Key
		reconcileCmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: prefixReconcile + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return a.reconcileCredential(cmd.Context(), key) },
		})
	}
	cmd.AddCommand(reconcileCmd)

	return cmd
}
