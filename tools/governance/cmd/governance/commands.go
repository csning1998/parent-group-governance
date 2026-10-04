package main

import "github.com/spf13/cobra"

func (a *app) newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "vault", Short: "Bastion Vault operations"}

	cmd.AddCommand(&cobra.Command{
		Use:   "tls-generate",
		Short: "[Vault] Generate TLS certificates for Bastion Vault (destroys existing files)",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.generateVaultTLS(cmd.Context()) },
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
		Use:   "tenant-session <tenant>",
		Short: "[Vault] Open a shell holding a tenant operator token, revoked on exit",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return a.runTenantSession(cmd.Context(), args[0]) },
	})
	for _, cred := range a.credentials {
		key := cred.Key
		cmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: "Rotate " + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return a.rotateCredential(cmd.Context(), key) },
		})
	}

	reconcileCmd := &cobra.Command{Use: "reconcile", Short: "Push a Vault-stored credential out to a drifted live service"}
	for _, cred := range a.credentials {
		key := cred.Key
		reconcileCmd.AddCommand(&cobra.Command{
			Use:   key,
			Short: "Reconcile " + key,
			RunE:  func(cmd *cobra.Command, args []string) error { return a.reconcileCredential(cmd.Context(), key) },
		})
	}
	cmd.AddCommand(reconcileCmd)

	return cmd
}

func (a *app) newAnsibleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ansible", Short: "Host Ansible operations"}
	cmd.AddCommand(&cobra.Command{
		Use:   "selinux",
		Short: "[Hypervisor] Apply workstation SELinux policy and file contexts",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.runHostSELinuxPlaybook(cmd.Context()) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "libvirt",
		Short: "[Hypervisor] Apply workstation Libvirt network and Bastion Vault host prerequisites",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.runHostLibvirtPlaybook(cmd.Context()) },
	})
	return cmd
}

func (a *app) newEnvCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "env", Short: "Environment verification"}
	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "[Hypervisor] Verify Terraform, Vault, and Ansible on PATH",
		RunE:  func(cmd *cobra.Command, args []string) error { return a.verifyEnvironment() },
	})
	return cmd
}
