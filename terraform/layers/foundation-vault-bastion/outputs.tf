
output "role_id" {
  description = "The RoleID of the Terraform admin AppRole"
  value       = vault_approle_auth_backend_role.terraform_admin.role_id
}

output "secret_id" {
  description = "The SecretID of the Terraform admin AppRole"
  value       = vault_approle_auth_backend_role_secret_id.terraform_admin.secret_id
  sensitive   = true
}

output "approle_path" {
  description = "The path where AppRole auth is enabled"
  value       = vault_auth_backend.approle.path
}

output "role_name" {
  description = "The name of the AppRole"
  value       = vault_approle_auth_backend_role.terraform_admin.role_name
}

output "bastion_vault_endpoint" {
  description = "The address of the Vault server"
  value       = module.local_credential_contexts.bastion_vault_config.endpoint
}

output "bastion_vault_listener_ca_cert_path" {
  description = "Path to the Bastion Vault server's own listener TLS CA, for downstream layers connecting to this same Vault instance"
  value       = abspath(local_file.bastion_vault_ca_copy.filename)
}

output "bastion_vault_ca_cert_pem" {
  description = "PEM content of the Bastion Vault listener CA certificate, for contexts-local-credential to regenerate its own local copy from live state"
  value       = data.local_file.bastion_vault_ca.content
}

output "bastion_pki_root_cert_pem" {
  description = "Infrastructure Root CA certificate (PEM). Signs only the Bootstrap Issuing Intermediate."
  value       = vault_pki_secret_backend_root_cert.root.certificate
}

output "bastion_pki_inter_cert_pem" {
  description = "Bootstrap Issuing Intermediate CA certificate (PEM), signed by the Infrastructure Root CA."
  value       = vault_pki_secret_backend_root_sign_intermediate.pki_intermediate_signed.certificate
}

output "bastion_pki_inter_mount_path" {
  description = "Mount path of the Bootstrap Issuing Intermediate PKI engine, used by downstream layers to request bootstrap leaf certificates."
  value       = vault_mount.pki_intermediate.path
}

output "bastion_pki_intermediate_cert_pem" {
  description = "Bootstrap Issuing Intermediate CA certificate (PEM), signed by the Infrastructure Root CA."
  value       = vault_pki_secret_backend_root_sign_intermediate.pki_intermediate_signed.certificate
}

output "bastion_pki_intermediate_mount_path" {
  description = "Mount path of the Bootstrap Issuing Intermediate PKI engine."
  value       = vault_mount.pki_intermediate.path
}
