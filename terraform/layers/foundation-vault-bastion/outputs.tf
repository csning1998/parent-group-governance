
# Every output is a category object of the Bastion Vault. A consumer reads one attribute of an object.
output "bastion_vault" {
  description = "Connection facts of the Bastion Vault instance."
  value = {
    endpoint              = module.local_credential_contexts.bastion_vault_config.endpoint
    listener_ca_cert_path = abspath(local_file.bastion_vault_ca_copy.filename)
    listener_ca_cert_pem  = data.local_file.bastion_vault_ca.content
  }
}

output "bastion_vault_pki" {
  description = "Certificate chain and mount path of the Bastion Vault PKI hierarchy."
  value = {
    root_cert_pem           = vault_pki_secret_backend_root_cert.root.certificate
    intermediate_cert_pem   = vault_pki_secret_backend_root_sign_intermediate.pki_intermediate_signed.certificate
    intermediate_mount_path = vault_mount.pki_intermediate.path
  }
}

output "bastion_vault_auth" {
  description = "Mount paths of the auth backends of the Bastion Vault."
  value = {
    approle_mount_path                         = vault_auth_backend.approle.path
    gitlab_saas_ci_job_jwt_provider_mount_path = vault_jwt_auth_backend.gitlab_saas.path
  }
}

output "bastion_vault_tenant" {
  description = "Owner codes of the tenants registered on the Bastion Vault, and the AppRole identity with which the Terraform operator of each tenant logs in to the Bastion Vault, keyed by owner code."
  value = {
    owner_codes = keys(local.tenants)
    terraform_operator = {
      role_names = { for code, role in vault_approle_auth_backend_role.tenant_terraform_operator : code => role.role_name }
      role_ids   = { for code, role in vault_approle_auth_backend_role.tenant_terraform_operator : code => role.role_id }
    }
  }
}

output "bastion_vault_tenant_credential" {
  description = "AppRole secret ID with which the Terraform operator of each Bastion Vault tenant logs in to the Bastion Vault, keyed by owner code."
  value = {
    terraform_operator = {
      secret_ids = { for code, secret in vault_approle_auth_backend_role_secret_id.tenant_terraform_operator : code => secret.secret_id }
    }
  }
  sensitive = true
}

# Intentional: this object stays available for re-provisioning after the tenant model is in place.
output "bastion_vault_terraform_admin" {
  description = "AppRole identity with which the Terraform admin logs in to the Bastion Vault."
  value = {
    role_name = vault_approle_auth_backend_role.terraform_admin.role_name
    role_id   = vault_approle_auth_backend_role.terraform_admin.role_id
    secret_id = vault_approle_auth_backend_role_secret_id.terraform_admin.secret_id
  }
  sensitive = true
}
