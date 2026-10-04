
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
    constrained_intermediates = {
      for name, mount in vault_mount.pki_constrained : name => {
        owner      = local.constrained_intermediates[name].owner
        mount_path = mount.path
        cert_pem   = vault_pki_secret_backend_root_sign_intermediate.pki_constrained_signed[name].certificate
      }
    }
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
  description = "Owner codes of the tenants registered on the Bastion Vault, the KV v2 secret to which each tenant writes its policy requests, and the AppRole identity with which the Terraform operator of each tenant logs in to the Bastion Vault, keyed by owner code."
  value = {
    owner_codes = keys(local.tenants)
    terraform_operator = {
      role_names = { for code, role in vault_approle_auth_backend_role.tenant_terraform_operator : code => role.role_name }
      role_ids   = { for code, role in vault_approle_auth_backend_role.tenant_terraform_operator : code => role.role_id }
    }
  }
}

output "bastion_vault_registry" {
  description = "Mount of the registry which publishes tenant facts, and the read-only policy of each tenant, keyed by owner code. A tenant role references the policy and cannot rewrite the policy."
  value = {
    mount_path      = vault_mount.registry.path
    reader_policies = { for code, policy in vault_policy.registry_reader : code => policy.name }
  }
}

output "bastion_vault_transit_unseal" {
  description = "Transit mount, and the key and the policy of every auto-unsealing Vault cluster, keyed by consumer. A tenant role references the policy and cannot rewrite the policy."
  value = {
    mount_path = vault_mount.transit_unseal.path
    consumers = {
      for name, consumer in local.transit_unseal_consumers : name => {
        owner       = consumer.owner
        key_name    = vault_transit_secret_backend_key.transit_unseal[name].name
        policy_name = vault_policy.transit_unseal[name].name
      }
    }
  }
}
