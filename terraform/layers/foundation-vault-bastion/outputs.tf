
# Every output is a category object of the Bastion Vault. A consumer reads one attribute of an object.
output "vault_bastion" {
  description = "Connection facts of the Bastion Vault instance."
  value = {
    endpoint             = local.vault_bastion_endpoint
    listener_ca_cert_pem = local.vault_bastion_listener_ca_bundle_pem
  }
}

output "vault_bastion_pki" {
  description = "Certificate chain and mount path of the Bastion Vault PKI hierarchy."
  value = {
    root_certs = {
      for algo, cert in vault_pki_secret_backend_root_cert.root : algo => cert.certificate
    }
    constrained_intermediates = {
      for name, mount in vault_mount.pki_constrained : name => {
        owner      = local.constrained_intermediates[name].owner
        root_ca_id = local.constrained_intermediates[name].root_ca_id
        mount_path = mount.path
        issuer_certs = {
          for algo_key, _ in local.constrained_intermediate_algorithms : algo_key => vault_pki_secret_backend_root_sign_intermediate.pki_constrained_signed["${name}/${algo_key}"].certificate
        }
      }
    }
  }
}

output "vault_bastion_auth" {
  description = "Mount paths of the auth backends of the Bastion Vault."
  value = {
    approle_mount_path                         = vault_auth_backend.approle.path
    gitlab_saas_ci_job_jwt_provider_mount_path = vault_jwt_auth_backend.gitlab_saas.path
  }
}

output "vault_bastion_tenant" {
  description = "Owner codes of the tenants registered on the Bastion Vault, and the operator cert role of each tenant keyed by owner code. The operator Vault Proxy of a tenant logs in through the operator cert role."
  value = {
    owner_codes   = keys(local.tenants)
    operator_role = { for code, role in vault_cert_auth_backend_role.operator : code => role.name if contains(keys(local.tenants), code) }
  }
}

output "vault_bastion_registry" {
  description = "Mount of the registry which publishes tenant facts, and the read only policy of each tenant keyed by owner code. A tenant role references the policy. The tenant role cannot rewrite the policy."
  value = {
    mount_path      = vault_mount.registry.path
    reader_policies = { for code, policy in vault_policy.registry_reader : code => policy.name }
  }
}

output "vault_bastion_transit_unseal" {
  description = "Transit mount, and the key and the policy of every auto unsealing Vault cluster keyed by consumer. A tenant role references the policy. The tenant role cannot rewrite the policy."
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
