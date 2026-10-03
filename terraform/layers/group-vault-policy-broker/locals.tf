module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"
}

locals {
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
  _state_auth = module.local_credential_contexts.state_auth_gitlab_saas
}

locals {
  bastion        = data.terraform_remote_state.foundation_vault_bastion.outputs
  owner_codes    = local.bastion.bastion_vault_tenant.owner_codes
  policy_request = local.bastion.bastion_vault_tenant.policy_request
  pki_mount      = local.bastion.bastion_vault_pki.intermediate_mount_path
  approle_mount  = local.bastion.bastion_vault_auth.approle_mount_path
  gitlab_mount   = local.bastion.bastion_vault_auth.gitlab_saas_ci_job_jwt_provider_mount_path

  # A tenant role MAY carry the registry reader policy of the tenant.
  registry_reader_policies = {
    for code in local.owner_codes : code => [local.bastion.bastion_vault_registry.reader_policies[code]]
  }

  # A tenant role MAY carry the transit unseal policy of a consumer which the tenant owns.
  transit_unseal_policies = {
    for code in local.owner_codes : code => sort([
      for consumer in values(local.bastion.bastion_vault_transit_unseal.consumers) : consumer.policy_name if consumer.owner == code
    ])
  }
}
