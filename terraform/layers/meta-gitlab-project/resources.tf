
module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"
}

module "baseline" {
  # Resolves relative to the directory containing this file (terraform/layers/<this layer>),
  # two levels up to terraform/, then into modules/provisioner-gitlab-project.
  source = "../../modules/provisioner-gitlab-project"

  name         = "parent-group-governance"
  description  = "Centralized gateway for all personal projects, including production-grade platform engineering."
  visibility   = "private"
  namespace_id = data.terraform_remote_state.foundation_group.outputs.group_id

  only_allow_merge_if_pipeline_succeeds = false
  inbound_job_token_scope_project_ids   = var.inbound_job_token_scope_project_ids
}

module "workload_identity_federation" {
  source = "../../modules/provisioner-workload-identity-federation"

  providers = {
    vault = vault.bastion
  }

  gitlab_project = {
    id   = module.baseline.project_id
    path = module.baseline.full_path
    code = "parent-group-governance"
  }

  anthropic_federation = {
    issuer_id       = data.terraform_remote_state.group_federation_anthropic.outputs.issuers.gitlab_saas.id
    organization_id = data.terraform_remote_state.group_federation_anthropic.outputs.organization.id
  }

  google_federation = {
    project_id     = data.terraform_remote_state.group_federation_gcp.outputs.project.id
    project_number = data.terraform_remote_state.group_federation_gcp.outputs.project.number
    pool_id        = data.terraform_remote_state.group_federation_gcp.outputs.pool.id
    provider_id    = data.terraform_remote_state.group_federation_gcp.outputs.provider.id
  }

  azure_federation = {
    tenant_id            = data.terraform_remote_state.group_federation_azure.outputs.tenant.id
    subscription_id      = data.terraform_remote_state.group_federation_azure.outputs.subscription.id
    cognitive_account_id = data.terraform_remote_state.group_federation_azure.outputs.openai.id
    openai_endpoint      = data.terraform_remote_state.group_federation_azure.outputs.openai.endpoint
    subjects = [
      "project_path:${module.baseline.full_path}:ref_type:branch:ref:main",
      "project_path:${module.baseline.full_path}:ref_type:branch:ref:refactor/google-cloud-platform",
    ]
  }
}

module "code_reviewer" {
  source    = "../../../../gitlab-ci-with-code-reviewer/terraform/modules/provisioner-code-reviewer"
  providers = { vault = vault.bastion }

  gitlab_project_id    = module.baseline.project_id
  legacy_alias_enabled = true
}
