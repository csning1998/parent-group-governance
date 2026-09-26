
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
}

module "code_reviewer" {
  source    = "../../../../gitlab-ci-with-code-reviewer/terraform/modules/provisioner-code-reviewer"
  providers = { vault = vault.bastion }

  gitlab_project_id    = module.baseline.project_id
  legacy_alias_enabled = true
}
