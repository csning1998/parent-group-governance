
module "provisioner_gitlab_project" {
  # Resolves relative to the directory containing this file (terraform/layers/<this layer>),
  # two levels up to terraform/, then into modules/provisioner-gitlab-project.
  source = "../../modules/provisioner-gitlab-project"

  name         = "parent-group-governance"
  description  = "Centralized gateway for all personal projects, including production-grade platform engineering."
  visibility   = var.gitlab_project.visibility
  namespace_id = data.terraform_remote_state.foundation_group.outputs.group_id

  only_allow_merge_if_pipeline_succeeds = false
  inbound_job_token_scope_project_ids   = var.inbound_job_token_scope_project_ids
}

module "workload_identity_federation" {
  source = "../../modules/provisioner-workload-identity-federation"

  gitlab_project = {
    id   = module.provisioner_gitlab_project.project_id
    path = module.provisioner_gitlab_project.full_path
    code = "parent-group-governance"
  }

  anthropic_federation = {
    issuer_id       = local.state.group_ai_provider_anthropic.issuers.gitlab_saas.id
    organization_id = local.state.group_ai_provider_anthropic.organization.id
  }

  google_federation = {
    project_id     = local.state.group_ai_provider_google_cloud.project.id
    project_number = local.state.group_ai_provider_google_cloud.project.number
    pool_id        = local.state.group_ai_provider_google_cloud.pool.id
    provider_id    = local.state.group_ai_provider_google_cloud.provider.id
  }

  azure_federation = {
    tenant_id            = local.state.group_ai_provider_azure.tenant.id
    subscription_id      = local.state.group_ai_provider_azure.subscription.id
    cognitive_account_id = local.state.group_ai_provider_azure.openai.id
    openai_endpoint      = local.state.group_ai_provider_azure.openai.endpoint
    subjects = [
      "project_path:${module.provisioner_gitlab_project.full_path}:ref_type:branch:ref:main",
      "project_path:${module.provisioner_gitlab_project.full_path}:ref_type:branch:ref:refactor/google-cloud-platform",
    ]
  }
}

module "code_reviewer" {
  source    = "gitlab.com/csning1998-lab/provisioner-code-reviewer/gitlab"
  version   = "~> 1.7.4"
  providers = { vault = vault.bastion }

  gitlab_project_id    = module.provisioner_gitlab_project.project_id
  legacy_alias_enabled = true
}

module "github_mirror" {
  source = "../../modules/provisioner-github-mirror"

  gitlab_project_id = module.provisioner_gitlab_project.project_id

  github_repository = {
    name  = "parent-group-governance"
    owner = var.github_owner
  }
}
