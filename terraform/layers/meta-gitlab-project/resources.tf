
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/state-backend"
}

data "terraform_remote_state" "foundation_group" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-foundation" })
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
}

module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"
}

locals {
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
  _state_auth = module.local_credential_contexts.state_auth_gitlab_saas
}
