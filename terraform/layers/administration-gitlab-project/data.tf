
locals {
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
}

locals {
  state = {
    group_ai_provider_anthropic    = data.terraform_remote_state.group_ai_provider_anthropic.outputs
    group_ai_provider_google_cloud = data.terraform_remote_state.group_ai_provider_google_cloud.outputs
    group_ai_provider_azure        = data.terraform_remote_state.group_ai_provider_azure.outputs
  }
}

data "terraform_remote_state" "foundation_group" {
  backend = "http"
  config  = { address = "${local._state_base}/group-foundation" }
}

data "terraform_remote_state" "group_ai_provider_anthropic" {
  backend = "http"
  config  = { address = "${local._state_base}/group-ai-provider-anthropic" }
}

data "terraform_remote_state" "group_ai_provider_google_cloud" {
  backend = "http"
  config  = { address = "${local._state_base}/group-ai-provider-google-cloud" }
}

data "terraform_remote_state" "group_ai_provider_azure" {
  backend = "http"
  config  = { address = "${local._state_base}/group-ai-provider-azure" }
}

ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/terraform/state-backend"
}

ephemeral "vault_kv_secret_v2" "anthropic_console" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/ai-provider-console/anthropic"
}

ephemeral "vault_kv_secret_v2" "github_publication" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/github/publication"
}
