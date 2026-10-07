
locals {
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
}

data "terraform_remote_state" "foundation_group" {
  backend = "http"
  config  = { address = "${local._state_base}/group-foundation" }
}

data "terraform_remote_state" "group_federation_anthropic" {
  backend = "http"
  config  = { address = "${local._state_base}/group-federation-anthropic" }
}

data "terraform_remote_state" "group_federation_gcp" {
  backend = "http"
  config  = { address = "${local._state_base}/group-federation-gcp" }
}

data "terraform_remote_state" "group_federation_azure" {
  backend = "http"
  config  = { address = "${local._state_base}/group-federation-azure" }
}

ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/terraform/state-backend"
}

ephemeral "vault_kv_secret_v2" "anthropic_admin_key" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/ai-provider-console/anthropic"
}

ephemeral "vault_kv_secret_v2" "github_publication" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/github/publication"
}
