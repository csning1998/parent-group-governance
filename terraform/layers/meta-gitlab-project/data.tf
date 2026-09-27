
locals {
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
  _state_auth = module.local_credential_contexts.state_auth_gitlab_saas
}

data "terraform_remote_state" "foundation_group" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-foundation" })
}

data "terraform_remote_state" "group_federation_anthropic" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-federation-anthropic" })
}

data "terraform_remote_state" "group_federation_gcp" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-federation-gcp" })
}

data "terraform_remote_state" "group_federation_azure" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-federation-azure" })
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
