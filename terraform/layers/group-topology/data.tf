
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/state-backend"
}

data "terraform_remote_state" "foundation_group" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-foundation" })
}
