
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/terraform/state-backend"
}

data "terraform_remote_state" "group_topology" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-topology" })
}
