
data "terraform_remote_state" "foundation_vault_bastion" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/foundation-vault-bastion" })
}

# The policy request of each tenant maps a policy name to a Vault policy document in JSON.
data "vault_generic_secret" "policy_request" {
  for_each = toset(local.owner_codes)

  provider = vault.bastion
  path     = "${local.policy_request.mount}/${local.policy_request.names[each.key]}"
}
