# Each key is an owner code, and executing_repository names the repository running the Terraform of that tenant.
locals {
  tenants = {
    "meta-platform" = { executing_repository = "meta-platform" }
  }

  # The Bastion Vault listens on 127.0.0.1 and 172.16.0.1 in the host network, hence a leaked secret ID or tenant
  # token fails from any other address.
  tenant_operator_source_cidrs = ["127.0.0.1/32", "172.16.0.1/32"]

  # The tenant writes the requested policies to this KV v2 secret, and group-vault-policy-broker writes the policies.
  policy_request_mount = "secret"
  policy_request_names = { for code in keys(local.tenants) : code => "${code}/vault-policy-requests" }
}

# architecture-naming-standard.md Section 4 Item F: Vault ACL grants by prefix, hence no owner code followed by a
# hyphen may prefix another owner code.
check "tenant_owner_codes_exclusive" {
  assert {
    condition = alltrue([
      for a in keys(local.tenants) : alltrue([
        for b in keys(local.tenants) : a == b || !startswith(b, "${a}-")
      ])
    ])
    error_message = "An owner code followed by a hyphen prefixes another owner code."
  }
}

# The broker always reads the request secret, since this layer creates the secret before any tenant request.
resource "vault_kv_secret_v2" "tenant_policy_request" {
  for_each = local.tenants

  provider  = vault.bastion
  mount     = local.policy_request_mount
  name      = local.policy_request_names[each.key]
  data_json = jsonencode({})

  lifecycle {
    ignore_changes = [data_json]
  }
}

# group-vault-policy-broker writes the tenant ACL under this name, since the ACL lists the exact assignable policy names.
# The removal keeps the policy in the Bastion Vault during the broker takeover.
removed {
  from = vault_policy.tenant_terraform_operator

  lifecycle {
    destroy = false
  }
}

# `./governance vault tenant-session` mints each secret ID wrapped for one login, hence no secret ID enters a state.
# The role caps every secret ID at one use and 60 seconds, which also binds a secret ID minted by hand.
resource "vault_approle_auth_backend_role" "tenant_terraform_operator" {
  for_each = local.tenants

  provider       = vault.bastion
  backend        = vault_auth_backend.approle.path
  role_name      = "${each.key}-terraform-operator"
  token_policies = ["${each.key}-terraform-operator", vault_policy.registry_reader[each.key].name]
  token_ttl      = 60 * 60
  token_max_ttl  = 60 * 60 * 4

  secret_id_num_uses    = 1
  secret_id_ttl         = 60
  token_bound_cidrs     = local.tenant_operator_source_cidrs
  secret_id_bound_cidrs = local.tenant_operator_source_cidrs
}
