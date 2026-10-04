# Each key is an owner code, and executing_repository names the repository running the Terraform of that tenant.
locals {
  tenants = {
    "meta-platform" = { executing_repository = "meta-platform" }
  }

  # The Bastion Vault listens on loopback and on the first host of the publish network, hence a leaked secret ID or
  # tenant token fails from any other address.
  tenant_operator_source_cidrs = ["127.0.0.1/32", "${cidrhost(local.platform_trust.bastion_publish_cidr, 1)}/32"]
}

# architecture-naming-standard.md Section 4 Item F: Vault ACL grants by prefix, hence no owner code followed by a
# hyphen may prefix another owner code. A precondition stops the plan, while a failed check block only warns.
resource "terraform_data" "tenant_owner_codes_validation" {
  input = keys(local.tenants)

  lifecycle {
    precondition {
      condition = alltrue([
        for a in keys(local.tenants) : alltrue([
          for b in keys(local.tenants) : a == b || !startswith(b, "${a}-")
        ])
      ])
      error_message = "An owner code followed by a hyphen prefixes another owner code."
    }
  }
}

resource "vault_policy" "tenant_terraform_operator" {
  for_each   = local.tenants
  depends_on = [terraform_data.tenant_owner_codes_validation]

  provider = vault.bastion
  name     = "${each.key}-terraform-operator"
  policy   = jsonencode(local.tenant_acl_document[each.key])
}

# `./governance vault tenant-session` mints each secret ID wrapped for one login, hence no secret ID enters a state.
# The role caps every secret ID at one use and 60 seconds, which also binds a secret ID minted by hand.
resource "vault_approle_auth_backend_role" "tenant_terraform_operator" {
  for_each = local.tenants

  provider       = vault.bastion
  backend        = vault_auth_backend.approle.path
  role_name      = "${each.key}-terraform-operator"
  token_policies = [vault_policy.tenant_terraform_operator[each.key].name, vault_policy.registry_reader[each.key].name]
  token_ttl      = 60 * 60
  token_max_ttl  = 60 * 60 * 4

  secret_id_num_uses    = 1
  secret_id_ttl         = 60
  token_bound_cidrs     = local.tenant_operator_source_cidrs
  secret_id_bound_cidrs = local.tenant_operator_source_cidrs
}
