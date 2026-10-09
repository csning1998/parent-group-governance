
# Each key is an owner code, and executing_repository names the repository running the Terraform of that tenant.
# The platform tenant code appears once, and every other declaration of this layer references it.
locals {
  platform_tenant = "platform-foundation"

  tenants = {
    (local.platform_tenant) = { executing_repository = local.platform_tenant }
  }
}

# Vault ACL grants by prefix, hence no owner code followed by a hyphen may prefix another owner code.
# A precondition stops the plan while a failed check block only warns.
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
