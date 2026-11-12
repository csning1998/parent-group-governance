
# Maps each tenant owner code to the repository executing its Terraform configurations.
# Centralizes platform_tenant for the ACL, PKI, and Transit unseal declarations of this layer.
locals {
  governance_owner = local.workstation.operator_vault_proxy.governance_owner_code
  platform_tenant  = "platform-foundation"

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
