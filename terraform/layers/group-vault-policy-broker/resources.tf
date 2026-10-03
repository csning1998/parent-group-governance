
# A single violation blocks every write. The Bastion Vault therefore never holds a partial set of tenant policies.
resource "terraform_data" "request_validation" {
  input = local.violations

  lifecycle {
    precondition {
      condition     = length(local.violations) == 0
      error_message = "The policy requests violate the tenant scope:\n${join("\n", local.violations)}"
    }
  }
}

resource "vault_policy" "tenant_terraform_operator" {
  for_each   = toset(local.owner_codes)
  depends_on = [terraform_data.request_validation]

  provider = vault.bastion
  name     = "${each.key}-terraform-operator"
  policy   = jsonencode(local.tenant_acl_document[each.key])
}

resource "vault_policy" "brokered" {
  for_each   = local.brokered
  depends_on = [terraform_data.request_validation]

  provider = vault.bastion
  name     = each.key
  policy   = jsonencode(each.value.document)
}
