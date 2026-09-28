# Each key is an owner code, and executing_repository names the repository running the Terraform of that tenant.
locals {
  tenants = {
    "meta-platform" = { executing_repository = "meta-platform" }
  }
}

resource "vault_policy" "tenant_terraform_operator" {
  for_each = local.tenants

  provider = vault.bastion
  name     = "${each.key}-terraform-operator"
  policy   = local.tenant_acl_policy[each.key]
}

resource "vault_approle_auth_backend_role" "tenant_terraform_operator" {
  for_each = local.tenants

  provider       = vault.bastion
  backend        = vault_auth_backend.approle.path
  role_name      = "${each.key}-terraform-operator"
  token_policies = [vault_policy.tenant_terraform_operator[each.key].name]
  token_ttl      = 60 * 60
  token_max_ttl  = 60 * 60 * 4
}

resource "vault_approle_auth_backend_role_secret_id" "tenant_terraform_operator" {
  for_each = local.tenants

  provider  = vault.bastion
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.tenant_terraform_operator[each.key].role_name
}

resource "vault_kv_secret_v2" "tenant_terraform_operator_login" {
  for_each = local.tenants

  provider = vault.bastion
  mount    = "secret"
  name     = "${each.key}/terraform/approle"
  data_json = jsonencode({
    role_id   = vault_approle_auth_backend_role.tenant_terraform_operator[each.key].role_id
    secret_id = vault_approle_auth_backend_role_secret_id.tenant_terraform_operator[each.key].secret_id
  })
}
