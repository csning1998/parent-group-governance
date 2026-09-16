
terraform {
  required_providers {
    vault = {
      source = "hashicorp/vault"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

resource "random_password" "this" {
  for_each = var.vault_credential_context.generate

  length      = each.value.length
  special     = each.value.special
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
  min_special = each.value.special ? 1 : 0
}

resource "vault_kv_secret_v2" "this" {
  mount = var.vault_credential_context.vault_kv_mount
  name  = "${var.vault_credential_context.namespace}/${var.vault_credential_context.domain}/${var.vault_credential_context.component}"

  data_json = jsonencode(merge(
    var.vault_credential_context.static,
    { for k, v in random_password.this : k => v.result }
  ))
}
