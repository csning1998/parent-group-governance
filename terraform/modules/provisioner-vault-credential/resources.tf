
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

locals {
  # Only the key set needs to be nonsensitive, to satisfy for_each. The length/special values
  # stay sensitive and are read back from the original object inside the resource block.
  generate_keys = toset(nonsensitive(keys(var.vault_credential_context.generate)))
}

resource "random_password" "this" {
  for_each = local.generate_keys

  length      = var.vault_credential_context.generate[each.key].length
  special     = var.vault_credential_context.generate[each.key].special
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
  min_special = var.vault_credential_context.generate[each.key].special ? 1 : 0
}

resource "vault_kv_secret_v2" "this" {
  mount = var.vault_credential_context.kv_mount
  name  = "${var.vault_credential_context.kv_namespace}/${var.vault_credential_context.domain}/${var.vault_credential_context.component}"

  data_json = jsonencode(merge(
    var.vault_credential_context.static,
    { for k, v in random_password.this : k => v.result }
  ))
}
