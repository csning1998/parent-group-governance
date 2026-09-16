
output "secret" {
  description = "Provides the secret path coordinates and sensitive credentials map."
  value = {
    mount = var.vault_credential_context.vault_kv_mount
    path  = vault_kv_secret_v2.this.name
    data = merge(
      var.vault_credential_context.static,
      { for k, v in random_password.this : k => v.result }
    )
  }
  sensitive = true
}
