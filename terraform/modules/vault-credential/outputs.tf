
output "path" {
  description = "Vault KV mount-relative path for cross-layer ephemeral reads"
  value       = vault_kv_secret_v2.this.name
}

output "credentials" {
  # Callers must never reference this output in a non-sensitive context, such
  # as a tag value. On Terraform versions before 1.5, a module output's
  # sensitive marking does not propagate to the calling module's own state.
  description = "All credentials (generated + static) keyed by name"
  value = merge(
    var.static,
    { for k, v in random_password.this : k => v.result }
  )
  sensitive = true
}
