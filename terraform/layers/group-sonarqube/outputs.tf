
output "secret_mount" {
  description = "Vault KV v2 mount point holding the SonarQube analysis token."
  value       = vault_kv_secret_v2.sonar_token.mount
}

output "secret_name" {
  description = "Vault KV v2 secret name holding the SonarQube analysis token."
  value       = vault_kv_secret_v2.sonar_token.name
}
