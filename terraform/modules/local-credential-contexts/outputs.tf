
# Every layer, foundation-vault-bastion included, connects to this single Bastion Vault and
# reads the address from here instead of redeclaring the default.
output "bastion_vault_endpoint" {
  value = "https://172.16.0.1:8200"
}

# Resolves the Bastion Vault CA certificate path relative to path.module for local or Git source invocations.
# Registry module consumers MUST supply var.vault_ca_cert_path to override default relative path resolution.
output "bastion_vault_ca_cert_path" {
  value = coalesce(var.vault_ca_cert_path, abspath("${path.module}/../../../vault/tls/ca.pem"))
}

# Reads Vault token directly from host token-helper file to break cyclic authentication dependencies during initialization.
output "vault_token" {
  value     = trimspace(file(pathexpand("~/.vault-token")))
  sensitive = true
}

# terraform_remote_state HTTP backend auth. Uses read_api CLI credentials to avoid
# persisting a higher-privilege token in the state of a consuming layer.
output "gl_state_auth" {
  value = {
    username = "oauth2"
    password = jsondecode(file(pathexpand("~/.terraform.d/credentials.tfrc.json"))).credentials["gitlab.com"].token
  }
  sensitive = true
}
