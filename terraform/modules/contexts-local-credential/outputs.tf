
# Use the following source of truth for every layer which includes foundation-vault-bastion.
output "bastion_vault_config" {
  description = "Reads the endpoint and CA cert path of the Bastion Vault."
  value = {
    endpoint     = coalesce(var.bastion_vault_config.endpoint, "https://172.16.0.1:8200")
    ca_cert_path = coalesce(var.bastion_vault_config.ca_cert_path, abspath("${path.module}/../../../vault/tls/ca.pem"))
    token_path   = coalesce(var.bastion_vault_config.token_path, trimspace(file(pathexpand("~/.vault-token"))))
  }
}

# terraform_remote_state HTTP backend auth. Uses read_api CLI credentials to avoid
# persisting a higher-privilege token in the state of a consuming layer.
output "_state_auth_gitlab_saas" {
  value = {
    username = "oauth2"
    password = jsondecode(file(pathexpand("~/.terraform.d/credentials.tfrc.json"))).credentials["gitlab.com"].token
  }
  sensitive = true
}
