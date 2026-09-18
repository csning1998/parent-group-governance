
locals {
  state_auth_gitlab_saas = {
    username = "oauth2"
    password = local.read_bastion_ca_from_state ? (
      var.gitlab_ci_remote_state_read_token != null ? var.gitlab_ci_remote_state_read_token : jsondecode(file(pathexpand("~/.terraform.d/credentials.tfrc.json"))).credentials["gitlab.com"].token
    ) : ""
  }
}

# Use the following source of truth for every layer which includes foundation-vault-bastion.
output "bastion_vault_config" {
  description = "Reads the endpoint and CA cert path of the Bastion Vault."
  value = {
    endpoint     = coalesce(var.bastion_vault_config.endpoint, "https://172.16.0.1:8200")
    ca_cert_path = coalesce(var.bastion_vault_config.ca_cert_path, try(local_file.bastion_ca_cert[0].filename, null))
    token_path   = coalesce(var.bastion_vault_config.token_path, trimspace(file(pathexpand("~/.vault-token"))))
  }
}

# terraform_remote_state HTTP backend auth. Uses read_api CLI credentials to avoid
# persisting a higher-privilege token in the state of a consuming layer.
output "state_auth_gitlab_saas" {
  value     = local.state_auth_gitlab_saas
  sensitive = true
}
