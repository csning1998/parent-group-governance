
# Every layer, foundation-vault-bastion included, connects to this single Bastion Vault and
# reads the address from here instead of redeclaring the default.
output "bastion_vault_endpoint" {
  value = "https://172.16.0.1:8200"
}

# path.root always resolves to the root of the calling layer, never to the directory of
# this module. This stays correct from every layer despite being computed here.
output "bastion_vault_ca_cert_path" {
  value = abspath("${path.root}/../../../vault/tls/ca.pem")
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
