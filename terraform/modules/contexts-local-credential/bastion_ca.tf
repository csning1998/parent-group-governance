
locals {
  # foundation-vault-bastion sets ca_cert_path explicitly. Every other caller leaves ca_cert_path
  # null and reads the live cert from the state of foundation-vault-bastion below.
  read_bastion_ca_from_state = var.bastion_vault_config.ca_cert_path == null
  bastion_ca_from_state      = local.read_bastion_ca_from_state ? data.terraform_remote_state.foundation_vault_bastion[0].outputs[var.bastion_vault_state.output_name][var.bastion_vault_state.attribute] : null
}

data "terraform_remote_state" "foundation_vault_bastion" {
  count   = local.read_bastion_ca_from_state ? 1 : 0
  backend = "http"
  config = {
    address = "https://gitlab.com/api/v4/projects/${var.bastion_vault_state.project_id}/terraform/state/${var.bastion_vault_state.state_name}"
  }
}

# Regenerated from live state on every apply. Decouples the Bastion Vault CA rotation cycle
# from the release version of this module.
resource "local_file" "bastion_ca_cert" {
  count                = local.read_bastion_ca_from_state ? 1 : 0
  content              = local.bastion_ca_from_state
  filename             = "${path.cwd}/tls/bastion-ca.pem"
  file_permission      = "0644"
  directory_permission = "0755"

  lifecycle {
    precondition {
      condition     = can(regex("-----BEGIN CERTIFICATE-----", local.bastion_ca_from_state))
      error_message = "bastion_vault_state.output_name and attribute resolved to empty or non-PEM content. Refusing to overwrite the existing CA certificate file with this value."
    }
  }
}
