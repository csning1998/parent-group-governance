
module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"

  # This layer is the true source. The module default reads state from this layer via terraform_remote_state.
  # This override avoids a self-referential state read.
  bastion_vault_config = {
    ca_cert_path = "${path.root}/../../../vault/tls/ca.pem"
  }
}

locals {
  bastion_pki_intermediate_mount_path = var.pki_intermediate_mount_path
}

data "local_file" "bastion_vault_ca" {
  filename = module.local_credential_contexts.bastion_vault_config.ca_cert_path
}

locals {
  gitlab_saas_jwt_mount_path = "gitlab-saas-ci-job-jwt-provider"
}
