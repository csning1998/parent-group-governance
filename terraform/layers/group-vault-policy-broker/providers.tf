terraform {
  required_version = ">= 1.14.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.5.0"
    }
  }

  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-vault-policy-broker"
    lock_address   = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-vault-policy-broker/lock"
    unlock_address = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-vault-policy-broker/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

provider "vault" {
  alias        = "bastion"
  address      = module.local_credential_contexts.bastion_vault_config.endpoint
  ca_cert_file = module.local_credential_contexts.bastion_vault_config.ca_cert_path
}
