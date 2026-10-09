
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    anthropic = {
      source  = "ippontech/anthropic"
      version = "1.43.5"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "5.5.0"
    }
  }

  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-federation-anthropic"
    lock_address   = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-federation-anthropic/lock"
    unlock_address = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-federation-anthropic/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

provider "anthropic" {
  admin_api_key = ephemeral.vault_kv_secret_v2.anthropic_admin_key.data["anthropic_admin_api_key"]
}

# The Bastion Vault. The .envrc of the layer supplies VAULT_ADDR, VAULT_CACERT, and the credential of the identity.
provider "vault" {
  alias = "bastion"
}
