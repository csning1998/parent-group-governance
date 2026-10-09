
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.9.0"
    }
  }
  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/86417732/terraform/state/foundation-vault-bastion"
    lock_address   = "https://gitlab.com/api/v4/projects/86417732/terraform/state/foundation-vault-bastion/lock"
    unlock_address = "https://gitlab.com/api/v4/projects/86417732/terraform/state/foundation-vault-bastion/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

# The Bastion Vault. The .envrc of terraform/ supplies VAULT_ADDR and VAULT_CACERT, and the token helper file the root token.
provider "vault" {
  alias = "bastion"
}
