
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.13.0"
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
  # State and lock URLs are omitted to avoid hardcoding the GitLab project ID in HCL. The layer .envrc supplies
  # TF_HTTP_ADDRESS, TF_HTTP_LOCK_ADDRESS, and TF_HTTP_UNLOCK_ADDRESS.
  backend "http" {
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

# The Bastion Vault. The .envrc of terraform/ supplies VAULT_ADDR and VAULT_CACERT, and the token helper file the root token.
provider "vault" {
  alias = "bastion"
}
