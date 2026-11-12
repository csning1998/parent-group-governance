
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.40.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "5.13.0"
    }
  }

  # The .envrc of the layer supplies TF_HTTP_ADDRESS, TF_HTTP_LOCK_ADDRESS, and TF_HTTP_UNLOCK_ADDRESS.
  backend "http" {
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

provider "google" {
  project = var.gcp_project_id
}

# The Bastion Vault. The .envrc of the layer supplies VAULT_ADDR, VAULT_CACERT, and the credential of the identity.
provider "vault" {
  alias = "bastion"
}
