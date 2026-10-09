
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    gitlab = {
      source  = "gitlabhq/gitlab"
      version = "19.2.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "5.5.0"
    }
  }

  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-topology"
    lock_address   = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-topology/lock"
    unlock_address = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-topology/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

provider "gitlab" {
  token = ephemeral.vault_kv_secret_v2.state_backend.data["token"]
}

# The Bastion Vault. The .envrc of the layer supplies VAULT_ADDR, VAULT_CACERT, and the credential of the identity.
provider "vault" {
  alias = "bastion"
}
