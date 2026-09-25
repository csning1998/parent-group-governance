
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    anthropic = {
      source  = "ippontech/anthropic"
      version = "1.43.5"
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

provider "anthropic" {}
