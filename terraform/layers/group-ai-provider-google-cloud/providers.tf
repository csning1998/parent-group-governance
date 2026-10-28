
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.40.0"
    }
  }

  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-ai-provider-google-cloud"
    lock_address   = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-ai-provider-google-cloud/lock"
    unlock_address = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-ai-provider-google-cloud/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

provider "google" {
  project = var.gcp_project_id
}
