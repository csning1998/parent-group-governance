
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    anthropic = {
      source  = "ippontech/anthropic"
      version = "1.43.5"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "3.10.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.7.0"
    }
    gitlab = {
      source  = "gitlabhq/gitlab"
      version = "19.2.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "8.4.0"
    }
  }
}
