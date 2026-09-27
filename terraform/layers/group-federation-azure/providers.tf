
terraform {
  required_version = ">= 1.14.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "3.10.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.7.0"
    }
  }

  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-federation-azure"
    lock_address   = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-federation-azure/lock"
    unlock_address = "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-federation-azure/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}

provider "azuread" {
  tenant_id = var.azure_tenant_id
}

provider "azurerm" {
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
  features {}
}
