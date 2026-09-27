
variable "azure_tenant_id" {
  description = "Target Microsoft Entra ID tenant identifier."
  type        = string
  default     = null
}

variable "azure_subscription_id" {
  description = "Target Azure subscription identifier hosting cognitive services."
  type        = string
  default     = null
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group hosting Azure OpenAI resources."
  type        = string
}

variable "location" {
  description = "Azure region hosting OpenAI cognitive services."
  type        = string
}

variable "cognitive_account_name" {
  description = "Name of the Azure OpenAI Cognitive Services account."
  type        = string
}

variable "sku_name" {
  description = "SKU tier for the Azure OpenAI Cognitive Services account."
  type        = string
  default     = "S0"
}

variable "is_premium_tier" {
  description = "Enables the premium Key Vault SKU, an HSM key, and private endpoints. False keeps the free tier."
  type        = bool
  default     = false
}

variable "virtual_network_address_space" {
  description = "IPv4 address space of the virtual network which hosts private endpoints. The premium tier consumes this value."
  type        = list(string)

  validation {
    condition = alltrue([
      for cidr in var.virtual_network_address_space : can(cidrhost(cidr, 0))
    ])
    error_message = "virtual_network_address_space must contain IPv4 CIDR blocks."
  }
}

variable "private_endpoint_subnet_prefix" {
  description = "IPv4 prefix of the subnet which hosts private endpoints. The premium tier consumes this value."
  type        = string

  validation {
    condition     = can(cidrhost(var.private_endpoint_subnet_prefix, 0))
    error_message = "private_endpoint_subnet_prefix must be an IPv4 CIDR block."
  }
}

variable "key_vault_ip_rules" {
  description = "IPv4 addresses or CIDR blocks which can call the Key Vault data plane and the cognitive account data plane on the free tier. The list contains the workstation public egress address. The group GitLab runner uses the same address."
  type        = list(string)

  validation {
    condition = length(var.key_vault_ip_rules) > 0 && alltrue([
      for rule in var.key_vault_ip_rules : can(cidrhost(rule, 0)) || can(cidrhost("${rule}/32", 0))
    ])
    error_message = "key_vault_ip_rules must contain at least one IPv4 address or CIDR block."
  }
}

variable "cmk_expiration_date" {
  description = "RFC3339 expiration timestamp for the customer managed key."
  type        = string

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$", var.cmk_expiration_date))
    error_message = "cmk_expiration_date must be an RFC3339 UTC timestamp."
  }
}
