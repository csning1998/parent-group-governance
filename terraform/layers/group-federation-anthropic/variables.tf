
variable "anthropic_organization_id" {
  description = "Specifies the Anthropic organization identifier displayed by `ant auth status`. Direct configuration is required because the provider organization data source requires an Admin API key."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.anthropic_organization_id))
    error_message = "anthropic_organization_id must be a lowercase UUID."
  }
}
