
variable "gitlab_project" {
  description = "Specifies GitLab project metadata for workload identity federation bindings."
  type = object({
    id   = number
    path = string
    code = string
  })
}

variable "anthropic_federation" {
  description = "Specifies configuration for Anthropic Workload Identity Federation."
  type = object({
    issuer_id              = string
    organization_id        = string
    workspace_id           = optional(string)
    workspace_name         = optional(string)
    audience               = optional(string, "https://api.anthropic.com")
    oauth_scope            = optional(string, "workspace:inference")
    token_lifetime_seconds = optional(number, 600)
    organization_role      = optional(string, "developer")
  })
  default = null

  validation {
    condition     = var.anthropic_federation == null ? true : can(regex("^fdis_", var.anthropic_federation.issuer_id))
    error_message = "anthropic_federation.issuer_id must start with fdis_."
  }

  validation {
    condition     = var.anthropic_federation == null ? true : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.anthropic_federation.organization_id))
    error_message = "anthropic_federation.organization_id must be a lowercase UUID."
  }

  validation {
    condition     = var.anthropic_federation == null ? true : (var.anthropic_federation.workspace_id == null || var.anthropic_federation.workspace_id == "default" || can(regex("^wrkspc_", var.anthropic_federation.workspace_id)))
    error_message = "anthropic_federation.workspace_id must be null, default, or start with wrkspc_."
  }
}

variable "google_federation" {
  description = "Specifies configuration for Google Cloud Workload Identity Federation."
  type = object({
    project_id         = string
    project_number     = string
    pool_id            = string
    provider_id        = string
    service_account_id = optional(string)
    roles              = optional(list(string), ["roles/aiplatform.user", "roles/serviceusage.serviceUsageConsumer"])
  })
  default = null

  validation {
    condition     = var.google_federation == null ? true : can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.google_federation.project_id))
    error_message = "google_federation.project_id must be a valid GCP project ID (6 to 30 characters, lowercase letters, digits, hyphens)."
  }

  validation {
    condition     = var.google_federation == null ? true : can(regex("^[0-9]+$", var.google_federation.project_number))
    error_message = "google_federation.project_number must be numeric."
  }

  validation {
    condition     = var.google_federation == null ? true : can(regex("^[a-z0-9-]+$", var.google_federation.pool_id))
    error_message = "google_federation.pool_id must contain only lowercase letters, digits, and hyphens."
  }

  validation {
    condition     = var.google_federation == null ? true : can(regex("^[a-z0-9-]+$", var.google_federation.provider_id))
    error_message = "google_federation.provider_id must contain only lowercase letters, digits, and hyphens."
  }

  validation {
    condition     = var.google_federation == null ? true : (var.google_federation.service_account_id == null || can(regex("^[a-z](?:[-a-z0-9]{4,28}[a-z0-9])$", var.google_federation.service_account_id)))
    error_message = "google_federation.service_account_id must be null or 6 to 30 characters matching ^[a-z](?:[-a-z0-9]{4,28}[a-z0-9])$."
  }
}

variable "azure_federation" {
  description = "Specifies configuration for Microsoft Azure Workload Identity Federation."
  type = object({
    tenant_id            = string
    subscription_id      = string
    cognitive_account_id = string
    openai_endpoint      = string
    application_name     = optional(string)
    audiences            = optional(list(string), ["https://gitlab.com"])
    subjects             = optional(list(string))
    roles                = optional(list(string), ["Cognitive Services OpenAI User"])
  })
  default = null

  validation {
    condition     = var.azure_federation == null ? true : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.azure_federation.tenant_id))
    error_message = "azure_federation.tenant_id must be a lowercase UUID."
  }

  validation {
    condition     = var.azure_federation == null ? true : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.azure_federation.subscription_id))
    error_message = "azure_federation.subscription_id must be a lowercase UUID."
  }

  validation {
    condition     = var.azure_federation == null ? true : can(regex("^https://", var.azure_federation.openai_endpoint))
    error_message = "azure_federation.openai_endpoint must be an HTTPS URL."
  }
}
