
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

variable "vault_kv_mount_path" {
  description = "Specifies the Vault KV-v2 engine mount path."
  type        = string
  default     = "secret"
}
