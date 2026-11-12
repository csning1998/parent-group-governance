
variable "gcp_project_id" {
  description = "Target Google Cloud project identifier hosting Workload Identity Federation."
  type        = string
}

variable "workload_identity_pool_id" {
  description = "Identifier of the Google Workload Identity Pool for GitLab SaaS."
  type        = string
  default     = "gitlab-pool"
}

variable "workload_identity_pool_provider_id" {
  description = "Identifier of the Google Workload Identity Pool Provider for GitLab SaaS."
  type        = string
  default     = "gitlab-provider"
}

variable "gitlab_url" {
  description = "Specifies the https URL of the GitLab instance, which vault-proxy-env exports from the origin remote of parent-group-governance."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+$", var.gitlab_url))
    error_message = "gitlab_url must be https://<host> without a trailing path."
  }
}

variable "gitlab_top_level_group_path" {
  description = "Specifies the path of the top-level GitLab group, which vault-proxy-env exports from the origin remote of parent-group-governance."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.gitlab_top_level_group_path))
    error_message = "gitlab_top_level_group_path must be one GitLab path segment."
  }
}
