
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
  description = "Specifies the GitLab instance HTTPS URL exported by vault-proxy-env from the repository origin remote."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+$", var.gitlab_url))
    error_message = "gitlab_url must be https://<host> without a trailing path."
  }
}

variable "gitlab_top_level_group_path" {
  description = "Specifies the root GitLab group path exported by vault-proxy-env from the repository origin remote."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.gitlab_top_level_group_path))
    error_message = "gitlab_top_level_group_path must be one GitLab path segment."
  }
}
