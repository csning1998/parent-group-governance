
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
