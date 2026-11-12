variable "gitlab_url" {
  description = "Specifies the https URL of the GitLab instance, which vault-proxy-env exports from the origin remote of parent-group-governance."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+$", var.gitlab_url))
    error_message = "gitlab_url must be https://<host> without a trailing path."
  }
}
