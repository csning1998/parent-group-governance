variable "gitlab_url" {
  description = "Specifies the GitLab instance HTTPS URL exported by vault-proxy-env from the repository origin remote."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+$", var.gitlab_url))
    error_message = "gitlab_url must be https://<host> without a trailing path."
  }
}
