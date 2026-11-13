variable "gitlab_top_level_group_path" {
  description = "Specifies the root GitLab group path exported by vault-proxy-env from the repository origin remote."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.gitlab_top_level_group_path))
    error_message = "gitlab_top_level_group_path must be one GitLab path segment."
  }
}
