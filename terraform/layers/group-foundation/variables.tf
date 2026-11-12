variable "gitlab_top_level_group_path" {
  description = "Specifies the path of the top-level GitLab group, which vault-proxy-env exports from the origin remote of parent-group-governance."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.gitlab_top_level_group_path))
    error_message = "gitlab_top_level_group_path must be one GitLab path segment."
  }
}
