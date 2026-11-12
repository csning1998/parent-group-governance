
variable "inbound_job_token_scope_project_ids" {
  description = "Specifies a list of numeric project IDs permitted to access this repository via CI_JOB_TOKEN."
  type        = list(number)
}

variable "github_owner" {
  description = "Specifies the GitHub account or organization login hosting the mirrored repository."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$", var.github_owner))
    error_message = "github_owner must be a GitHub login of 1 to 39 characters. A hyphen must not be the first or last character."
  }
}

variable "gitlab_project" {
  description = "Basic items for GitLab project settings"
  type = object({
    visibility = string
  })

  validation {
    condition     = contains(["public", "private", "internal"], var.gitlab_project.visibility)
    error_message = "gitlab_project.visibility must be one of: public, private, internal."
  }
}

variable "gitlab_terraform_state_base" {
  description = "Specifies the GitLab Terraform state API URL of the project hosting every state of this repository, without a trailing slash."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+/.+/projects/[0-9]+/terraform/state$", var.gitlab_terraform_state_base))
    error_message = "gitlab_terraform_state_base must match https://<host>/<api path>/projects/<project ID>/terraform/state."
  }
}
