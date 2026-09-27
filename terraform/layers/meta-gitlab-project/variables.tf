
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
