
variable "name" {
  description = "Specifies the project name and repository slug identifier."
  type        = string
}

variable "description" {
  description = "Provides the project description displayed on the GitLab project overview interface."
  type        = string
  default     = ""
}

variable "visibility" {
  description = "Specifies the visibility level of the GitLab project."
  type        = string
  default     = "private"

  validation {
    condition     = contains(["public", "private", "internal"], var.visibility)
    error_message = "visibility must be one of: public, private, internal."
  }
}

variable "namespace_id" {
  description = "Specifies the numeric identifier of the target subgroup, sourced from the remote state of 10-group-topology. Omission of a default value mandates explicit specification by the caller."
  type        = number
}

variable "only_allow_merge_if_pipeline_succeeds" {
  description = "Specifies whether merge operations require successful pipeline completion. This attribute MUST be set to false for repositories lacking a .gitlab-ci.yml configuration file to prevent deadlock during merge evaluation."
  type        = bool
  default     = true
}

variable "squash_commit_template" {
  description = "Specifies the commit message template applied to squashed commits upon merge execution."
  type        = string
  default     = "%%{title}"
}

variable "extra_variables" {
  description = "Specifies a map of extra CI/CD variables to configure on the GitLab project. Values are masked and hidden."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "inbound_job_token_scope_project_ids" {
  description = "Specifies a list of numeric project IDs permitted to access this repository via CI_JOB_TOKEN."
  type        = list(number)
  default     = []
}
