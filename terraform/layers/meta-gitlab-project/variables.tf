
variable "inbound_job_token_scope_project_ids" {
  description = "Specifies a list of numeric project IDs permitted to access this repository via CI_JOB_TOKEN."
  type        = list(number)
}
