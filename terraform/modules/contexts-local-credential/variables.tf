
variable "bastion_vault_config" {
  description = "Absolute path to the Bastion Vault endpoint and the CA certificate path."
  type = object({
    ca_cert_path = optional(string)
    endpoint     = optional(string, "https://172.16.0.1:8200")
    token_path   = optional(string)
  })
  default = {}
}

variable "bastion_vault_state" {
  description = "GitLab Terraform state backend exposing the live Bastion Vault CA certificate. Read only when bastion_vault_config.ca_cert_path is not set."
  type = object({
    project_id  = optional(number, 86417732)
    state_name  = optional(string, "foundation-vault-bastion")
    output_name = optional(string, "bastion_vault_ca_cert_pem")
  })
  default = {}
}

variable "gitlab_ci_remote_state_read_token" {
  description = "GitLab PAT with read_api scope, for terraform_remote_state HTTP backend auth in a CI runner. CI_JOB_TOKEN cannot be used here: its API allowlist excludes the Terraform State API. Unset for a local operator apply, which falls back to the ~/.terraform.d/credentials.tfrc.json OAuth token from terraform login."
  type        = string
  sensitive   = true
  default     = null
}
