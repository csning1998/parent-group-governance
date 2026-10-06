
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
    output_name = optional(string, "bastion_vault")
    attribute   = optional(string, "listener_ca_cert_pem")
  })
  default = {}
}
