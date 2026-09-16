
variable "bastion_vault_config" {
  description = "Absolute path to the Bastion Vault endpoint and the CA certificate path."
  type = object({
    ca_cert_path = optional(string)
    endpoint     = optional(string, "https://172.16.0.1:8200")
    token_path   = optional(string)
  })
  default = {}
}
