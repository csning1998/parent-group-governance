variable "vault_ca_cert_path" {
  description = "Absolute path to the Bastion Vault CA certificate. Defaults to the conventional location for a caller at terraform/layers/<layer>/ within this repository."
  type        = string
  default     = null
}
