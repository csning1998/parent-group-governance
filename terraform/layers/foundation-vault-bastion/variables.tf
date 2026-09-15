
variable "pki_root_ca_common_name" {
  description = "Common name of the Infrastructure Root CA minted at pki/root/generate/internal"
  type        = string
  default     = "On-prem Infrastructure Root CA"
}

variable "pki_intermediate_ca_common_name" {
  description = "Common name of the Bootstrap Issuing Intermediate CA signed by the Root CA"
  type        = string
  default     = "On-prem Infrastructure Intermediate CA"
}

variable "pki_intermediate_mount_path" {
  description = "Mount path of the Bootstrap Issuing Intermediate PKI secrets engine"
  type        = string
  default     = "pki_int"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.pki_intermediate_mount_path))
    error_message = "pki_intermediate_mount_path must be a bare Vault mount path segment."
  }
}
