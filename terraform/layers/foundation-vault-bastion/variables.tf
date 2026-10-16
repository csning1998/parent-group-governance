
variable "pki_root_ca_common_name" {
  description = "Common name of the Infrastructure Root CA minted at pki/root/generate/internal"
  type        = string
  default     = "On-prem Infrastructure Root CA"
}
