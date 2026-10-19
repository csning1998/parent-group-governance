
variable "pki_root_ca" {
  description = "Configuration parameters of the Platform PKI Root CA issuers."
  type = object({
    ec_p384 = object({
      common_name = string
    })
    ml_dsa_87 = object({
      common_name = string
      ttl_seconds = number
    })
  })
  default = {
    ec_p384 = {
      common_name = "On-prem Infrastructure Root CA"
    }
    ml_dsa_87 = {
      common_name = "On-prem Infrastructure Root CA ML-DSA-87"
      ttl_seconds = 60 * 60 * 24 * 365 * 10 # 10 Years
    }
  }

  validation {
    condition     = var.pki_root_ca.ml_dsa_87.ttl_seconds <= 60 * 60 * 24 * 365 * 10
    error_message = "pki_root_ca.ml_dsa_87.ttl_seconds must not exceed the pki_root mount max_lease_ttl_seconds (10 years)."
  }

  validation {
    condition     = var.pki_root_ca.ec_p384.common_name != var.pki_root_ca.ml_dsa_87.common_name
    error_message = "pki_root_ca.ec_p384.common_name and pki_root_ca.ml_dsa_87.common_name must declare distinct common names."
  }
}
