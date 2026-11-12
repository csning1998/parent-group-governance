
variable "gitlab_url" {
  description = "Specifies the https URL of the GitLab instance, which vault-proxy-env exports from the origin remote of parent-group-governance."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+$", var.gitlab_url))
    error_message = "gitlab_url must be https://<host> without a trailing path."
  }
}

variable "gitlab_top_level_group_path" {
  description = "Specifies the path of the top-level GitLab group, which vault-proxy-env exports from the origin remote of parent-group-governance."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.gitlab_top_level_group_path))
    error_message = "gitlab_top_level_group_path must be one GitLab path segment."
  }
}

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

variable "host_log_rendezvous_offset" {
  description = "Host number of the log rendezvous receiver inside the host log rendezvous segment."
  type        = number
  default     = 10

  validation {
    condition     = var.host_log_rendezvous_offset >= 1 && var.host_log_rendezvous_offset <= 254
    error_message = "host_log_rendezvous_offset MUST lie between 1 and 254."
  }
}
