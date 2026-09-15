
variable "vault_kv_namespace" {
  description = "Project-level Vault KV namespace prefix"
  type        = string
}

variable "component" {
  description = "Vault secret component within the domain"
  type        = string
}

variable "domain" {
  description = "Vault secret domain, the top-level service grouping under the namespace"
  type        = string
}

variable "generate" {
  description = "Map of secret key names to password generation parameters"
  type = map(object({
    length  = number
    special = optional(bool, false)
  }))
  default = {}
}

variable "static" {
  description = "Static key-value pairs merged into the same Vault secret (e.g. usernames)"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "vault_kv_mount" {
  description = "Vault KV v2 secrets engine mount path"
  type        = string
  default     = "secret"
}
