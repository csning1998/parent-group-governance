
variable "vault_credential_context" {
  description = "Specifies Vault KV path coordinates and payload generation parameters for the managed secret."
  type = object({
    kv_mount     = optional(string, "secret")
    kv_namespace = string
    domain       = string
    component    = string
    generate = optional(map(object({
      length  = number
      special = optional(bool, false)
    })), {})
    static = optional(map(string), {})
  })
  sensitive = true
}
