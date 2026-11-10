
# The tenant ACL and the operator policies grant capabilities through these names alone.
locals {
  acl_capability = {
    read            = ["read"]
    issue           = ["create", "update"]
    configure_mount = ["create", "read", "update", "sudo"]
    manage          = ["create", "read", "update", "delete", "list"]
    manage_mount    = ["create", "read", "update", "delete", "sudo"]
    kv_data         = ["create", "read", "update", "delete"]
    kv_metadata     = ["create", "read", "update", "list", "delete"]
    kv_version      = ["update"]
    kv_rotate       = ["create", "read", "update", "patch"]
    administer      = ["create", "read", "update", "delete", "list", "sudo"]
    list_sudo       = ["read", "sudo"]
  }
}
