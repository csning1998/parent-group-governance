
# Documentation: documentation/architecture/platform-spire-parent-frontend.md Section 1 Item C.
# Root CA mount and certificate generation for the internal trust hierarchy.
locals {
  root_cas = {
    "primary" = {
      mount_path  = "pki-root"
      common_name = var.pki_root_ca_common_name
      key_type    = "ec"
      key_bits    = 384
      ttl_seconds = 60 * 60 * 24 * 365 * 10 # 10 Years
      not_after   = "2035-12-31T23:59:59Z"  # NIST IR 8547 disallows every quantum vulnerable signature after 2035.
      description = "Infrastructure Root CA. Signs only authorized issuing intermediates."
    }
  }
}

resource "vault_mount" "pki_root" {
  for_each = local.root_cas

  provider    = vault.bastion
  path        = each.value.mount_path
  type        = "pki"
  description = each.value.description

  default_lease_ttl_seconds = each.value.ttl_seconds
  max_lease_ttl_seconds     = each.value.ttl_seconds
}

resource "vault_pki_secret_backend_root_cert" "root" {
  for_each = local.root_cas

  provider    = vault.bastion
  backend     = vault_mount.pki_root[each.key].path
  common_name = each.value.common_name
  type        = "internal"
  key_type    = each.value.key_type
  key_bits    = each.value.key_bits
  not_after   = each.value.not_after

  # Prevent resource destruction to avoid invalidating downstream certificates without a rotation handler.
  lifecycle {
    prevent_destroy = true
  }
}
