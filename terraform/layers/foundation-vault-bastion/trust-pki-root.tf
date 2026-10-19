
# Documentation: documentation/architecture/bastion-vault-privilege-convergence.md Section 7 Item B.1.
# Root CA mount and certificate generation for the internal trust hierarchy.
resource "vault_mount" "pki_root" {
  provider    = vault.bastion
  path        = "pki-root"
  type        = "pki"
  description = "Infrastructure Root CA. Signs only authorized issuing intermediates."

  default_lease_ttl_seconds = 60 * 60 * 24 * 365 * 10 # 10 Years
  max_lease_ttl_seconds     = 60 * 60 * 24 * 365 * 10
}

resource "vault_pki_secret_backend_root_cert" "root" {
  provider    = vault.bastion
  backend     = vault_mount.pki_root.path
  common_name = var.pki_root_ca_common_name
  type        = "internal"
  key_type    = "ec"
  key_bits    = 384
  not_after   = "2035-12-31T23:59:59Z" # NIST IR 8547 disallows every quantum vulnerable signature after 2035.

  # Prevent resource destruction to avoid invalidating downstream certificates without a rotation handler.
  lifecycle {
    prevent_destroy = true
  }
}
