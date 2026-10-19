
# Documentation: documentation/architecture/bastion-vault-privilege-convergence.md Section 7 Item B.1.
# Root CA mount and certificate generation for the internal trust hierarchy.
locals {
  root_cas = {
    "ec-p384" = {
      common_name   = var.pki_root_ca.ec_p384.common_name
      key_type      = "ec"
      key_bits      = 384
      parameter_set = null
      issuer_name   = null
      key_name      = null
      not_after     = "2035-12-31T23:59:59Z" # NIST IR 8547 disallows every quantum vulnerable signature after 2035.
      ttl_seconds   = null
    }
    "ml-dsa-87" = {
      common_name   = var.pki_root_ca.ml_dsa_87.common_name
      key_type      = "ml-dsa"
      key_bits      = null
      parameter_set = "ml-dsa-87"
      issuer_name   = "ml-dsa-87"
      key_name      = "ml-dsa-87"
      not_after     = null
      ttl_seconds   = var.pki_root_ca.ml_dsa_87.ttl_seconds
    }
  }
}

resource "vault_mount" "pki_root" {
  provider    = vault.bastion
  path        = "pki-root"
  type        = "pki"
  description = "Infrastructure Root CA. Signs only authorized issuing intermediates."

  default_lease_ttl_seconds = 60 * 60 * 24 * 365 * 10 # 10 Years
  max_lease_ttl_seconds     = 60 * 60 * 24 * 365 * 10
}

resource "vault_pki_secret_backend_root_cert" "root" {
  for_each = local.root_cas

  provider      = vault.bastion
  backend       = vault_mount.pki_root.path
  common_name   = each.value.common_name
  type          = "internal"
  key_type      = each.value.key_type
  key_bits      = each.value.key_bits
  parameter_set = each.value.parameter_set
  issuer_name   = each.value.issuer_name
  key_name      = each.value.key_name
  not_after     = each.value.not_after
  ttl           = each.value.ttl_seconds

  # Prevent resource destruction to avoid invalidating downstream certificates without a rotation handler.
  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_pki_secret_backend_issuer" "root" {
  for_each = local.root_cas

  provider    = vault.bastion
  backend     = vault_mount.pki_root.path
  issuer_ref  = vault_pki_secret_backend_root_cert.root[each.key].issuer_id
  issuer_name = each.key

  issuing_certificates    = ["${local.bastion_vault_endpoint}/v1/${vault_mount.pki_root.path}/issuer/${each.key}/der"]
  crl_distribution_points = ["${local.bastion_vault_endpoint}/v1/${vault_mount.pki_root.path}/issuer/${each.key}/crl/der"]
}

resource "vault_pki_secret_backend_config_issuers" "root" {
  provider                      = vault.bastion
  backend                       = vault_mount.pki_root.path
  default                       = vault_pki_secret_backend_issuer.root["ec-p384"].issuer_id
  default_follows_latest_issuer = false
}
