
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


# 2. Bootstrap Issuing Intermediate.
resource "vault_mount" "pki_intermediate" {
  provider    = vault.bastion
  path        = var.pki_intermediate_mount_path
  type        = "pki"
  description = "Bootstrap Issuing Intermediate. Issues pre-Production-Vault leaf certificates and signs the Production Vault intermediate."

  default_lease_ttl_seconds = 60 * 60 * 24 * 365 # 1 Year
  max_lease_ttl_seconds     = 60 * 60 * 24 * 365
}

resource "vault_pki_secret_backend_intermediate_cert_request" "pki_intermediate_csr" {
  provider = vault.bastion
  backend  = vault_mount.pki_intermediate.path

  type        = "internal"
  common_name = var.pki_intermediate_ca_common_name
  key_type    = "ec"
  key_bits    = 256

  # The key type and the mount accessor name the key, since Vault rejects a new key under an existing key name.
  key_name = "inter-ec256-${vault_mount.pki_intermediate.accessor}"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "pki_intermediate_signed" {
  provider = vault.bastion
  backend  = vault_mount.pki_root.path

  csr                  = vault_pki_secret_backend_intermediate_cert_request.pki_intermediate_csr.csr
  common_name          = var.pki_intermediate_ca_common_name
  format               = "pem"
  ttl                  = 60 * 60 * 24 * 365 # 1 Year
  exclude_cn_from_sans = true
  max_path_length      = 0 # The bootstrap intermediate lacks Name Constraints, hence a zero path length keeps the mount from signing a CA.

  # Pin issuer reference to trigger re-signing when the Root CA certificate is regenerated.
  issuer_ref = vault_pki_secret_backend_root_cert.root.issuer_id
}

# Import intermediate certificate into backend to complete CSR registration.
resource "vault_pki_secret_backend_intermediate_set_signed" "pki_intermediate_set" {
  provider    = vault.bastion
  backend     = vault_mount.pki_intermediate.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.pki_intermediate_signed.certificate
}

resource "vault_pki_secret_backend_config_urls" "pki_intermediate_urls" {
  provider = vault.bastion
  backend  = vault_mount.pki_intermediate.path

  issuing_certificates    = ["${local.bastion_vault_endpoint}/v1/${vault_mount.pki_intermediate.path}/ca"]
  crl_distribution_points = ["${local.bastion_vault_endpoint}/v1/${vault_mount.pki_intermediate.path}/crl"]
}

# Set default issuer explicitly for the intermediate PKI backend.
resource "vault_pki_secret_backend_config_issuers" "pki_intermediate_default" {
  provider                      = vault.bastion
  backend                       = vault_mount.pki_intermediate.path
  default                       = vault_pki_secret_backend_intermediate_set_signed.pki_intermediate_set.imported_issuers[0]
  default_follows_latest_issuer = true
}
