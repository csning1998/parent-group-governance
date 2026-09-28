
# Documentation: documentation/architecture/platform-spire-parent-frontend.md Section 1 Item C.
# Root CA mount and certificate generation for the internal trust hierarchy.
resource "vault_mount" "pki_root" {
  provider    = vault.bastion
  path        = "pki-root"
  type        = "pki"
  description = "Infrastructure Root CA. Signs only the Bootstrap Issuing Intermediate."

  default_lease_ttl_seconds = 60 * 60 * 24 * 365 * 10 # 10 Years
  max_lease_ttl_seconds     = 60 * 60 * 24 * 365 * 10
}

resource "vault_pki_secret_backend_root_cert" "root" {
  provider    = vault.bastion
  backend     = vault_mount.pki_root.path
  common_name = var.pki_root_ca_common_name
  type        = "internal"
  ttl         = "87600h" # 10 Years

  # Prevent resource destruction to avoid invalidating downstream certificates without a rotation handler.
  lifecycle {
    prevent_destroy = true
  }
}

# Stage the Vault listener CA certificate in the local layer directory for downstream remote state access.
resource "local_file" "bastion_vault_ca_copy" {
  content  = data.local_file.bastion_vault_ca.content
  filename = "${path.root}/tls/bastion-vault-ca.crt"
}

# 2. Bootstrap Issuing Intermediate.
resource "vault_mount" "pki_intermediate" {
  provider    = vault.bastion
  path        = local.bastion_pki_intermediate_mount_path
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
  key_type    = "rsa"
  key_bits    = 4096

  # Append mount accessor to force resource replacement and private key regeneration when the backend mount is recreated.
  key_name = "inter-${vault_mount.pki_intermediate.accessor}"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "pki_intermediate_signed" {
  provider = vault.bastion
  backend  = vault_mount.pki_root.path

  csr                  = vault_pki_secret_backend_intermediate_cert_request.pki_intermediate_csr.csr
  common_name          = var.pki_intermediate_ca_common_name
  format               = "pem"
  ttl                  = 60 * 60 * 24 * 365 # 1 Year
  exclude_cn_from_sans = true

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

  issuing_certificates    = ["${module.local_credential_contexts.bastion_vault_config.endpoint}/v1/${vault_mount.pki_intermediate.path}/ca"]
  crl_distribution_points = ["${module.local_credential_contexts.bastion_vault_config.endpoint}/v1/${vault_mount.pki_intermediate.path}/crl"]
}

# Set default issuer explicitly for the intermediate PKI backend.
resource "vault_pki_secret_backend_config_issuers" "pki_intermediate_default" {
  provider                      = vault.bastion
  backend                       = vault_mount.pki_intermediate.path
  default                       = vault_pki_secret_backend_intermediate_set_signed.pki_intermediate_set.imported_issuers[0]
  default_follows_latest_issuer = true
}

moved {
  from = vault_mount.pki_inter
  to   = vault_mount.pki_intermediate
}

moved {
  from = vault_pki_secret_backend_intermediate_cert_request.pki_inter_csr
  to   = vault_pki_secret_backend_intermediate_cert_request.pki_intermediate_csr
}

moved {
  from = vault_pki_secret_backend_root_sign_intermediate.pki_inter_signed
  to   = vault_pki_secret_backend_root_sign_intermediate.pki_intermediate_signed
}

moved {
  from = vault_pki_secret_backend_intermediate_set_signed.pki_inter_set
  to   = vault_pki_secret_backend_intermediate_set_signed.pki_intermediate_set
}

moved {
  from = vault_pki_secret_backend_config_urls.pki_inter_urls
  to   = vault_pki_secret_backend_config_urls.pki_intermediate_urls
}

moved {
  from = vault_pki_secret_backend_config_issuers.pki_inter_default
  to   = vault_pki_secret_backend_config_issuers.pki_intermediate_default
}
