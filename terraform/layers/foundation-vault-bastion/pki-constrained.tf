
# Each key names a PKI mount whose RFC 5280 Name Constraints bind the whole subtree, whatever a caller of sign-intermediate passes.
locals {
  constrained_intermediates = {
    # The mount signs the SPIRE Parent CA, which signs the SPIRE Child CA.
    "pki-spire" = {
      owner                 = "meta-platform"
      common_name           = "On-prem SPIRE Upstream Intermediate CA"
      max_path_length       = 2
      permitted_dns_domains = local.spire_trust_domains
      excluded_dns_domains  = []
      permitted_uri_domains = local.spire_trust_domains
      excluded_uri_domains  = []
      permitted_ip_ranges   = []
      excluded_ip_ranges    = ["0.0.0.0/0", "::/0"]
    }
    # The subtree of the Downstream Vault CA excludes the Bastion listener names and the SPIFFE trust domain.
    "pki-downstream" = {
      owner                 = "meta-platform"
      common_name           = "On-prem Downstream Vault Intermediate CA"
      max_path_length       = 2
      permitted_dns_domains = concat([local.platform_trust.domain_suffix], local.platform_trust.downstream_extra_dns_domains)
      excluded_dns_domains  = []
      permitted_uri_domains = []
      excluded_uri_domains  = [local.platform_trust.domain_suffix, ".${local.platform_trust.domain_suffix}"]
      permitted_ip_ranges   = [local.platform_trust.network_cidr]
      excluded_ip_ranges    = [local.platform_trust.bastion_publish_cidr]
    }
  }
}

resource "vault_mount" "pki_constrained" {
  for_each = local.constrained_intermediates

  provider    = vault.bastion
  path        = each.key
  type        = "pki"
  description = "${each.value.common_name}. Name Constraints bind the subtree. Owner ${each.value.owner}."

  default_lease_ttl_seconds = 60 * 60 * 24 * 365 * 5 # 5 Years
  max_lease_ttl_seconds     = 60 * 60 * 24 * 365 * 5
}

resource "vault_pki_secret_backend_intermediate_cert_request" "pki_constrained_csr" {
  for_each = local.constrained_intermediates

  provider = vault.bastion
  backend  = vault_mount.pki_constrained[each.key].path

  type        = "internal"
  common_name = each.value.common_name
  key_type    = "rsa"
  key_bits    = 4096

  # Append mount accessor to force resource replacement and private key regeneration when the backend mount is recreated.
  key_name = "inter-${vault_mount.pki_constrained[each.key].accessor}"
}

# The intermediate outlives the one-year CA certificates which the mount signs, since Vault rejects a TTL past the issuer expiry.
resource "vault_pki_secret_backend_root_sign_intermediate" "pki_constrained_signed" {
  for_each = local.constrained_intermediates

  provider = vault.bastion
  backend  = vault_mount.pki_root.path

  csr                  = vault_pki_secret_backend_intermediate_cert_request.pki_constrained_csr[each.key].csr
  common_name          = each.value.common_name
  format               = "pem"
  ttl                  = 60 * 60 * 24 * 365 * 5 # 5 Years
  exclude_cn_from_sans = true
  max_path_length      = each.value.max_path_length

  permitted_dns_domains = each.value.permitted_dns_domains
  permitted_uri_domains = each.value.permitted_uri_domains
  permitted_ip_ranges   = each.value.permitted_ip_ranges
  excluded_dns_domains  = each.value.excluded_dns_domains
  excluded_uri_domains  = each.value.excluded_uri_domains
  excluded_ip_ranges    = each.value.excluded_ip_ranges

  issuer_ref = vault_pki_secret_backend_root_cert.root.issuer_id
}

resource "vault_pki_secret_backend_intermediate_set_signed" "pki_constrained_set" {
  for_each = local.constrained_intermediates

  provider    = vault.bastion
  backend     = vault_mount.pki_constrained[each.key].path
  certificate = vault_pki_secret_backend_root_sign_intermediate.pki_constrained_signed[each.key].certificate
}

resource "vault_pki_secret_backend_config_urls" "pki_constrained_urls" {
  for_each = local.constrained_intermediates

  provider = vault.bastion
  backend  = vault_mount.pki_constrained[each.key].path

  issuing_certificates    = ["${module.local_credential_contexts.bastion_vault_config.endpoint}/v1/${vault_mount.pki_constrained[each.key].path}/ca"]
  crl_distribution_points = ["${module.local_credential_contexts.bastion_vault_config.endpoint}/v1/${vault_mount.pki_constrained[each.key].path}/crl"]
}

resource "vault_pki_secret_backend_config_issuers" "pki_constrained_default" {
  for_each = local.constrained_intermediates

  provider                      = vault.bastion
  backend                       = vault_mount.pki_constrained[each.key].path
  default                       = vault_pki_secret_backend_intermediate_set_signed.pki_constrained_set[each.key].imported_issuers[0]
  default_follows_latest_issuer = true
}
