
# Each key names a PKI mount whose RFC 5280 Name Constraints bind the whole subtree, whatever a caller of sign-intermediate passes.
# An assignable entry declares the policy which the owner may assign on the listed auth scopes, and {owner} expands to the owner.
locals {
  constrained_intermediates = {
    # The mount signs the SPIRE Parent CA, which signs the SPIRE Child CA.
    "pki-intermediate-spire" = {
      owner                 = local.platform_tenant
      root_ca_id            = "ec-p384"
      common_name           = "On-prem SPIRE Upstream Intermediate CA"
      max_path_length       = 2
      permitted_dns_domains = local.stage_domains
      excluded_dns_domains  = []
      permitted_uri_domains = local.stage_domains
      excluded_uri_domains  = []
      permitted_ip_ranges   = []
      excluded_ip_ranges    = ["0.0.0.0/0", "::/0"]
      assignable = {
        suffix = "signer"
        scopes = ["approle"]
        paths  = { "root/sign-intermediate" = ["create", "update"] }
      }
    }
    # The subtree of the Downstream Vault CA excludes the Bastion listener names and the SPIFFE trust domain.
    "pki-intermediate-vault-downstream" = {
      owner                 = local.platform_tenant
      root_ca_id            = "ec-p384"
      common_name           = "On-prem Downstream Vault Intermediate CA"
      max_path_length       = 2
      permitted_dns_domains = concat([local.network_allocation.domain_suffix], local.cilium_hubble_extra_dns_domains)
      excluded_dns_domains  = []
      permitted_uri_domains = []
      excluded_uri_domains  = [local.network_allocation.domain_suffix, ".${local.network_allocation.domain_suffix}"]
      permitted_ip_ranges   = [local.network_allocation.network_cidr]
      excluded_ip_ranges    = [local.network_allocation.bastion_publish_cidr]
      assignable            = null
    }
    # The mount issues leaf certificates alone, since the zero path length forbids a subordinate CA.
    "pki-leaf-platform" = {
      owner                 = local.platform_tenant
      root_ca_id            = "ec-p384"
      common_name           = "On-prem Platform Leaf Intermediate CA"
      max_path_length       = 0
      permitted_dns_domains = [local.network_allocation.domain_suffix, local.kubernetes_default_cluster_domain]
      excluded_dns_domains  = []
      permitted_uri_domains = []
      excluded_uri_domains  = [local.network_allocation.domain_suffix, ".${local.network_allocation.domain_suffix}"]
      permitted_ip_ranges   = [local.network_allocation.network_cidr]
      excluded_ip_ranges    = [local.network_allocation.bastion_publish_cidr]
      assignable = {
        suffix = "issuer"
        scopes = ["owned"]
        paths = {
          "issue/{owner}-*" = ["create", "update"]
          "sign/{owner}-*"  = ["create", "update"]
        }
      }
    }
  }

  constrained_intermediate_algorithms = {
    "ec-p384" = {
      key_type      = "ec"
      key_bits      = 384
      parameter_set = null
    }
    "ml-dsa-87" = {
      key_type      = "ml-dsa"
      key_bits      = null
      parameter_set = "ml-dsa-87"
    }
  }

  constrained_intermediate_issuers = merge([
    for mount_key, mount_spec in local.constrained_intermediates : {
      for algo_key, algo_spec in local.constrained_intermediate_algorithms : "${mount_key}/${algo_key}" => {
        mount                 = mount_key
        algorithm             = algo_key
        common_name           = mount_spec.common_name
        max_path_length       = mount_spec.max_path_length
        permitted_dns_domains = mount_spec.permitted_dns_domains
        excluded_dns_domains  = mount_spec.excluded_dns_domains
        permitted_uri_domains = mount_spec.permitted_uri_domains
        excluded_uri_domains  = mount_spec.excluded_uri_domains
        permitted_ip_ranges   = mount_spec.permitted_ip_ranges
        excluded_ip_ranges    = mount_spec.excluded_ip_ranges
        key_type              = algo_spec.key_type
        key_bits              = algo_spec.key_bits
        parameter_set         = algo_spec.parameter_set
      }
    }
  ]...)

  constrained_assignable = {
    for mount, spec in local.constrained_intermediates : "${mount}-${spec.assignable.suffix}-${spec.owner}" => {
      owner  = spec.owner
      mount  = mount
      scopes = spec.assignable.scopes
      paths  = spec.assignable.paths
    } if spec.assignable != null
  }

  # A mount without an assignable entry lacks a key, and lookup returns null for the mount alone.
  constrained_assignable_by_mount = {
    for name, policy in vault_policy.pki_constrained_assignable : local.constrained_assignable[name].mount => policy.name
  }
}

# The tenant cannot rewrite the policy, because the tenant ACL does not grant any write on sys/policies/acl.
resource "vault_policy" "pki_constrained_assignable" {
  for_each = local.constrained_assignable

  provider = vault.bastion
  name     = each.key
  policy = jsonencode({
    path = {
      for path, capabilities in each.value.paths : "${vault_mount.pki_constrained[each.value.mount].path}/${replace(path, "{owner}", each.value.owner)}" => {
        capabilities = capabilities
      }
    }
  })
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
  for_each = local.constrained_intermediate_issuers

  provider = vault.bastion
  backend  = vault_mount.pki_constrained[each.value.mount].path

  type          = "internal"
  common_name   = each.value.common_name
  key_type      = each.value.key_type
  key_bits      = each.value.key_bits
  parameter_set = each.value.parameter_set

  # The algorithm and the mount accessor name the key, since Vault rejects a new key under an existing key name.
  key_name = "${each.value.algorithm}-${vault_mount.pki_constrained[each.value.mount].accessor}"
}

# The intermediate outlives the one-year CA certificates which the mount signs, since Vault rejects a TTL past the issuer expiry.
resource "vault_pki_secret_backend_root_sign_intermediate" "pki_constrained_signed" {
  for_each = local.constrained_intermediate_issuers

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

  issuer_ref = vault_pki_secret_backend_issuer.root[each.value.algorithm].issuer_id
}

resource "vault_pki_secret_backend_intermediate_set_signed" "pki_constrained_set" {
  for_each = local.constrained_intermediate_issuers

  provider    = vault.bastion
  backend     = vault_mount.pki_constrained[each.value.mount].path
  certificate = vault_pki_secret_backend_root_sign_intermediate.pki_constrained_signed[each.key].certificate
}

resource "vault_pki_secret_backend_issuer" "pki_constrained" {
  for_each = local.constrained_intermediate_issuers

  provider    = vault.bastion
  backend     = vault_mount.pki_constrained[each.value.mount].path
  issuer_ref  = vault_pki_secret_backend_intermediate_set_signed.pki_constrained_set[each.key].imported_issuers[0]
  issuer_name = each.value.algorithm

  issuing_certificates    = ["${local.bastion_vault_endpoint}/v1/${vault_mount.pki_constrained[each.value.mount].path}/issuer/${each.value.algorithm}/der"]
  crl_distribution_points = ["${local.bastion_vault_endpoint}/v1/${vault_mount.pki_constrained[each.value.mount].path}/issuer/${each.value.algorithm}/crl/der"]
}

resource "vault_pki_secret_backend_config_issuers" "pki_constrained_default" {
  for_each = local.constrained_intermediates

  provider                      = vault.bastion
  backend                       = vault_mount.pki_constrained[each.key].path
  default                       = vault_pki_secret_backend_issuer.pki_constrained["${each.key}/${each.value.root_ca_id}"].issuer_id
  default_follows_latest_issuer = false
}
