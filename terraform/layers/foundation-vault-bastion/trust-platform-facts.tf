
# The instance values reside in the Bastion Vault since this repository is public and serves every deployment.
# Only the root token writes the path, and platform-trust.example.json documents the fields.
data "vault_generic_secret" "platform_trust" {
  provider = vault.bastion
  path     = "secret/parent-group-governance/platform-trust"
}

locals {
  # The facts are not secret, while the provider marks every KV value as sensitive.
  platform_trust_raw = nonsensitive(data.vault_generic_secret.platform_trust.data)

  platform_trust = {
    domain_suffix        = lookup(local.platform_trust_raw, "domain_suffix", "")
    stages               = tolist(jsondecode(lookup(local.platform_trust_raw, "stages", "[]")))
    network_cidr         = lookup(local.platform_trust_raw, "network_cidr", "")
    bastion_publish_cidr = lookup(local.platform_trust_raw, "bastion_publish_cidr", "")
    # Cilium names the Hubble mTLS peers under these fixed suffixes outside the platform domain.
    downstream_extra_dns_domains = ["hubble-grpc.cilium.io", "hubble-relay.cilium.io"]
    # Raft peers of an in-cluster Vault join through the Service names under the cluster domain.
    kubernetes_cluster_domain = "cluster.local"
  }

  spire_trust_domains = [for stage in local.platform_trust.stages : "${stage}.${local.platform_trust.domain_suffix}"]

  dns_name_pattern  = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
  dns_label_pattern = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"

  # The Bastion publish network lies inside the platform network when both share the platform network address.
  # The conditional evaluates the comparison only for two valid CIDRs, hence a malformed value reaches the precondition.
  bastion_publish_inside_network = can(cidrnetmask(local.platform_trust.network_cidr)) && can(cidrnetmask(local.platform_trust.bastion_publish_cidr)) ? (
    tonumber(split("/", local.platform_trust.bastion_publish_cidr)[1]) >= tonumber(split("/", local.platform_trust.network_cidr)[1]) &&
    cidrhost("${split("/", local.platform_trust.bastion_publish_cidr)[0]}/${split("/", local.platform_trust.network_cidr)[1]}", 0) == cidrhost(local.platform_trust.network_cidr, 0)
  ) : false

  # The publish listener of workstation-topology.yaml lies inside the Bastion publish network of the trust facts.
  topology_publish_inside_network = can(cidrnetmask(local.platform_trust.bastion_publish_cidr)) ? (
    cidrhost("${local.workstation.bastion_vault.publish_address}/${split("/", local.platform_trust.bastion_publish_cidr)[1]}", 0) == cidrhost(local.platform_trust.bastion_publish_cidr, 0)
  ) : false

  platform_trust_valid = alltrue([
    can(regex(local.dns_name_pattern, local.platform_trust.domain_suffix)),
    length(local.platform_trust.stages) > 0,
    alltrue([for stage in local.platform_trust.stages : can(regex(local.dns_label_pattern, stage))]),
    can(cidrnetmask(local.platform_trust.network_cidr)),
    can(cidrnetmask(local.platform_trust.bastion_publish_cidr)),
    local.bastion_publish_inside_network,
  ])
}

# A precondition stops the plan, while a failed check block only warns.
resource "terraform_data" "platform_trust_validation" {
  input = local.platform_trust

  lifecycle {
    precondition {
      condition     = local.platform_trust_valid
      error_message = "secret/parent-group-governance/platform-trust MUST hold a DNS domain_suffix, a JSON list of DNS label stages, and IPv4 network_cidr and bastion_publish_cidr, with bastion_publish_cidr inside network_cidr."
    }
    precondition {
      condition     = local.topology_publish_inside_network
      error_message = "bastion_vault.publish_address of workstation-topology.yaml MUST lie inside bastion_publish_cidr of secret/parent-group-governance/platform-trust."
    }
  }
}
