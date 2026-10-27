
# The instance values reside in the Bastion Vault since this repository is public and serves every deployment.
# The root token writes the path during the bootstrap, and the administrator identity writes the path afterwards.
# network-allocation.example.json documents the fields.
data "vault_generic_secret" "network_allocation" {
  provider = vault.bastion
  path     = "secret/parent-group-governance/network/allocation"
}

locals {
  # The facts are not secret, while the provider marks every KV value as sensitive.
  network_allocation_raw = nonsensitive(data.vault_generic_secret.network_allocation.data)

  network_allocation = {
    domain_suffix        = lookup(local.network_allocation_raw, "domain_suffix", "")
    stages               = tolist(jsondecode(lookup(local.network_allocation_raw, "stages", "[]")))
    network_cidr         = lookup(local.network_allocation_raw, "network_cidr", "")
    bastion_publish_cidr = lookup(local.network_allocation_raw, "bastion_publish_cidr", "")
  }

  # Cilium names the Hubble mTLS peers under these fixed suffixes outside the platform domain.
  cilium_hubble_extra_dns_domains = ["hubble-grpc.cilium.io", "hubble-relay.cilium.io"]
  # Raft peers of an in-cluster Vault join through the Service names under the cluster domain.
  kubernetes_default_cluster_domain = "cluster.local"

  stage_domains = [for stage in local.network_allocation.stages : "${stage}.${local.network_allocation.domain_suffix}"]

  # The third octet of each host segment lies outside the catalog numbering of platform-foundation.
  host_segment_indexes = {
    host_telemetry_scrape = 249
    host_log_rendezvous   = 250
  }
  host_segment_cidrs = {
    for name, index in local.host_segment_indexes : name => (
      can(cidrsubnet(local.network_allocation.network_cidr, 8, index)) ? cidrsubnet(local.network_allocation.network_cidr, 8, index) : ""
    )
  }

  # The host keeps the host number of its publish address on every host segment.
  host_number = tonumber(split(".", local.workstation.bastion_vault.publish_address)[3])

  host_telemetry_scrape_address    = local.host_segment_cidrs.host_telemetry_scrape != "" ? cidrhost(local.host_segment_cidrs.host_telemetry_scrape, local.host_number) : ""
  host_log_rendezvous_address      = local.host_segment_cidrs.host_log_rendezvous != "" ? cidrhost(local.host_segment_cidrs.host_log_rendezvous, var.host_log_rendezvous_offset) : ""
  host_log_rendezvous_server_names = [for base in local.stage_domains : "host-log-rendezvous.${base}"]

  dns_name_pattern  = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
  dns_label_pattern = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"

  # The Bastion publish network lies inside the platform network when both share the platform network address.
  # The conditional evaluates the comparison only for two valid CIDRs, hence a malformed value reaches the precondition.
  bastion_publish_inside_network = can(cidrnetmask(local.network_allocation.network_cidr)) && can(cidrnetmask(local.network_allocation.bastion_publish_cidr)) ? (
    tonumber(split("/", local.network_allocation.bastion_publish_cidr)[1]) >= tonumber(split("/", local.network_allocation.network_cidr)[1]) &&
    cidrhost("${split("/", local.network_allocation.bastion_publish_cidr)[0]}/${split("/", local.network_allocation.network_cidr)[1]}", 0) == cidrhost(local.network_allocation.network_cidr, 0)
  ) : false

  # The publish listener of workstation-topology.yaml lies inside the Bastion publish network of the network allocation facts.
  topology_publish_inside_network = can(cidrnetmask(local.network_allocation.bastion_publish_cidr)) ? (
    cidrhost("${local.workstation.bastion_vault.publish_address}/${split("/", local.network_allocation.bastion_publish_cidr)[1]}", 0) == cidrhost(local.network_allocation.bastion_publish_cidr, 0)
  ) : false

  network_allocation_valid = alltrue([
    can(regex(local.dns_name_pattern, local.network_allocation.domain_suffix)),
    length(local.network_allocation.stages) > 0,
    alltrue([for stage in local.network_allocation.stages : can(regex(local.dns_label_pattern, stage))]),
    can(cidrnetmask(local.network_allocation.network_cidr)),
    can(cidrnetmask(local.network_allocation.bastion_publish_cidr)),
    can(cidrnetmask(local.network_allocation.network_cidr)) ? split("/", local.network_allocation.network_cidr)[1] == "16" : false,
    can(cidrsubnet(local.network_allocation.network_cidr, 8, 0)) ? local.network_allocation.bastion_publish_cidr == cidrsubnet(local.network_allocation.network_cidr, 8, 0) : false,
    local.bastion_publish_inside_network,
  ])
}

# A precondition stops the plan, while a failed check block only warns.
resource "terraform_data" "network_allocation_validation" {
  input = local.network_allocation

  lifecycle {
    precondition {
      condition     = local.network_allocation_valid
      error_message = "secret/parent-group-governance/network/allocation MUST hold a DNS domain_suffix, a JSON list of DNS label stages, IPv4 network_cidr of /16, and bastion_publish_cidr of segment 0 inside network_cidr."
    }
    precondition {
      condition     = local.topology_publish_inside_network
      error_message = "bastion_vault.publish_address of workstation-topology.yaml MUST lie inside bastion_publish_cidr of secret/parent-group-governance/network/allocation."
    }
    precondition {
      condition     = var.host_log_rendezvous_offset != local.host_number
      error_message = "host_log_rendezvous_offset MUST differ from the host number of bastion_vault.publish_address in workstation-topology.yaml."
    }
  }
}
