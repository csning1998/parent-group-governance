
# The single declaration of the platform names and ranges which the Bastion Vault trusts.
# Locals stay beyond tfvars, -var, and TF_VAR_ overrides, hence every change of a trust boundary passes review.
locals {
  platform_trust = {
    domain_suffix        = "homelab-infra.dev"
    stages               = ["production"]
    network_cidr         = "172.16.0.0/16"
    bastion_publish_cidr = "172.16.0.0/24"
    # Cilium names the Hubble mTLS peers under these fixed suffixes outside the platform domain.
    downstream_extra_dns_domains = ["hubble-grpc.cilium.io", "hubble-relay.cilium.io"]
  }

  spire_trust_domains = [for stage in local.platform_trust.stages : "${stage}.${local.platform_trust.domain_suffix}"]

  # The Bastion publish network lies inside the platform network when both share the platform network address.
  bastion_publish_prefix = tonumber(split("/", local.platform_trust.bastion_publish_cidr)[1])
  network_prefix         = tonumber(split("/", local.platform_trust.network_cidr)[1])
  bastion_publish_inside_network = (
    local.bastion_publish_prefix >= local.network_prefix &&
    cidrhost("${split("/", local.platform_trust.bastion_publish_cidr)[0]}/${local.network_prefix}", 0) == cidrhost(local.platform_trust.network_cidr, 0)
  )
}

check "platform_trust_consistent" {
  assert {
    condition     = length(local.platform_trust.stages) > 0 && local.bastion_publish_inside_network
    error_message = "platform_trust MUST name a stage, and bastion_publish_cidr MUST lie inside network_cidr."
  }
}
