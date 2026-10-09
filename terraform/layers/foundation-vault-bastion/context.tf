
# The workstation topology and the local CA of the repository, which this layer reads as files.
locals {
  workstation            = yamldecode(file("${path.root}/../../../workstation-topology.yaml"))
  bastion_vault_endpoint = "https://${local.workstation.bastion_vault.publish_address}:${local.workstation.bastion_vault.api_port}"
}

data "local_file" "bastion_vault_ca" {
  filename = "${path.root}/../../../vault/tls/ca.pem"
}
