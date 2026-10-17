
# The workstation topology and the local CAs of the repository, which this layer reads as files.
locals {
  workstation            = yamldecode(file("${path.root}/../../../workstation-topology.yaml"))
  bastion_vault_endpoint = "https://${local.workstation.bastion_vault.publish_address}:${local.workstation.bastion_vault.api_port}"
}

# The ML-DSA-87 CA signs the loopback listener and every operator client certificate.
data "local_file" "bastion_vault_operator_ca" {
  filename = "${path.root}/../../../vault/tls/ca-ml-dsa-87.pem"
}

# The EC P-384 CA signs the publish listener, which guests verify.
data "local_file" "bastion_vault_publish_ca" {
  filename = "${path.root}/../../../vault/tls/ca-ec-p384.pem"
}
