
# This layer reads the workstation topology and the local CAs of the repository as files.
locals {
  workstation            = yamldecode(file("${path.root}/../../../workstation-topology.yaml"))
  vault_bastion_endpoint = "https://${local.workstation.vault_bastion.publish_address}:${local.workstation.vault_bastion.api_port}"
}

# The ML-DSA-87 Transport Root CA signs the loopback listener and every operator client certificate.
data "local_file" "vault_bastion_operator_ca" {
  filename = "${path.root}/../../../vault/tls/ca-ml-dsa-87.pem"
}

# The EC P-384 Transport Root CA signs the publish listener certificate verified by guests.
data "local_file" "vault_bastion_publish_ca" {
  filename = "${path.root}/../../../vault/tls/ca-ec-p384.pem"
}

# Consumers trust both Transport Root CAs. The publish listener can switch to ML-DSA without a consumer redeployment.
# Each certificate ends with one newline. A file without a trailing newline merges two PEM blocks and drops both anchors.
locals {
  vault_bastion_listener_ca_bundle_pem = join("", [
    for pem in [data.local_file.vault_bastion_publish_ca.content, data.local_file.vault_bastion_operator_ca.content] : "${trimspace(pem)}\n"
  ])
}
