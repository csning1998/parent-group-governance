
# Configures both file and stdout audit devices because Vault rejects all requests unless at least one audit sink succeeds.
resource "vault_audit" "file" {
  provider    = vault.bastion
  type        = "file"
  path        = "file"
  description = "Audit log on the dedicated volume, read by the decrypt and policy anomaly check."

  options = {
    file_path = "/opt/vault/audit/audit.log"
    mode      = "0600"
  }
}

resource "vault_audit" "stdout" {
  provider    = vault.bastion
  type        = "file"
  path        = "stdout"
  description = "Audit log through the container log driver, the second sink."

  options = {
    file_path = "stdout"
  }
}
