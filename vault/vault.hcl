
ui            = true
api_addr      = "https://172.16.0.1:8200"
cluster_addr  = "https://127.0.0.1:8201"
disable_mlock = false

storage "raft" {
  node_id = "node1"
  path    = "/opt/vault/data"
}

# Local operator, Terraform, and entry.sh access.
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable   = false
  tls_cert_file = "/opt/vault/tls/vault.pem"
  tls_key_file  = "/opt/vault/tls/vault-key.pem"
}

# Guest VM access via the dedicated publish network (hypervisor_baseline).
listener "tcp" {
  address       = "172.16.0.1:8200"
  tls_disable   = false
  tls_cert_file = "/opt/vault/tls/vault.pem"
  tls_key_file  = "/opt/vault/tls/vault-key.pem"
}
