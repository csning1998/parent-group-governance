
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/terraform/state-backend"
}

data "terraform_remote_state" "group_topology" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-topology" })
}

data "terraform_remote_state" "sonarqube_bootstrap" {
  backend = "http"
  config  = merge(local._state_auth, { address = "${local._state_base}/group-sonarqube" })
}

# Resolves KV secret location from upstream layer outputs. Prevents Vault 404 API errors
# by trapping missing outputs when layers/15-sonarqube-bootstrap is unapplied.
data "vault_kv_secret_v2" "sonar_token" {
  provider = vault.bastion
  mount    = data.terraform_remote_state.sonarqube_bootstrap.outputs.secret_mount
  name     = data.terraform_remote_state.sonarqube_bootstrap.outputs.secret_name
}

check "sonarqube_bootstrap_outputs_present" {
  assert {
    condition     = data.terraform_remote_state.sonarqube_bootstrap.outputs.secret_mount != "" && data.terraform_remote_state.sonarqube_bootstrap.outputs.secret_name != ""
    error_message = "group-sonarqube layer outputs secret_mount or secret_name are empty. Apply group-sonarqube layer first."
  }
}
