
module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"
}

resource "sonarqube_user_token" "ci_analysis" {
  name = "gitlab-ci-analysis"
  type = "GLOBAL_ANALYSIS_TOKEN"
}

# sonarqube/ci-analysis-bot belongs to this layer. sonarqube/admin-account belongs to governance.
resource "vault_kv_secret_v2" "sonar_token" {
  provider  = vault.bastion
  mount     = "secret"
  name      = "parent-group-governance/sonarqube/ci-analysis-bot"
  data_json = jsonencode({ sonarqube_ci_token = sonarqube_user_token.ci_analysis.token })
}
