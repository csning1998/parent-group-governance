
module "local_creds" {
  source = "../../modules/local-credential-contexts"
}

resource "sonarqube_user_token" "ci_analysis" {
  name = "gitlab-ci-analysis"
  type = "GLOBAL_ANALYSIS_TOKEN"
}

# infrastructure/token/* belongs to this layer. infrastructure/credentials/* belongs to governance.
resource "vault_kv_secret_v2" "sonar_token" {
  provider  = vault.bastion
  mount     = "secret"
  name      = "parent-group-governance/infrastructure/token/sonarqube"
  data_json = jsonencode({ sonarqube_ci_token = sonarqube_user_token.ci_analysis.token })
}
