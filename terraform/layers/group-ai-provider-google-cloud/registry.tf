
# Downstream administration layers read the federation identifiers from the registry instead of the state of this layer.
resource "vault_kv_secret_v2" "registry_platform_ai_provider_google_cloud" {
  provider = vault.bastion
  mount    = "registry"
  name     = "platform/ai-provider/google-cloud"
  data_json = jsonencode({
    project_id     = data.google_project.current.project_id
    project_number = data.google_project.current.number
    pool_id        = google_iam_workload_identity_pool.gitlab_saas.workload_identity_pool_id
    provider_id    = google_iam_workload_identity_pool_provider.gitlab_saas.workload_identity_pool_provider_id
  })
}
