
output "project" {
  description = "Google Cloud project metadata."
  value = {
    id     = data.google_project.current.project_id
    number = data.google_project.current.number
    name   = data.google_project.current.name
  }
}

output "pool" {
  description = "Google Workload Identity Pool metadata."
  value = {
    id   = google_iam_workload_identity_pool.gitlab_saas.workload_identity_pool_id
    name = google_iam_workload_identity_pool.gitlab_saas.name
  }
}

output "provider" {
  description = "Google Workload Identity Pool Provider metadata."
  value = {
    id   = google_iam_workload_identity_pool_provider.gitlab_saas.workload_identity_pool_provider_id
    name = google_iam_workload_identity_pool_provider.gitlab_saas.name
  }
}
