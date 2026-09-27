
locals {
  required_services = toset([
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "aiplatform.googleapis.com",
    "generativelanguage.googleapis.com",
  ])
}

resource "google_project_service" "required" {
  for_each = local.required_services

  project                    = data.google_project.current.project_id
  service                    = each.key
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_iam_workload_identity_pool" "gitlab_saas" {
  depends_on = [google_project_service.required]

  project                   = data.google_project.current.project_id
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "GitLab SaaS Pool"
  description               = "Workload Identity Pool for GitLab SaaS pipelines."
  disabled                  = false

  lifecycle {
    prevent_destroy = true
  }

}

resource "google_iam_workload_identity_pool_provider" "gitlab_saas" {
  depends_on = [google_project_service.required]

  project                            = data.google_project.current.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.gitlab_saas.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_pool_provider_id
  display_name                       = "GitLab SaaS Provider"
  description                        = "OIDC identity provider for GitLab SaaS."
  disabled                           = false

  attribute_mapping = {
    "google.subject"           = "assertion.sub"
    "attribute.aud"            = "assertion.aud"
    "attribute.project_path"   = "assertion.project_path"
    "attribute.project_id"     = "assertion.project_id"
    "attribute.namespace_path" = "assertion.namespace_path"
    "attribute.namespace_id"   = "assertion.namespace_id"
    "attribute.ref"            = "assertion.ref"
    "attribute.ref_type"       = "assertion.ref_type"
  }

  attribute_condition = "assertion.namespace_path.startsWith(\"csning1998-lab\")"

  oidc {
    issuer_uri        = "https://gitlab.com"
    allowed_audiences = ["https://gitlab.com"]
  }

  lifecycle {
    prevent_destroy = true
  }

}
