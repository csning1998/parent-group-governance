
resource "google_apikeys_key" "gemini" {
  for_each = local.ai_review_repos

  name         = "gemini-${each.key}"
  display_name = "Gemini API Key -- ${each.key}"
  project      = var.gcp_project_id

  restrictions {
    api_targets {
      service = "generativelanguage.googleapis.com"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}
