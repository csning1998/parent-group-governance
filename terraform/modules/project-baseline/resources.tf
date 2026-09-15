
resource "gitlab_project" "this" {
  name             = var.name
  path             = var.name
  description      = var.description
  visibility_level = var.visibility
  namespace_id     = var.namespace_id

  merge_method           = "ff"
  squash_option          = "always"
  squash_commit_template = var.squash_commit_template

  only_allow_merge_if_pipeline_succeeds = var.only_allow_merge_if_pipeline_succeeds

  remove_source_branch_after_merge         = true
  ci_push_repository_for_job_token_allowed = true

  issues_access_level    = "enabled"
  wiki_access_level      = "disabled"
  initialize_with_readme = false
  shared_runners_enabled = false
}

resource "gitlab_branch_protection" "main" {
  project = gitlab_project.this.id
  branch  = "main"

  allowed_to_push  = [{ access_level = "no one" }]
  allowed_to_merge = [{ access_level = "maintainer" }]

  allow_force_push = false
}

locals {
  review_api_key_values = {
    CLAUDE_API_KEY = var.claude_api_key
    GEMINI_API_KEY = var.gemini_api_key
  }

  # for_each cannot accept a sensitive value; nonsensitive() strips the mark from the
  # presence check only, the actual value stays sensitive via the provider's own schema.
  review_api_key_enabled = nonsensitive({
    for k, v in local.review_api_key_values : k => true if v != ""
  })
}

resource "gitlab_project_variable" "review_api_key" {
  for_each = local.review_api_key_enabled

  project   = gitlab_project.this.id
  key       = each.key
  value     = local.review_api_key_values[each.key]
  masked    = true
  hidden    = true
  raw       = true
  protected = false
}
