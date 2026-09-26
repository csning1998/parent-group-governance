
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
  # for_each cannot accept a sensitive value; nonsensitive() strips the mark from the
  # keys only, the actual value stays sensitive via the provider's own schema.
  extra_variable_keys = nonsensitive(toset(keys(var.extra_variables)))
}

resource "gitlab_project_variable" "extra" {
  for_each = local.extra_variable_keys

  project   = gitlab_project.this.id
  key       = each.value
  value     = var.extra_variables[each.value]
  masked    = true
  hidden    = true
  raw       = true
  protected = false
}

resource "gitlab_project_job_token_scope" "this" {
  for_each          = toset([for id in var.inbound_job_token_scope_project_ids : tostring(id)])
  project           = gitlab_project.this.id
  target_project_id = tonumber(each.value)
}
