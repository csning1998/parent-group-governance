
data "gitlab_project" "this" {
  id = var.gitlab_project_id
}

data "gitlab_project_mirror_public_key" "this" {
  project_id = var.gitlab_project_id
  mirror_id  = gitlab_project_push_mirror.this.mirror_id
}

resource "github_repository" "this" {
  #checkov:skip=CKV_GIT_1: Repository visibility dynamically reflects the source GitLab project visibility.
  #checkov:skip=CKV2_GIT_1: Branch protection is governed upstream on GitLab while GitHub acts as a push mirror.
  name        = var.github_repository.name
  description = coalesce(var.github_repository.description, data.gitlab_project.this.description, "")
  visibility  = local.github_visibility[coalesce(var.github_repository.visibility, data.gitlab_project.this.visibility)]

  # An initial commit would diverge from the GitLab history before the first mirror push.
  auto_init = false

  has_issues      = false
  has_projects    = false
  has_wiki        = false
  has_discussions = false

  # Destroy archives the GitHub repository. Repository deletion would drop the published history.
  archive_on_destroy = true
}

resource "gitlab_project_push_mirror" "this" {
  project = var.gitlab_project_id
  # The mirror URL uses the Git SSH scheme, which keeps password material out of the remote URL.
  url         = "ssh://git@github.com/${var.github_repository.owner}/${var.github_repository.name}.git"
  auth_method = "ssh_public_key"
  host_keys   = local.github_ssh_host_keys
  enabled     = true

  # Publication includes every branch unless only_protected_branches is explicitly true.
  only_protected_branches = var.github_repository.only_protected_branches

  # A false value removes a GitHub ref absent from the GitLab project.
  keep_divergent_refs = var.github_repository.keep_divergent_refs
}

resource "github_repository_deploy_key" "this" {
  title      = "gitlab-push-mirror"
  repository = github_repository.this.name
  key        = data.gitlab_project_mirror_public_key.this.public_key
  read_only  = false
}
