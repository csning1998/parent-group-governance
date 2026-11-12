
# Enable AppRole auth backend
resource "vault_auth_backend" "approle" {
  provider = vault.bastion
  type     = "approle"
}

# Verifies CI job JWTs issued by the GitLab instance configured in var.gitlab_url.
resource "vault_jwt_auth_backend" "gitlab_saas" {
  provider           = vault.bastion
  path               = "gitlab-saas-ci-job-jwt-provider"
  type               = "jwt"
  oidc_discovery_url = var.gitlab_url
  bound_issuer       = var.gitlab_url
}

# Policy granting read-only access to CI secrets under parent-group-governance.
resource "vault_policy" "code_reviewer_read" {
  provider = vault.bastion
  name     = "gitlab-ci-code-reviewer-read"
  policy   = <<EOT
path "secret/data/parent-group-governance/ci/*" {
  capabilities = ["read"]
}
EOT
}

# JWT Auth Role pinned to gitlab-ci-with-code-reviewer project path.
resource "vault_jwt_auth_backend_role" "code_reviewer" {
  provider        = vault.bastion
  backend         = vault_jwt_auth_backend.gitlab_saas.path
  role_name       = "ci-code-reviewer"
  role_type       = "jwt"
  user_claim      = "project_path"
  bound_audiences = [var.gitlab_url]
  token_ttl       = 300
  token_max_ttl   = 600
  token_policies  = [vault_policy.code_reviewer_read.name]

  bound_claims = {
    project_path = "${var.gitlab_top_level_group_path}/gitlab-ci-with-code-reviewer"
  }
}
