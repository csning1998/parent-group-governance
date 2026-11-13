
# The federation issuer endpoints accept only an org:admin OAuth token. The OAuth token expires within minutes.
resource "anthropic_federation_issuer" "gitlab_saas" {
  name                     = "issuer-gitlab-saas"
  issuer_url               = var.gitlab_url
  check_jti                = true
  max_jwt_lifetime_seconds = 3600
  jwks                     = { type = "discovery" }

  lifecycle {
    prevent_destroy = true
  }
}
