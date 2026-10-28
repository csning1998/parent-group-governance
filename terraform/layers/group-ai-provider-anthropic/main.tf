
# The federation issuer endpoints accept an org:admin OAuth token alone, which expires within minutes.
resource "anthropic_federation_issuer" "gitlab_saas" {
  name                     = "issuer-gitlab-saas"
  issuer_url               = "https://gitlab.com"
  check_jti                = true
  max_jwt_lifetime_seconds = 3600
  jwks                     = { type = "discovery" }

  lifecycle {
    prevent_destroy = true
  }
}
