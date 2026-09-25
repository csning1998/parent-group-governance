
# The Anthropic provider reads an org:admin OAuth token from ANTHROPIC_AUTH_TOKEN. The token expires within minutes.
resource "anthropic_federation_issuer" "gitlab" {
  name                     = "wif-gitlab-saas-host-admin"
  issuer_url               = "https://gitlab.com"
  check_jti                = true
  max_jwt_lifetime_seconds = 3600
  jwks                     = { type = "discovery" }

  lifecycle {
    prevent_destroy = true
  }
}
