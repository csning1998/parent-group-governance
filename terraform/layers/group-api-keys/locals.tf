
module "local_creds" {
  # Resolves relative to the directory containing this file (terraform/layers/<this layer>),
  # two levels up to terraform/, then into modules/local-credential-contexts.
  source = "../../modules/local-credential-contexts"
}

locals {

  # Specifies target repositories whose CI configuration enables AI review components.
  # Repository LaTeX_Documents lacks CI integration and is excluded from key generation.
  ai_review_repos = toset([
    "second-brain",
    "on-premise-agent",
    "app-content-matter",
    "monte-carlo-portfolio-trader",
    "on-premise-gitlab-deployment",
    "template-project",
    "template-project-fullstack",
  ])

  claude_api_keys = data.vault_kv_secret_v2.claude_keys.data
}

check "claude_api_keys_complete" {
  assert {
    condition     = alltrue([for repo in local.ai_review_repos : contains(keys(local.claude_api_keys), repo) && local.claude_api_keys[repo] != ""])
    error_message = "secret/parent-group-governance/review-bot-api-keys/claude must contain a non-empty entry for every repository in local.ai_review_repos."
  }
}
