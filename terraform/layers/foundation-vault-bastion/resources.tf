
# Documentation: documentation/architecture/platform-spire-parent-frontend.md Section 4 Item E.
resource "vault_policy" "terraform_admin" {
  provider = vault.bastion
  name     = "terraform-admin-policy"
  policy   = <<EOT
# [1] KV v2 Data Operations.
path "secret/data/meta-platform/*" {
  capabilities = ["read", "create", "update", "delete"]
}

# [2] KV v2 Metadata Operations.
path "secret/metadata/meta-platform/*" {
  capabilities = ["read", "list", "delete"]
}

# [3] KV v2 Version Deletion.
path "secret/delete/meta-platform/*" {
  capabilities = ["update"]
}

# [4] KV v2 Version Destruction.
path "secret/destroy/meta-platform/*" {
  capabilities = ["update"]
}

# [4a] KV v2 Preflight Mount Lookup.
path "sys/internal/ui/mounts/secret/*" {
  capabilities = ["read"]
}

# [4b] Credential Bootstrap Data Operations.
path "secret/data/parent-group-governance/*" {
  capabilities = ["read", "create", "update", "delete"]
}

# [4c] Credential Bootstrap Metadata Operations.
path "secret/metadata/parent-group-governance/*" {
  capabilities = ["read", "list", "delete"]
}

# [4d] Credential Bootstrap Version Deletion.
path "secret/delete/parent-group-governance/*" {
  capabilities = ["update"]
}

# [4e] Credential Bootstrap Version Destruction.
path "secret/destroy/parent-group-governance/*" {
  capabilities = ["update"]
}

# [5] Bootstrap Certificate Issuance.
path "${local.bastion_pki_inter_mount_path}/issue/*" {
  capabilities = ["create", "update"]
}

# [6] PKI Mount Configuration Read.
path "sys/mounts/${local.bastion_pki_inter_mount_path}" {
  capabilities = ["read"]
}

# [7] Intermediate CA Signing.
path "${local.bastion_pki_inter_mount_path}/root/sign-intermediate" {
  capabilities = ["create", "update"]
}

# [8] Auth Mount Table Inspection.
path "sys/auth" {
  capabilities = ["read"]
}

${local.jwt_auth_backend_policy}

# [9] AppRole Role Management: consumer-owned AppRoles this AppRole itself issues.
path "auth/approle/role/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# [10] ACL Policy Management: consumer-owned Vault access policies this AppRole itself issues.
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# [11] PKI Role Management: consumer-owned leaf certificate roles under the Bootstrap
# Issuing Intermediate.
path "${local.bastion_pki_inter_mount_path}/roles/*" {
  capabilities = ["create", "read", "update", "delete"]
}
EOT
}

# Enable AppRole auth backend
resource "vault_auth_backend" "approle" {
  provider = vault.bastion
  type     = "approle"
}

# Create the Terraform AppRole
resource "vault_approle_auth_backend_role" "terraform_admin" {
  provider       = vault.bastion
  backend        = vault_auth_backend.approle.path
  role_name      = "terraform-admin-role"
  token_policies = [vault_policy.terraform_admin.name]
  token_ttl      = 60 * 60     # 1 Hour
  token_max_ttl  = 60 * 60 * 4 # 4 Hours
}

resource "vault_approle_auth_backend_role_secret_id" "terraform_admin" {
  provider  = vault.bastion
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.terraform_admin.role_name
}

resource "vault_kv_secret_v2" "terraform_admin_auth" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/terraform/approle"
  data_json = jsonencode({
    role_id   = vault_approle_auth_backend_role.terraform_admin.role_id
    secret_id = vault_approle_auth_backend_role_secret_id.terraform_admin.secret_id
  })
}

# GitLab SaaS JWT Auth Backend.
resource "vault_jwt_auth_backend" "gitlab_saas" {
  provider           = vault.bastion
  path               = "gitlab-saas-jwt"
  type               = "jwt"
  oidc_discovery_url = "https://gitlab.com"
  bound_issuer       = "https://gitlab.com"
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
  bound_audiences = ["https://gitlab.com"]
  token_ttl       = 300
  token_max_ttl   = 600
  token_policies  = [vault_policy.code_reviewer_read.name]

  bound_claims = {
    project_path = "csning1998-lab/gitlab-ci-with-code-reviewer"
  }
}
