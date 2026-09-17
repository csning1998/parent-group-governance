
module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"

  # This layer is the true source. The module default reads state from this layer via terraform_remote_state.
  # This override avoids a self-referential state read.
  bastion_vault_config = {
    ca_cert_path = "${path.root}/../../../vault/tls/ca.pem"
  }
}

locals {
  bastion_pki_inter_mount_path = var.pki_intermediate_mount_path
}

data "local_file" "bastion_vault_ca" {
  filename = module.local_credential_contexts.bastion_vault_config.ca_cert_path
}

# Documentation: documentation/architecture/platform-spire-parent-frontend.md Section 4 Item D, Item E.
# JWT-backed auth mounts share an identical five-grant ACL template.
locals {
  jwt_auth_backends = [
    { path_key = "gitlab-saas-jwt", label = "SaaS GitLab" },
  ]

  jwt_auth_backend_policy = join("\n\n", [
    for backend in local.jwt_auth_backends : trimspace(<<-EOT
      # ${backend.label} JWT Auth Backend Management.
      path "sys/auth/${backend.path_key}" {
        capabilities = ["create", "read", "update", "delete", "sudo"]
      }

      # ${backend.label} JWT Auth Mount Configuration.
      path "sys/mounts/auth/${backend.path_key}*" {
        capabilities = ["read", "create", "update"]
      }

      # ${backend.label} JWT Auth Mount Tuning.
      path "sys/auth/${backend.path_key}/tune" {
        capabilities = ["create", "read", "update"]
      }

      # ${backend.label} OIDC Configuration.
      path "auth/${backend.path_key}/config" {
        capabilities = ["create", "read", "update"]
      }

      # ${backend.label} Role Provisioning.
      path "auth/${backend.path_key}/role/*" {
        capabilities = ["create", "read", "update", "delete"]
      }
      EOT
    )
  ])
}
