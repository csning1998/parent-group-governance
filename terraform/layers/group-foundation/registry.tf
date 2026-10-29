
# Downstream administration layers read the top-level group from the registry instead of the state of this layer.
resource "vault_kv_secret_v2" "registry_platform_gitlab_group_top_level" {
  provider = vault.bastion
  mount    = "registry"
  name     = "platform/gitlab-group/top-level"
  data_json = jsonencode({
    group_id  = tostring(gitlab_group.this.id)
    full_path = gitlab_group.this.full_path
  })
}
