
# Downstream administration layers read the subgroup namespaces from the registry instead of the state of this layer.
resource "vault_kv_secret_v2" "registry_platform_gitlab_group_subgroups" {
  provider = vault.bastion
  mount    = "registry"
  name     = "platform/gitlab-group/subgroups"
  data_json = jsonencode({
    subgroup_ids = jsonencode(merge(
      { for key, group in gitlab_group.subgroups : key => tostring(group.id) },
      { for key, group in gitlab_group.nested_subgroups : key => tostring(group.id) },
    ))
  })
}
