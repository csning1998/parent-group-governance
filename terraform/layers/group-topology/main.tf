

resource "gitlab_group" "subgroups" {
  for_each = local.top_level_subgroups

  name             = each.value.name
  path             = each.key
  description      = each.value.description
  parent_id        = data.terraform_remote_state.foundation_group.outputs.group_id
  visibility_level = each.value.visibility
}

resource "gitlab_group" "nested_subgroups" {
  for_each = local.nested_subgroups

  name             = each.value.name
  path             = each.key
  description      = each.value.description
  parent_id        = gitlab_group.subgroups[each.value.parent].id
  visibility_level = each.value.visibility
}
