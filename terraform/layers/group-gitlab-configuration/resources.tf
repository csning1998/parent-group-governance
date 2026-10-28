
resource "gitlab_group_label" "this" {
  for_each = local.group_labels

  group       = data.terraform_remote_state.group_topology.outputs.top_group_id
  name        = each.key
  color       = each.value.color
  description = each.value.description
}

resource "gitlab_group_variable" "review_secret" {
  for_each = local.group_variables_secret

  group     = data.terraform_remote_state.group_topology.outputs.top_group_id
  key       = each.key
  value     = each.value
  masked    = true
  hidden    = true
  raw       = true
  protected = false
}

resource "gitlab_group_variable" "plain" {
  for_each = local.group_variables_plain

  group     = data.terraform_remote_state.group_topology.outputs.top_group_id
  key       = each.key
  value     = each.value
  masked    = false
  protected = false
}
