
output "top_group_id" {
  description = "Numeric identifier of the top-level group 'csning1998-lab', relayed from 00-foundation-group for downstream consumption."
  value       = data.terraform_remote_state.foundation_group.outputs.group_id
}

output "subgroup_ids" {
  description = "Map of subgroup paths to numeric identifiers, utilized by callers of module project-baseline to specify the namespace_id attribute."
  value = merge(
    { for key, group in gitlab_group.subgroups : key => group.id },
    { for key, group in gitlab_group.nested_subgroups : key => group.id },
  )
}
