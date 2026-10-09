

resource "gitlab_user_runner" "shared" {
  runner_type = "group_type"
  group_id    = data.terraform_remote_state.group_topology.outputs.top_group_id
  description = local.runner_description
  tag_list    = local.runner_tag_list
  locked      = true
}

# local_sensitive_file marks content as sensitive at the schema level, suppressing the
# rendered token from terraform plan/apply console and CI log output.
resource "local_sensitive_file" "runner_config" {
  content = templatefile("${path.module}/templates/config.toml.tftpl", {
    runner_name  = local.runner_description
    runner_token = gitlab_user_runner.shared.token
  })
  filename             = local.runner_config_path
  file_permission      = "0600"
  directory_permission = "0700"
}
