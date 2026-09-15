
locals {
  # Target: group-topology state, hosted under this GitLab project.
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
  _state_auth = module.local_creds.gl_state_auth

  runner_description = "parent-group-governance-shared-podman-runner"
  runner_tag_list    = ["podman", "local"]

  runner_config_path = pathexpand("~/GitLab/csning1998-lab/parent-group-governance/gitlab-runner-configs/config.toml")
}
