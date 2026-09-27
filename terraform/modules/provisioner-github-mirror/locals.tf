
locals {
  # SSH push mirror authentication requires stored host keys before GitLab opens the connection.
  # Refer to https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
  github_ssh_host_keys = toset([
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
  ])

  # GitLab internal maps to GitHub private because GitHub does not provide an equivalent visibility level.
  github_visibility = {
    public   = "public"
    internal = "private"
    private  = "private"
  }
}
