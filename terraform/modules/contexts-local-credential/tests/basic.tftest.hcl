
# Exercises the coalesce() defaults. ca_cert_path defaults to a live copy fetched from the
# state of foundation-vault-bastion and written to tls/bastion-ca.pem at path.cwd.
run "meta_platform_default_call" {
  command = plan

  assert {
    condition     = output.bastion_vault_config.endpoint == "https://172.16.0.1:8200"
    error_message = "the default endpoint must be the Bastion Vault address"
  }

  assert {
    condition     = can(regex("bastion-ca\\.pem$", output.bastion_vault_config.ca_cert_path))
    error_message = "the default ca_cert_path must resolve to the generated tls/bastion-ca.pem file"
  }
}

run "explicit_endpoint_override" {
  command = plan

  variables {
    bastion_vault_config = {
      endpoint = "https://172.16.0.1:9200"
    }
  }

  assert {
    condition     = output.bastion_vault_config.endpoint == "https://172.16.0.1:9200"
    error_message = "an explicit endpoint override must be honored, not silently defaulted"
  }

  assert {
    condition     = can(regex("bastion-ca\\.pem$", output.bastion_vault_config.ca_cert_path))
    error_message = "overriding endpoint alone must leave ca_cert_path at its own default"
  }
}

run "state_auth_unused_when_ca_cert_path_overridden" {
  command = plan

  variables {
    bastion_vault_config = {
      ca_cert_path = "/tmp/fake-ca.pem"
    }
  }

  assert {
    condition     = output.state_auth_gitlab_saas.password == ""
    error_message = "a caller which never reads the state of foundation-vault-bastion must not be forced to read ~/.terraform.d/credentials.tfrc.json"
  }
}

run "fully_overridden_config" {
  command = plan

  variables {
    bastion_vault_config = {
      endpoint     = "https://vault.example.internal:8200"
      ca_cert_path = "/tmp/fake-ca.pem"
      token_path   = "fake-token-value"
    }
  }

  assert {
    condition     = output.bastion_vault_config.endpoint == "https://vault.example.internal:8200"
    error_message = "a fully overridden endpoint must be honored"
  }

  assert {
    condition     = output.bastion_vault_config.ca_cert_path == "/tmp/fake-ca.pem"
    error_message = "a fully overridden ca_cert_path must be honored, bypassing the real vault/tls/ file"
  }

  assert {
    condition     = output.bastion_vault_config.token_path == "fake-token-value"
    error_message = "a fully overridden token_path must be honored, bypassing ~/.vault-token"
  }
}
