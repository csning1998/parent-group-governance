
# Exercises the coalesce() defaults which read real host files.
# This requires related files exist on the gitlab runner, per the assumption of the module.
run "meta_platform_default_call" {
  command = plan

  assert {
    condition     = output.bastion_vault_config.endpoint == "https://172.16.0.1:8200"
    error_message = "the default endpoint must be the Bastion Vault address"
  }

  assert {
    condition     = can(regex("/vault/tls/ca\\.pem$", output.bastion_vault_config.ca_cert_path))
    error_message = "the default ca_cert_path must resolve inside this repository's vault/tls/"
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
    condition     = can(regex("/vault/tls/ca\\.pem$", output.bastion_vault_config.ca_cert_path))
    error_message = "overriding endpoint alone must leave ca_cert_path at its own default"
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
