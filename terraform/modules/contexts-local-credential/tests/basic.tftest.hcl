
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

run "bastion_ca_file_is_not_world_writable" {
  command = plan

  override_data {
    target = data.terraform_remote_state.foundation_vault_bastion[0]
    values = {
      outputs = {
        bastion_vault = {
          listener_ca_cert_pem = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----"
        }
      }
    }
  }

  assert {
    condition     = local_file.bastion_ca_cert[0].file_permission == "0644"
    error_message = "the CA certificate file must be readable by others and writable by the owner alone"
  }

  assert {
    condition     = local_file.bastion_ca_cert[0].directory_permission == "0755"
    error_message = "the tls directory must not be writable by group or others"
  }
}
