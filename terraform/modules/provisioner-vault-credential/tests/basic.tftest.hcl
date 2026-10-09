
mock_provider "vault" {}
mock_provider "random" {}

# Mirrors the module.keepalived_credential call of a security-credentials layer.
run "keepalived_credential" {
  command = plan

  variables {
    vault_credential_context = {
      kv_namespace = "example-platform/haproxy-frontend"
      domain       = "haproxy"
      component    = "frontend"
      generate = {
        keepalived_auth_pass = { length = 32 }
      }
    }
  }

  assert {
    condition     = vault_kv_secret_v2.this.mount == "secret"
    error_message = "kv_mount should default to secret when unset"
  }

  assert {
    condition     = vault_kv_secret_v2.this.name == "example-platform/haproxy-frontend/haproxy/frontend"
    error_message = "secret path must compose kv_namespace/domain/component"
  }
}

# Mirrors the module.keycloak_frontend call of a security-credentials layer.
run "keycloak_frontend" {
  command = plan

  variables {
    vault_credential_context = {
      kv_namespace = "example-platform/keycloak-frontend"
      domain       = "keycloak"
      component    = "frontend"
      static = {
        keycloak_admin_user = "admin"
        keycloak_db_user    = "keycloak"
      }
      generate = {
        keycloak_admin_password = { length = 32 }
        keycloak_db_password    = { length = 32 }
      }
    }
  }
}

# Mirrors the module.service_identity call of a security-vault-guest-identity layer, the
# for_each case where generate falls back to {} (lookup default) for a key with no password.
run "service_identity_empty_generate" {
  command = plan

  variables {
    vault_credential_context = {
      kv_namespace = "example-platform/ssh-identity"
      domain       = "gitlab-runner"
      component    = "frontend"
      static = {
        ssh_private_key_b64 = "ZmFrZS1rZXk="
        ssh_public_key_b64  = "ZmFrZS1wdWJrZXk="
      }
    }
  }

  assert {
    condition     = length(random_password.this) == 0
    error_message = "an empty generate map must not create any random_password resources"
  }
}

run "fully_empty_payload" {
  command = plan

  variables {
    vault_credential_context = {
      kv_namespace = "test/empty"
      domain       = "test"
      component    = "empty"
    }
  }

  assert {
    condition     = length(random_password.this) == 0
    error_message = "omitting both generate and static must create zero random_password resources"
  }
}

run "custom_kv_mount" {
  command = plan

  variables {
    vault_credential_context = {
      kv_mount     = "kv-transit"
      kv_namespace = "test/custom-mount"
      domain       = "test"
      component    = "frontend"
    }
  }

  assert {
    condition     = vault_kv_secret_v2.this.mount == "kv-transit"
    error_message = "an explicit kv_mount must override the secret mount default"
  }
}

run "special_character_generation" {
  command = plan

  variables {
    vault_credential_context = {
      kv_namespace = "test/special"
      domain       = "test"
      component    = "frontend"
      generate = {
        with_special    = { length = 40, special = true }
        without_special = { length = 20 }
      }
    }
  }

  assert {
    condition     = random_password.this["with_special"].min_special == 1
    error_message = "special = true must require at least one special character"
  }

  assert {
    condition     = random_password.this["without_special"].min_special == 0
    error_message = "special defaulting to false must not require a special character"
  }

  assert {
    condition     = random_password.this["without_special"].length == 20
    error_message = "each generate entry must keep its own requested length"
  }
}

# When generate and static declare the same key, the generated random value must win. The
# generated value is applied last in merge(). A silent argument-order change in resources.tf
# would flip this precedence without triggering any type error.
run "generate_overrides_static_on_key_collision" {
  command = apply

  variables {
    vault_credential_context = {
      kv_namespace = "test/collision"
      domain       = "test"
      component    = "frontend"
      static = {
        shared_key = "static-value"
      }
      generate = {
        shared_key = { length = 16 }
      }
    }
  }

  assert {
    condition     = jsondecode(vault_kv_secret_v2.this.data_json)["shared_key"] == random_password.this["shared_key"].result
    error_message = "a key present in both generate and static must resolve to the generated value"
  }
}
