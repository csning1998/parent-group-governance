
output "bastion_vault_brokered_policies" {
  description = "Names of the policies which the broker wrote for each tenant, and the exact policy names which an auth role of the tenant may carry, keyed by owner code."
  value = {
    for code in local.owner_codes : code => {
      policy_names   = sort([for name, policy in vault_policy.brokered : name if local.brokered[name].code == code])
      policy_ceiling = local.policy_ceiling[code]
    }
  }
}
