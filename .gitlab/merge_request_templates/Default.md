# type(scope): description

## Summary

...

## Changes

### Core Architecture

1.  **Feature/Change A**: Description...
2.  **Feature/Change B**: Description...

### Fixes & Technical Debt

- **[Issue/Module Name]**:
    - _Problem_: Describe the root cause or the error encountered.
    - _Solution_: Describe the fix implementation.
- **[Issue/Module Name]**:
    - _Problem_: ...
    - _Solution_: ...

### Refactoring

- **[Topic]**: Description of the refactor.
- **[Topic]**: Description of the refactor.

### Verification

- [ ] **Plan Convergence**: `terraform plan` reports no unexpected changes across the affected layers.
- [ ] **Governance Propagation**: Group and project settings, labels, and CI/CD variables reflect the declared state on GitLab.
- [ ] **Service Health**: SonarQube, Vault, and runner containers report healthy status after the change.
- [ ] **Idempotency**: Repeated `terraform apply` execution does not alter existing resource state.
