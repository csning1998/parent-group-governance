

locals {
  # Target: group-topology and group-sonarqube state, hosted under this GitLab project.
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"

  group_variables_secret = {
    SONAR_TOKEN = data.vault_kv_secret_v2.sonar_token.data["sonarqube_ci_token"]
  }

  # Job containers connect to SonarQube through the sonarqube compose service endpoint
  # on the sonarqube-ci-net bridge network configured in the runner network mode.
  group_variables_plain = {
    SONAR_HOST_URL = "http://sonarqube:9000"
  }

  group_labels = {
    # Scoped labels under the 'type::' prefix MUST specify the primary category of change. These labels are mutually exclusive within an Issue or Merge Request scope.
    "type::bug"           = { color = "#ef4444", description = "Identifies a defect or anomaly within the system." }
    "type::feature"       = { color = "#9333ea", description = "Specifies new functional features for implementation." }
    "type::enhancement"   = { color = "#6366f1", description = "Specifies proposed enhancements to existing system functionality." }
    "type::fix"           = { color = "#10b981", description = "Denotes resolution of a previously identified defect or functional issue." }
    "type::refactor"      = { color = "#14b8a6", description = "Denotes structural code modification without altering observable system behavior." }
    "type::documentation" = { color = "#06b6d4", description = "Denotes additions or updates to technical documentation." }
    "type::test"          = { color = "#059669", description = "Denotes creation or modification of automated test suites." }
    "type::question"      = { color = "#ec4899", description = "Identifies technical inquiries or operational requests." }
    "type::adhoc"         = { color = "#78716c", description = "Denotes a temporary, non-releasable change exempt from semantic version bump determination." }
    "type::chore"         = { color = "#a8a29e", description = "Denotes routine maintenance changes without releasable functional impact (build, chore, ci, revert, style)." }

    # Scoped labels under the 'area::' prefix MUST specify the functional domain or component impacted. These labels are mutually exclusive within an Issue or Merge Request scope.
    "area::CI"             = { color = "#2563eb", description = "Designates configurations or merge requests related to Continuous Integration." }
    "area::infrastructure" = { color = "#1d4ed8", description = "Designates configurations related to infrastructure provisioning and Infrastructure as Code (IaC)." }
    "area::frontend"       = { color = "#0284c7", description = "Designates client-side implementation and user interface components." }
    "area::backend"        = { color = "#4338ca", description = "Designates server-side implementation and Application Programming Interfaces (APIs)." }
    "area::observability"  = { color = "#f97316", description = "Designates telemetry, log aggregation, distributed tracing, and monitoring tasks." }

    # Scoped labels under the 'priority::' prefix MUST specify the schedule urgency. These labels are mutually exclusive within an Issue or Merge Request scope.
    "priority::P0-critical" = { color = "#dc2626", description = "Identifies a critical priority requiring immediate intervention." }
    "priority::P1-high"     = { color = "#ea580c", description = "Identifies a high priority scheduled for the immediate execution cycle." }
    "priority::P2-medium"   = { color = "#d97706", description = "Identifies a normal priority in the standard execution queue." }
    "priority::P3-low"      = { color = "#64748b", description = "Identifies a low priority scheduled for future execution." }

    # Scoped labels under the 'status::' prefix MUST track the execution state. These labels are mutually exclusive within an Issue or Merge Request scope.
    "status::pending"   = { color = "#eab308", description = "Indicates that progress is blocked pending external action or review." }
    "status::to-do"     = { color = "#3b82f6", description = "Indicates an item scheduled for implementation that has not yet commenced." }
    "status::duplicate" = { color = "#94a3b8", description = "Identifies a duplicate instance of an existing issue or merge request." }
    "status::wontfix"   = { color = "#64748b", description = "Indicates a formal decision to forego resolution or implementation." }
    "status::invalid"   = { color = "#475569", description = "Indicates an issue or merge request deemed out of scope or invalid." }

    # Scoped labels under the 'action::' prefix MUST specify required pipeline or review actions. These labels are mutually exclusive within an Issue or Merge Request scope.
    "action::needs-review"   = { color = "#7c3aed", description = "Indicates that the merge request is ready for formal code review." }
    "action::changes-needed" = { color = "#d97706", description = "Indicates that modifications are requested by reviewers prior to approval." }
    "action::blocked"        = { color = "#b91c1c", description = "Indicates that execution is blocked by external dependencies or upstream tasks." }

    # Labels lacking a prefix represent orthogonal metadata attributes and MAY be concurrently assigned regardless of scoped label selections.
    "security"         = { color = "#991b1b", description = "Denotes security vulnerability mitigations or hardening enhancements." }
    "breaking-change"  = { color = "#881337", description = "Denotes backward-incompatible API, schema, or configuration modifications." }
    "do-not-merge"     = { color = "#18181b", description = "Prevents merge operation execution regardless of pipeline status." }
    "good first issue" = { color = "#15803d", description = "Identifies introductory tasks suitable for onboarding contributors." }
    "help wanted"      = { color = "#22c55e", description = "Requests additional assistance to resolve the specified issue." }
    "issue"            = { color = "#64748b", description = "Denotes general issue tracking without specific category assignment." }
  }
}
