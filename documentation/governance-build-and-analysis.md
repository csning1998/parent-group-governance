# Governance Build and Local Analysis

This document describes the build, test, and local SonarQube workflow executed by `build-governance.sh`.

## Section 1. Build Pipeline

1. **Toolchain and Path Resolution**: `build-governance.sh` prepends `${HOME}/.local/bin` to `PATH` to locate user installed toolchains and exports `GOTOOLCHAIN=auto` because Linux distribution packages default to `GOTOOLCHAIN=local`. Setting `GOTOOLCHAIN=auto` directs every `go` command to use the toolchain version declared in `tools/governance/go.mod`. The pinned linter module matches the `golangci_image` tag in `.gitlab-ci.yml`. Running `go run` under the `go.mod` toolchain builds `golangci-lint` with the same Go version as the module.
2. **Formatting, Testing, and Static Compilation**: The script runs `go fmt`, `golangci-lint`, and `go test -race -count=1 -coverprofile=coverage.out ./...` inside `tools/governance`. Binary compilation then runs `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'` to emit a statically linked and path independent `./governance` binary at the repository root. Compilation executes before SonarQube analysis. A failed or skipped scan therefore does not block the binary required to bootstrap the Bastion Vault and SonarQube.
3. **Python Audit Test Coverage**: The script executes `pytest` against `ansible/roles/workstation_vault_audit/tests` through `uv run --no-project` with a temporary coverage configuration enabling `relative_files = True` to emit `coverage.xml`. Relative coverage paths align host reports with the `/usr/src` mount path inside the scanner container.

## Section 2. Local SonarQube Analysis

1. **Project Key and Endpoint Configuration**: `build-governance.sh` derives `sonar_project_key` from the `origin` Git remote URL using GitLab `CI_PROJECT_PATH_SLUG` normalization rules. Local scans and CI scans therefore target the same SonarQube project key without hardcoding the group path. The endpoint defaults to `http://127.0.0.1:9000` and accepts overrides through `SONAR_HOST_URL`.
2. **Skip Conditions**: The script skips SonarQube analysis and exits successfully after building the binary when any of four conditions holds:
    - SonarQube at `SONAR_HOST_URL` does not report `"status":"UP"` on `/api/system/status`. The Bastion Vault and the analysis token may not exist during early workstation bootstrap.
    - Uncommitted changes exist under `tools`, `terraform`, or `ansible`. Files lacking `git blame` history count entirely as new code in SonarQube quality gates.
    - `vault-proxy-env` is absent from `PATH` because host proxy prerequisites have not been applied.
    - Reading `sonarqube_ci_token` from `secret/parent-group-governance/sonarqube/ci-analysis-bot` fails.
3. **Credential Isolation and Scanner Execution**: Token retrieval evaluates `vault-proxy-env credential-distributor-parent-group-governance` inside a command substitution subshell. Proxy environment variables therefore do not leak into the parent shell process. The script creates a scanner container with `--network host` and transfers source files through `tar` piped to `podman cp` without bind mounting the repository tree. The archive includes tracked and unignored files under `tools`, `terraform`, `ansible`, `sonar-project.properties`, `.gitignore`, `.git`, `coverage.xml`, and `tools/governance/coverage.out`. Ignored directories such as `.terraform` and runtime state remain excluded, and copied files receive container SELinux labels without exposing the host filesystem.

## Section 3. Constraints and Trade Offs

1. **Archive Blocking Factor**: `build-governance.sh` invokes `tar` with `-b 1`. Default tar blocking factors pad archives with trailing zero records, and `podman cp` fails on trailing padding after reaching the end of archive marker.
2. **Scanner Container Cleanup**: Exit and signal traps (`EXIT`, `INT`, `TERM`) remove the scanner container on every exit path. The container configuration retains `SONAR_TOKEN` in its stored environment metadata. Removing the container on exit prevents the credential from persisting in Podman state. Transferring files via `podman cp` incurs extra copy overhead on each local scan compared to a bind mount.
