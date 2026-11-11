#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Execution PATH MUST include ~/.local/bin to discover user-installed toolchains.
export PATH="${HOME}/.local/bin:${PATH}"

# Analysis secrets and repository identifiers SHALL adhere to parent-group-governance schemas.
readonly cli_module="governance"
readonly -a cli_binaries=(
    governance
)
readonly sonar_project_key="csning1998-lab-parent-group-governance"
readonly sonar_token_path="parent-group-governance/sonarqube/ci-analysis-bot"
readonly sonar_token_field="sonarqube_ci_token"
readonly scanner_image="docker.io/sonarsource/sonar-scanner-cli:12.1.0.3225_8.0.1"
# The linter version MUST equal the golangci_image tag of .gitlab-ci.yml.
readonly golangci_lint_module="github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0"

# Exported environment variables SHALL override default workstation analysis endpoints.
readonly sonar_host_url="${SONAR_HOST_URL:-http://127.0.0.1:9000}"

# Every go command MUST run on the toolchain directive of go.mod, which the distribution default GOTOOLCHAIN=local blocks.
export GOTOOLCHAIN=auto

# Static analysis and formatting MUST execute within the target Go module directory.
# The linter MUST be built by that toolchain because a linter built by an older Go refuses the module.
(cd tools/"${cli_module}" && go fmt ./... >/dev/null)
(cd tools/"${cli_module}" && go run "${golangci_lint_module}" run -c ../../.gitlab/golangci.yml ./...)

go test -C tools/"${cli_module}" -race -count=1 -coverprofile=coverage.out ./...

# Binary compilation MUST produce statically linked, path-independent executables matching deployment images.
# A failed analysis MUST NOT block the binary which bootstraps the Bastion Vault and SonarQube.
for binary in "${cli_binaries[@]}"; do
    CGO_ENABLED=0 go build -C tools/"${cli_module}" -trimpath -ldflags='-s -w' -o ../../"${binary}" ./cmd/"${binary}"
    echo "built: $(pwd)/${binary}"
done

# Coverage configuration MUST enforce relative paths to align host reports across scanner container mounts.
coverage_rc=$(mktemp)
trap 'rm -f "$coverage_rc"' EXIT
printf '[run]\nrelative_files = True\n' >"$coverage_rc"
PYTHONDONTWRITEBYTECODE=1 COVERAGE_FILE="${coverage_rc}.data" uv run --no-project --with pytest --with pytest-cov \
    pytest -q -p no:cacheprovider ansible/roles/workstation_vault_audit/tests \
    --cov=ansible/roles/workstation_vault_audit/files --cov-config="$coverage_rc" --cov-report=xml:coverage.xml
rm -f "${coverage_rc}.data"

# The analysis MUST be skipped when SonarQube does not report UP because the Bastion Vault and the token may not exist yet.
if ! curl -fsS --max-time 5 "${sonar_host_url}/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
    echo "skipped: SonarQube at ${sonar_host_url} is not UP" >&2
# The analysis MUST be skipped on uncommitted sources because a file without git blame counts entirely as new code.
elif [[ -n "$(git status --porcelain -- tools terraform ansible)" ]]; then
    echo "skipped: tools, terraform, or ansible holds uncommitted changes, commit them before the SonarQube analysis" >&2
elif ! command -v vault-proxy-env >/dev/null; then
    echo "skipped: vault-proxy-env is missing, run the first menu item of ./governance in parent-group-governance" >&2
# Token resolution MUST isolate proxy environment evaluation to prevent variable leaks and capture execution failures.
elif ! sonar_token=$(proxy_env=$(vault-proxy-env credential-distributor) && eval "${proxy_env}" &&
    vault kv get -mount=secret -field="${sonar_token_field}" "${sonar_token_path}"); then
    echo "skipped: the Bastion Vault returned no ${sonar_token_field} at secret/${sonar_token_path}" >&2
else
    # The scanner receives copies of the unignored files, the git history, and the coverage reports through podman cp,
    # which bind-mounts no host path and skips ignored trees such as .terraform, node_modules, and Packer output.
    # The copies carry the labels of the container and leave the host files out of reach of the analyzer.
    # The traps remove the scanner, whose stored configuration holds SONAR_TOKEN, on every exit path.
    scanner=""
    remove_scanner() { if [ -n "${scanner}" ]; then podman rm -f "${scanner}" >/dev/null 2>&1 || true; scanner=""; fi; }
    trap 'rm -f "$coverage_rc"; remove_scanner' EXIT
    trap 'remove_scanner; exit 130' INT TERM
    scanner=$(SONAR_TOKEN="${sonar_token}" podman create --network host \
        -e SONAR_HOST_URL="${sonar_host_url}" \
        -e SONAR_TOKEN \
        -e SONAR_SCANNER_OPTS="-Dsonar.projectKey=${sonar_project_key} -Dsonar.projectBaseDir=/usr/src -Dsonar.qualitygate.wait=true" \
        "${scanner_image}")
    {
        git ls-files -z --cached --others --exclude-standard -- tools terraform ansible sonar-project.properties .gitignore
        printf '%s\0' .git
        for report in coverage.xml tools/${cli_module}/coverage.out; do
            if [ -e "${report}" ]; then printf '%s\0' "${report}"; fi
        done
    } | tar -c --null --ignore-failed-read -T - | podman cp - "${scanner}:/usr/src"
    podman start --attach "${scanner}"
    remove_scanner
fi
