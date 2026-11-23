#!/usr/bin/env bash
# Builds and tests the governance CLI with optional local SonarQube analysis. Refer to documentation/governance-build-and-analysis.md.
set -euo pipefail

cd "$(dirname "$0")"

export PATH="${HOME}/.local/bin:${PATH}"

readonly cli_module="governance"
readonly -a cli_binaries=(
    governance
)
# Matches GitLab CI_PROJECT_PATH_SLUG normalization for the SonarQube project key.
origin_project_path="$(git remote get-url origin)"
origin_project_path="${origin_project_path#*://*/}"
origin_project_path="${origin_project_path#*:}"
origin_project_path="${origin_project_path#/}"
origin_project_path="${origin_project_path%/}"
origin_project_path="${origin_project_path%.git}"
sonar_project_key="$(printf '%s' "${origin_project_path}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | cut -b1-63 | sed 's/^-*//;s/-*$//')"
readonly sonar_project_key
readonly sonar_token_path="parent-group-governance/sonarqube/ci-analysis-bot"
readonly sonar_token_field="sonarqube_ci_token"
readonly scanner_image="docker.io/sonarsource/sonar-scanner-cli:12.1.0.3225_8.0.1"
# Kept in sync with the golangci_image tag in .gitlab-ci.yml.
readonly golangci_lint_module="github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0"

readonly sonar_host_url="${SONAR_HOST_URL:-http://127.0.0.1:9000}"

# Overrides distribution GOTOOLCHAIN=local to honor the go.mod toolchain directive.
export GOTOOLCHAIN=auto

(cd tools/"${cli_module}" && go fmt ./... >/dev/null)
(cd tools/"${cli_module}" && go run "${golangci_lint_module}" run -c ../../.gitlab/golangci.yml ./...)

go test -C tools/"${cli_module}" -race -count=1 -coverprofile=coverage.out ./...

# Builds the CLI before SonarQube analysis because the binary bootstraps Vault and SonarQube.
for binary in "${cli_binaries[@]}"; do
    CGO_ENABLED=0 go build -C tools/"${cli_module}" -trimpath -ldflags='-s -w' -o ../../"${binary}" ./cmd/"${binary}"
    echo "built: $(pwd)/${binary}"
done

coverage_rc=$(mktemp)
trap 'rm -f "$coverage_rc"' EXIT
printf '[run]\nrelative_files = True\n' >"$coverage_rc"
PYTHONDONTWRITEBYTECODE=1 COVERAGE_FILE="${coverage_rc}.data" uv run --no-project --with pytest --with pytest-cov \
    pytest -q -p no:cacheprovider ansible/roles/workstation_vault_audit/tests \
    --cov=ansible/roles/workstation_vault_audit/files --cov-config="$coverage_rc" --cov-report=xml:coverage.xml
rm -f "${coverage_rc}.data"

if ! curl -fsS --max-time 5 "${sonar_host_url}/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
    echo "skipped: SonarQube at ${sonar_host_url} is not UP" >&2
elif [[ -n "$(git status --porcelain -- tools terraform ansible)" ]]; then
    echo "skipped: tools, terraform, or ansible contains uncommitted changes, commit them before the SonarQube analysis" >&2
elif ! command -v vault-proxy-env >/dev/null; then
    echo "skipped: vault-proxy-env is missing, run the first menu item of ./governance in parent-group-governance" >&2
elif ! sonar_token=$(proxy_env=$(vault-proxy-env credential-distributor-parent-group-governance) && eval "${proxy_env}" &&
    vault kv get -mount=secret -field="${sonar_token_field}" "${sonar_token_path}"); then
    echo "skipped: the Bastion Vault returned no ${sonar_token_field} at secret/${sonar_token_path}" >&2
else
    scanner=""
    remove_scanner() { if [ -n "${scanner}" ]; then podman rm -f "${scanner}" >/dev/null 2>&1 || true; scanner=""; fi; }
    # Removes the scanner container on exit because its stored config contains SONAR_TOKEN.
    trap 'rm -f "$coverage_rc"; remove_scanner' EXIT
    trap 'remove_scanner; exit 130' INT TERM
    scanner=$(SONAR_TOKEN="${sonar_token}" podman create --network host \
        -e SONAR_HOST_URL="${sonar_host_url}" \
        -e SONAR_TOKEN \
        -e SONAR_SCANNER_OPTS="-Dsonar.projectKey=${sonar_project_key} -Dsonar.projectBaseDir=/usr/src -Dsonar.qualitygate.wait=true" \
        "${scanner_image}")
    # Uses tar blocking factor 1 (-b 1) because podman cp fails on trailing archive padding.
    {
        git ls-files -z --cached --others --exclude-standard -- tools terraform ansible sonar-project.properties .gitignore
        printf '%s\0' .git
        for report in coverage.xml tools/${cli_module}/coverage.out; do
            if [ -e "${report}" ]; then printf '%s\0' "${report}"; fi
        done
    } | tar -c -b 1 --null --ignore-failed-read -T - | podman cp - "${scanner}:/usr/src"
    podman start --attach "${scanner}"
    remove_scanner
fi
