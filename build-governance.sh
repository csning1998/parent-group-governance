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
# The linter MUST be built by that toolchain, since a linter built by an older Go refuses the module.
(cd tools/"${cli_module}" && go fmt ./... >/dev/null)
(cd tools/"${cli_module}" && go run "${golangci_lint_module}" run -c ../../.gitlab/golangci.yml ./...)

go test -C tools/"${cli_module}" -race -count=1 -coverprofile=coverage.out ./...

# Coverage configuration MUST enforce relative paths to align host reports across scanner container mounts.
coverage_rc=$(mktemp)
trap 'rm -f "$coverage_rc"' EXIT
printf '[run]\nrelative_files = True\n' >"$coverage_rc"
PYTHONDONTWRITEBYTECODE=1 COVERAGE_FILE="${coverage_rc}.data" uv run --no-project --with pytest --with pytest-cov \
    pytest -q -p no:cacheprovider ansible/roles/workstation_vault_audit/tests \
    --cov=ansible/roles/workstation_vault_audit/files --cov-config="$coverage_rc" --cov-report=xml:coverage.xml
rm -f "${coverage_rc}.data"

# The analysis MUST be skipped when SonarQube does not report UP, since the Bastion Vault and the token may not exist yet.
if ! curl -fsS --max-time 5 "${sonar_host_url}/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
    echo "skipped: SonarQube at ${sonar_host_url} is not UP" >&2
# The analysis MUST be skipped on uncommitted sources, since a file without git blame counts entirely as new code.
elif [[ -n "$(git status --porcelain -- tools terraform ansible)" ]]; then
    echo "skipped: tools, terraform, or ansible holds uncommitted changes, commit them before the SonarQube analysis" >&2
else
    # Token resolution MUST isolate proxy environment evaluation to prevent variable leaks and capture execution failures.
    if ! command -v vault-proxy-env >/dev/null; then
        echo "vault-proxy-env is missing, run the first menu item of ./governance in parent-group-governance" >&2
        exit 1
    fi
    proxy_env=$(vault-proxy-env credential-distributor)
    sonar_token=$(eval "${proxy_env}" && vault kv get -mount=secret -field="${sonar_token_field}" "${sonar_token_path}")
    unset proxy_env

    # Container mounts MUST remain read-only and restricted to tracked source trees to prevent analyzer modification.
    SONAR_TOKEN="${sonar_token}" podman run --rm --network host \
        --security-opt label=type:spc_t \
        -e SONAR_HOST_URL="${sonar_host_url}" \
        -e SONAR_TOKEN \
        -e SONAR_SCANNER_OPTS="-Dsonar.projectKey=${sonar_project_key} -Dsonar.projectBaseDir=/usr/src -Dsonar.qualitygate.wait=true -Dsonar.sources=tools,terraform,ansible -Dsonar.exclusions=**/testdata/**,**/.terraform/**,**/*_test.go,**/tests/test_*.py -Dsonar.tests=tools,ansible -Dsonar.test.inclusions=**/*_test.go,**/tests/test_*.py -Dsonar.go.coverage.reportPaths=tools/${cli_module}/coverage.out -Dsonar.python.coverage.reportPaths=coverage.xml" \
        -v "$PWD/coverage.xml:/usr/src/coverage.xml:ro" \
        -v "$PWD/tools:/usr/src/tools:ro" \
        -v "$PWD/terraform:/usr/src/terraform:ro" \
        -v "$PWD/ansible:/usr/src/ansible:ro" \
        -v "$PWD/.git:/usr/src/.git:ro" \
        -v "$PWD/.gitignore:/usr/src/.gitignore:ro" \
        "${scanner_image}"
fi

# Binary compilation MUST produce statically linked, path-independent executables matching deployment images.
for binary in "${cli_binaries[@]}"; do
    CGO_ENABLED=0 go build -C tools/"${cli_module}" -trimpath -ldflags='-s -w' -o ../../"${binary}" ./cmd/"${binary}"
    echo "built: $(pwd)/${binary}"
done
