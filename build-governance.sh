#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Repository constants. The KV path and its field are frozen names of this repository.
readonly cli="governance"
readonly sonar_project_key="csning1998-lab-parent-group-governance"
readonly sonar_token_path="secret/parent-group-governance/sonarqube/ci-analysis-bot"
readonly sonar_token_field="sonarqube_ci_token"
readonly scanner_image="docker.io/sonarsource/sonar-scanner-cli:12.1.0.3225_8.0.1"

# Workstation values, which an exported variable overrides.
readonly bastion_vault_addr="${BASTION_VAULT_ADDR:-https://172.16.0.1:8200}"
readonly bastion_vault_cacert="${BASTION_VAULT_CACERT:-$PWD/vault/tls/ca.pem}"
readonly sonar_host_url="${SONAR_HOST_URL:-http://127.0.0.1:9000}"

go test -C tools/"${cli}" -race -count=1 -coverprofile=coverage.out ./...

# The script carries the relative path setting of the scanner container, since the repository ignores .coveragerc.
coverage_rc=$(mktemp)
trap 'rm -f "$coverage_rc"' EXIT
printf '[run]\nrelative_files = True\n' >"$coverage_rc"
PYTHONDONTWRITEBYTECODE=1 COVERAGE_FILE="${coverage_rc}.data" uv run --no-project --with pytest --with pytest-cov \
    pytest -q -p no:cacheprovider ansible/roles/workstation_vault_audit/tests \
    --cov=ansible/roles/workstation_vault_audit/files --cov-config="$coverage_rc" --cov-report=xml:coverage.xml
rm -f "${coverage_rc}.data"

# A session token takes precedence over the token file of the vault CLI. The separate assignment stops the run on a
# failed read, which a prefix assignment of podman would ignore, and keeps the token out of every other command.
sonar_token=$(VAULT_ADDR="${bastion_vault_addr}" VAULT_CACERT="${bastion_vault_cacert}" \
    VAULT_TOKEN="${VAULT_TOKEN:-$(cat "$HOME/.vault-token")}" \
    vault kv get -field="${sonar_token_field}" "${sonar_token_path}")

# The scanner mounts only the analyzed trees read-only, since the Python indexer walks the whole base directory.
# The root .gitignore drives the SCM exclusion, which keeps generated files such as 0600 inventories unread.
SONAR_TOKEN="${sonar_token}" podman run --rm --network host \
    --security-opt label=type:spc_t \
    -e SONAR_HOST_URL="${sonar_host_url}" \
    -e SONAR_TOKEN \
    -e SONAR_SCANNER_OPTS="-Dsonar.projectKey=${sonar_project_key} -Dsonar.projectBaseDir=/usr/src -Dsonar.qualitygate.wait=true -Dsonar.sources=tools,terraform,ansible -Dsonar.exclusions=**/testdata/**,**/.terraform/** -Dsonar.tests=tools,ansible -Dsonar.test.inclusions=**/*_test.go,**/tests/test_*.py -Dsonar.go.coverage.reportPaths=tools/${cli}/coverage.out -Dsonar.python.coverage.reportPaths=coverage.xml" \
    -v "$PWD/coverage.xml:/usr/src/coverage.xml:ro" \
    -v "$PWD/tools:/usr/src/tools:ro" \
    -v "$PWD/terraform:/usr/src/terraform:ro" \
    -v "$PWD/ansible:/usr/src/ansible:ro" \
    -v "$PWD/.git:/usr/src/.git:ro" \
    -v "$PWD/.gitignore:/usr/src/.gitignore:ro" \
    "${scanner_image}"

go build -C tools/"${cli}" -o ../../"${cli}" ./cmd/"${cli}"

echo "built: $(pwd)/${cli}"
