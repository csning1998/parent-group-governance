#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

readonly cli="governance"

go test -C tools/"${cli}" -race -count=1 -coverprofile=coverage.out ./...

# The script carries the relative path setting of the scanner container, since the repository ignores .coveragerc.
coverage_rc=$(mktemp)
trap 'rm -f "$coverage_rc"' EXIT
printf '[run]\nrelative_files = True\n' >"$coverage_rc"
PYTHONDONTWRITEBYTECODE=1 COVERAGE_FILE="${coverage_rc}.data" uv run --no-project --with pytest --with pytest-cov \
    pytest -q -p no:cacheprovider ansible/roles/workstation_vault_audit/tests \
    --cov=ansible/roles/workstation_vault_audit/files --cov-config="$coverage_rc" --cov-report=xml:coverage.xml
rm -f "${coverage_rc}.data"

# The scanner mounts only the analyzed trees read-only, since the Python indexer walks the whole base directory.
SONAR_TOKEN=$(VAULT_ADDR='https://172.16.0.1:8200' VAULT_CACERT="$PWD/vault/tls/ca.pem" VAULT_TOKEN=$(cat "$HOME/.vault-token") vault kv get -field=sonarqube_ci_token secret/parent-group-governance/sonarqube/ci-analysis-bot) \
podman run --rm --network host \
    --security-opt label=type:spc_t \
    -e SONAR_HOST_URL="http://127.0.0.1:9000" \
    -e SONAR_TOKEN \
    -e SONAR_SCANNER_OPTS="-Dsonar.projectKey=csning1998-lab-parent-group-governance -Dsonar.projectBaseDir=/usr/src -Dsonar.qualitygate.wait=true -Dsonar.sources=tools,terraform,ansible -Dsonar.exclusions=**/testdata/**,**/.terraform/** -Dsonar.tests=tools,ansible -Dsonar.test.inclusions=**/*_test.go,**/tests/test_*.py -Dsonar.go.coverage.reportPaths=tools/${cli}/coverage.out -Dsonar.python.coverage.reportPaths=coverage.xml" \
    -v "$PWD/coverage.xml:/usr/src/coverage.xml:ro" \
    -v "$PWD/tools:/usr/src/tools:ro" \
    -v "$PWD/terraform:/usr/src/terraform:ro" \
    -v "$PWD/ansible:/usr/src/ansible:ro" \
    -v "$PWD/.git:/usr/src/.git:ro" \
    docker.io/sonarsource/sonar-scanner-cli:12.1.0.3225_8.0.1

go build -C tools/"${cli}" -o ../../"${cli}" ./cmd/"${cli}"

echo "built: $(pwd)/${cli}"
