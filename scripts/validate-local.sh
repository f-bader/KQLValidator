#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-/tmp/kql-validator-dotnet-home}"
export AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-/tmp/kql-validator-azure-config}"
export DOTNET_BUNDLE_EXTRACT_BASE_DIR="${DOTNET_BUNDLE_EXTRACT_BASE_DIR:-/tmp/kql-validator-bicep-extract}"

dotnet restore kql-validator.slnx --locked-mode
dotnet format kql-validator.slnx --verify-no-changes --no-restore
dotnet build kql-validator.slnx --configuration Release --no-restore --disable-build-servers -m:1 -nodeReuse:false
dotnet test tests/KqlValidator.Tests/KqlValidator.Tests.csproj --configuration Release --no-build --no-restore --disable-build-servers -m:1 -nodeReuse:false
dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj --configuration Release --no-restore --output artifacts/publish /p:UseAppHost=false
mkdir -p artifacts
dotnet list kql-validator.slnx package --vulnerable --include-transitive --format json --output-version 1 --no-restore > artifacts/vulnerable-packages.json
jq --exit-status '[.. | objects | .vulnerabilities? // empty] | flatten | length == 0' artifacts/vulnerable-packages.json >/dev/null
dotnet list kql-validator.slnx package --deprecated --include-transitive

if command -v az >/dev/null 2>&1; then
  az bicep version >/dev/null 2>&1 || az bicep install
  az bicep build --file infra/main.bicep --outfile /tmp/kql-validator-main.json
  az bicep build --file infra/budget.bicep --outfile /tmp/kql-validator-budget.json
fi

if command -v docker >/dev/null 2>&1; then
  docker build --tag kql-validator:local .
else
  echo "Docker is unavailable; the image build must be validated by the Azure ACR build gate."
fi
