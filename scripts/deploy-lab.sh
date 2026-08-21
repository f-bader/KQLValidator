#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

: "${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP}"
: "${AZURE_ACR_NAME:?Set AZURE_ACR_NAME to an existing registry}"

AZURE_LOCATION="${AZURE_LOCATION:-westeurope}"
AZURE_APP_NAME="${AZURE_APP_NAME:-kql-validator-lab}"
AZURE_ACR_RESOURCE_GROUP="${AZURE_ACR_RESOURCE_GROUP:-$AZURE_RESOURCE_GROUP}"
image_tag="$(git rev-parse --short=12 HEAD)"
source_revision="$(git rev-parse HEAD)"
image_name="kql-validator:$image_tag"
version="${VERSION:-$(git describe --tags --match 'v*' --abbrev=0 2>/dev/null | sed 's/^v//' || true)}"
version="${version:-0.0.0-lab}"

az account set --subscription "$AZURE_SUBSCRIPTION_ID"
az group show --name "$AZURE_RESOURCE_GROUP" >/dev/null
registry_server="$(az acr show --resource-group "$AZURE_ACR_RESOURCE_GROUP" --name "$AZURE_ACR_NAME" --query loginServer --output tsv)"

az acr build \
  --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
  --registry "$AZURE_ACR_NAME" \
  --image "$image_name" \
  --build-arg "SOURCE_REVISION=$source_revision" \
  --build-arg "VERSION=$version" \
  --file Dockerfile \
  .

image_digest="$(az acr manifest show-metadata \
  --registry "$AZURE_ACR_NAME" \
  --name "$image_name" \
  --query digest \
  --output tsv)"

deployment="$(az deployment group create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --template-file infra/main.bicep \
  --parameters \
    appName="$AZURE_APP_NAME" \
    location="$AZURE_LOCATION" \
    image="$registry_server/kql-validator@$image_digest" \
    registryName="$AZURE_ACR_NAME" \
    registryResourceGroupName="$AZURE_ACR_RESOURCE_GROUP" \
  --query properties.outputs.url.value \
  --output tsv)"

"$repo_root/scripts/smoke-test.sh" "$deployment"
echo "Azure lab deployment passed: $deployment"
