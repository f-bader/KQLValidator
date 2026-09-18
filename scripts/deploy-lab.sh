#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

: "${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP}"
: "${AZURE_ACR_NAME:?Set AZURE_ACR_NAME to a globally unique registry name}"
: "${AZURE_STORAGE_ACCOUNT_NAME:?Set AZURE_STORAGE_ACCOUNT_NAME to a globally unique storage account name}"

AZURE_LOCATION="${AZURE_LOCATION:-westeurope}"
AZURE_APP_NAME="${AZURE_APP_NAME:-kql-validator-lab}"
AZURE_SCHEMA_SHARE_NAME="${AZURE_SCHEMA_SHARE_NAME:-schema-catalog}"
CUSTOM_SCHEMA_PATH="${CUSTOM_SCHEMA_PATH:-$repo_root/examples/custom-schema.json}"
[[ -f "$CUSTOM_SCHEMA_PATH" ]] || { echo "Catalog file does not exist: $CUSTOM_SCHEMA_PATH" >&2; exit 64; }
image_tag="$(git rev-parse --short=12 HEAD)"
source_revision="$(git rev-parse HEAD)"
image_name="kql-validator:$image_tag"
version="${VERSION:-$(git describe --tags --match 'v*' --abbrev=0 2>/dev/null | sed 's/^v//' || true)}"
version="${version:-0.0.0-lab}"

az account set --subscription "$AZURE_SUBSCRIPTION_ID"
az group show --name "$AZURE_RESOURCE_GROUP" >/dev/null

# This bootstrap is deliberately separate from the app revision so a retry after an
# image build or catalog update does not recreate the foundation resources.
az deployment group create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --template-file infra/foundation.bicep \
  --parameters \
    appName="$AZURE_APP_NAME" \
    location="$AZURE_LOCATION" \
    registryName="$AZURE_ACR_NAME" \
    storageAccountName="$AZURE_STORAGE_ACCOUNT_NAME" \
    schemaShareName="$AZURE_SCHEMA_SHARE_NAME" \
  >/dev/null

registry_server="$(az acr show --resource-group "$AZURE_RESOURCE_GROUP" --name "$AZURE_ACR_NAME" --query loginServer --output tsv)"

az acr build \
  --resource-group "$AZURE_RESOURCE_GROUP" \
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

storage_key="$(az storage account keys list \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --account-name "$AZURE_STORAGE_ACCOUNT_NAME" \
  --query '[0].value' \
  --output tsv)"
az storage file upload \
  --account-name "$AZURE_STORAGE_ACCOUNT_NAME" \
  --account-key "$storage_key" \
  --share-name "$AZURE_SCHEMA_SHARE_NAME" \
  --source "$CUSTOM_SCHEMA_PATH" \
  --path custom-schema.json \
  --overwrite true \
  >/dev/null

deployment="$(az deployment group create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --template-file infra/main.bicep \
  --parameters \
    appName="$AZURE_APP_NAME" \
    location="$AZURE_LOCATION" \
    image="$registry_server/kql-validator@$image_digest" \
    registryName="$AZURE_ACR_NAME" \
    managedEnvironmentName="${AZURE_APP_NAME}-env" \
    storageAccountName="$AZURE_STORAGE_ACCOUNT_NAME" \
    schemaShareName="$AZURE_SCHEMA_SHARE_NAME" \
  --query properties.outputs.url.value \
  --output tsv)"

"$repo_root/scripts/smoke-test.sh" "$deployment" SharedAudit NormalizeActor
echo "Azure lab deployment passed: $deployment"
