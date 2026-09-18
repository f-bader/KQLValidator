# Self-hosting

KQL Validator is deliberately unauthenticated and public when external ingress is enabled. It statically analyzes KQL only: it never executes submitted KQL, persists requests, or makes runtime Azure API calls. Mounted schema catalogs are static configuration files, not a runtime data integration.

## Local Docker

Build, run, verify, and update a read-only catalog:

```bash
docker build --tag kql-validator:local .
docker run --rm --publish 8080:8080 \
  --mount type=bind,src="$PWD/examples/custom-schema.json",dst=/catalog/custom-schema.json,readonly \
  --env SchemaOverlay__Path=/catalog/custom-schema.json \
  kql-validator:local
./scripts/smoke-test.sh http://127.0.0.1:8080 SharedAudit NormalizeActor
```

Update the host file and restart the container. An invalid file is intentional fail-fast behavior; inspect `docker logs` for the catalog error. See [custom-schema-catalog.md](custom-schema-catalog.md) for the format.

## Azure Container Apps

Prerequisites: Azure CLI plus the Container Apps extension, a signed-in identity with `Contributor` on the target resource group, and either `Owner` or scoped `Role Based Access Control Administrator` permission to create the app identity's `AcrPull` role assignment. The foundation stage creates the `${AZURE_APP_NAME}-pull` identity; the latter permission can use the existing conditional-assignment approach in [lab-deployment.md](lab-deployment.md), restricted to the `AcrPull` role and that identity.

Choose globally unique registry and storage-account names, create the resource group, then use the fixed deployment helper:

```bash
az extension add --name containerapp --upgrade
export AZURE_SUBSCRIPTION_ID='YOUR_SUBSCRIPTION_ID'
export AZURE_RESOURCE_GROUP='YOUR_RESOURCE_GROUP'
export AZURE_LOCATION='westeurope'
export AZURE_APP_NAME='kql-validator-lab'
export AZURE_ACR_NAME='YOUR_UNIQUE_ACR_NAME'
export AZURE_STORAGE_ACCOUNT_NAME='YOUR_UNIQUE_STORAGE_NAME'
export CUSTOM_SCHEMA_PATH="$PWD/examples/custom-schema.json"
az group create --name "$AZURE_RESOURCE_GROUP" --location "$AZURE_LOCATION"
./scripts/deploy-lab.sh
```

The helper provisions a [Basic ACR](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-skus), Standard_LRS storage account, classic Azure Files share, and Container Apps environment; builds the image in ACR; uploads `custom-schema.json`; deploys the immutable image digest; and checks readiness plus a known custom table/function. The app uses the [Container Apps Azure Files mount](https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts) in `ReadOnly` mode at `/mnt/custom-schema` and sets `SchemaOverlay__Path=/mnt/custom-schema/custom-schema.json`.

To update the catalog, set `CUSTOM_SCHEMA_PATH` to the replacement file and rerun the helper; it uploads the file and creates a fresh app revision. To tear down a dedicated installation, run `az group delete --name "$AZURE_RESOURCE_GROUP"` after confirming the exact resource group.

Basic ACR is appropriate for low-usage installations, but has a fixed monthly charge. Container Apps Consumption can scale to zero and may fit within its free grant at light use. Azure Files storage and requests also cost money; check current regional pricing and set a budget alert with `infra/budget.bicep`. Budget alerts notify only—they do not stop charges.

## Public-schema disclosure

REST and MCP expose table/function lookup and schema search without authentication. A mounted catalog's names, parameters, and columns are therefore publicly discoverable. Keep sensitive names, business labels, and metadata out of it. This applies equally to checked-in Sentinel snapshots and persistent custom declarations.
