# Self-hosting

KQL Validator runs without authentication. External ingress exposes its REST, MCP, and schema endpoints publicly. Submitted KQL is never executed, stored, or logged.

## Local Docker

Build and start the container:

```bash
docker build --tag kql-validator:local .
docker run --detach --name kql-validator --publish 8080:8080 kql-validator:local
```

Once `/health/ready` succeeds, run the smoke checks:

```bash
./scripts/smoke-test.sh http://127.0.0.1:8080
```

Inspect startup failures with `docker logs kql-validator`. See [custom catalogs](custom-schema-catalog.md#docker) to mount a schema file.

## Azure Container Apps

Requires Azure CLI, the Container Apps extension, and a signed-in identity with `Contributor` on the target resource group. Creating the app identity's `AcrPull` assignment also requires `Owner` or scoped `Role Based Access Control Administrator`. See [Azure access setup](lab-deployment.md#one-time-oidc-and-azure-access-setup) for a conditional assignment restricted to `AcrPull` and the `${AZURE_APP_NAME}-pull` identity.

Choose a dedicated resource group and globally unique registry name:

```bash
az extension add --name containerapp --upgrade
export AZURE_SUBSCRIPTION_ID='YOUR_SUBSCRIPTION_ID'
export AZURE_RESOURCE_GROUP='YOUR_RESOURCE_GROUP'
export AZURE_LOCATION='westeurope'
export AZURE_APP_NAME='kql-validator-lab'
export AZURE_ACR_NAME='YOUR_UNIQUE_ACR_NAME'
az group create --name "$AZURE_RESOURCE_GROUP" --location "$AZURE_LOCATION"
./scripts/deploy-lab.sh
```

The helper creates a Basic ACR, Consumption Container Apps environment, scale-to-zero app, and pull identity. It builds in ACR, deploys the immutable image digest, and runs REST/MCP smoke checks.

To mount a custom catalog, set both variables before running the helper:

```bash
export AZURE_STORAGE_ACCOUNT_NAME='YOUR_UNIQUE_STORAGE_NAME'
export CUSTOM_SCHEMA_PATH="$PWD/examples/custom-schema.json"
```

This creates a Standard_LRS storage account and classic Azure Files share, uploads `custom-schema.json`, and mounts it read-only at `/mnt/custom-schema`. `SchemaOverlay__Path` points to `/mnt/custom-schema/custom-schema.json`. Smoke checks include the catalog's known table and function.

To update the catalog, set `CUSTOM_SCHEMA_PATH` to the replacement file and rerun the helper. It uploads the file and creates a fresh revision. See [lab deployment](lab-deployment.md) for CI setup, custom domains, budget alerts, and teardown.

ACR has a fixed charge; Container Apps usage and optional Azure Files storage/transactions can add costs. Check regional pricing before deployment.

## Limits and health

By default, production REST and MCP requests share a per-IP token bucket with capacity 10 and one token replenished per second. A global bucket has capacity 100 and replenishes 25 tokens per second. Excess requests receive HTTP 429 with `Retry-After: 1`.

Analysis has a five-second deadline and can return HTTP 504. `/health/ready` fails when an active analysis exceeds 10 seconds; `/health/live` fails after 30 seconds. Health probes are exempt from rate limits. Container Apps uses these probes for routing and restarts.

## Public-schema disclosure

External ingress makes catalog names, function parameters, and columns publicly discoverable. Keep sensitive metadata out of bundled snapshots and mounted catalogs.
