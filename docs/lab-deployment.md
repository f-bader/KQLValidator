# Azure lab deployment

This runbook keeps the lab isolated and builds the Linux image inside Azure Container Registry. It does not publish to GHCR or any public repository.

## One-time resources

Choose globally unique registry and dedicated resource-group names:

```bash
az group create \
  --name rg-kql-validator-lab \
  --location westeurope \
  --tags application=kql-validator environment=lab

az acr create \
  --resource-group rg-kql-validator-lab \
  --name YOUR_UNIQUE_ACR_NAME \
  --location westeurope \
  --sku Basic \
  --admin-enabled false
```

A Basic registry is the lab's fixed-cost floor. West Europe public retail pricing was approximately US$0.1666/day in August 2026. Container Apps is configured for Consumption scale-to-zero and normally remains inside its monthly free grant at low traffic.

## Build, deploy, and validate

Run the complete local gate first:

```bash
./scripts/validate-local.sh
```

Then build in ACR, deploy the resulting immutable digest, and run the live REST/MCP smoke suite:

```bash
export AZURE_SUBSCRIPTION_ID='YOUR_SUBSCRIPTION_ID'
export AZURE_RESOURCE_GROUP='rg-kql-validator-lab'
export AZURE_ACR_RESOURCE_GROUP='rg-kql-validator-lab'
export AZURE_ACR_NAME='YOUR_UNIQUE_ACR_NAME'
export AZURE_LOCATION='westeurope'
export AZURE_APP_NAME='kql-validator-lab'

./scripts/deploy-lab.sh
```

The deployment creates a Consumption Container Apps environment, one scale-to-zero app, and a user-assigned identity with only `AcrPull` on the selected registry. It does not create Log Analytics, Application Insights, a VNet, Dapr, or a database.

## Optional budget alert

Budgets notify but do not cap or stop spending:

```bash
az deployment sub create \
  --location westeurope \
  --template-file infra/budget.bicep \
  --parameters \
    amount=10 \
    startDate="$(date -u +%Y-%m-01)" \
    contactEmails='["you@example.com"]'
```

## Inspect or remove the lab

```bash
az resource list --resource-group rg-kql-validator-lab --output table
az containerapp show --resource-group rg-kql-validator-lab --name kql-validator-lab
```

Deleting the dedicated resource group removes the app, environment, identity, registry, and stored images. Do this only when the lab is no longer needed:

```bash
az group delete --name rg-kql-validator-lab
```
