# Azure lab deployment

This runbook keeps the lab isolated and builds the Linux image inside its dedicated Basic Azure Container Registry. It deploys a public, unauthenticated Container App and does not publish images anywhere else. For the shorter self-hosting path, see [self-hosting.md](self-hosting.md).

## One-time resources

Choose a globally unique registry and dedicated resource-group names. The deployment helper creates the Basic ACR and Container Apps environment on its first run:

```bash
export AZURE_RESOURCE_GROUP='YOUR_RESOURCE_GROUP'
export AZURE_ACR_NAME='YOUR_UNIQUE_ACR_NAME'
export AZURE_LOCATION='YOUR_AZURE_REGION'

az group create \
  --name "$AZURE_RESOURCE_GROUP" \
  --location "$AZURE_LOCATION" \
  --tags application=kql-validator environment=lab

```

A Basic registry is the lab's fixed-cost floor; check current Azure Container Registry pricing for your region. Container Apps is configured for Consumption scale-to-zero and normally remains inside its monthly free grant at low traffic. When enabled, Azure Files capacity and transactions are charged separately.

## Build, deploy, and validate

Run the complete local gate first:

```bash
./scripts/validate-local.sh
```

The helper provisions foundation resources, builds in ACR, deploys the immutable digest, and runs REST/MCP smoke checks.

```bash
export AZURE_SUBSCRIPTION_ID='YOUR_SUBSCRIPTION_ID'
export AZURE_RESOURCE_GROUP='YOUR_RESOURCE_GROUP'
export AZURE_ACR_NAME='YOUR_UNIQUE_ACR_NAME'
export AZURE_LOCATION='YOUR_AZURE_REGION'
export AZURE_APP_NAME='YOUR_APP_NAME'

./scripts/deploy-lab.sh
```

To mount a persistent custom catalog, set both optional variables before running the helper. It then creates a standard storage account and classic Azure Files share, uploads the file as `custom-schema.json`, mounts it read-only, and includes catalog checks in the smoke suite:

```bash
export AZURE_STORAGE_ACCOUNT_NAME='YOUR_UNIQUE_STORAGE_ACCOUNT_NAME'
export CUSTOM_SCHEMA_PATH="$PWD/examples/custom-schema.json"
```

## GitHub Actions deployment

The CI workflow deploys only after its validation job passes. Pushes to `main` and manual runs from `main` use the GitHub `lab` environment. This repository does not currently configure a required-reviewer gate; add one when the repository policy requires it. Pull requests and runs from other branches never deploy.

The workflow uses GitHub OIDC and an existing user-assigned managed identity; no Azure client secret is stored in GitHub. The tenant, subscription, and client IDs are stored as repository **secrets** so public workflow logs mask them; the remaining values are ordinary variables. Add them, then configure any optional environment protection rules:

```bash
export GITHUB_REPOSITORY='OWNER/REPOSITORY'
gh secret set AZURE_SUBSCRIPTION_ID --repo "$GITHUB_REPOSITORY" --body 'YOUR_SUBSCRIPTION_ID'
gh secret set AZURE_TENANT_ID --repo "$GITHUB_REPOSITORY" --body 'YOUR_TENANT_ID'
gh secret set AZURE_CLIENT_ID --repo "$GITHUB_REPOSITORY" --body 'DEPLOYMENT_IDENTITY_CLIENT_ID'
gh variable set AZURE_RESOURCE_GROUP --repo "$GITHUB_REPOSITORY" --body 'YOUR_RESOURCE_GROUP'
gh variable set AZURE_LOCATION --repo "$GITHUB_REPOSITORY" --body 'YOUR_AZURE_REGION'
gh variable set AZURE_APP_NAME --repo "$GITHUB_REPOSITORY" --body 'YOUR_APP_NAME'
gh variable set AZURE_ACR_NAME --repo "$GITHUB_REPOSITORY" --body 'YOUR_ACR_NAME'
gh variable set AZURE_MANAGED_IDENTITY_NAME --repo "$GITHUB_REPOSITORY" --body 'YOUR_DEPLOYMENT_IDENTITY_NAME'
```

To enable the optional catalog in CI, configure both variables. `CUSTOM_SCHEMA_PATH` is relative to the repository root, for example `examples/custom-schema.json`:

```bash
gh variable set AZURE_STORAGE_ACCOUNT_NAME --repo "$GITHUB_REPOSITORY" --body 'YOUR_STORAGE_ACCOUNT_NAME'
gh variable set CUSTOM_SCHEMA_PATH --repo "$GITHUB_REPOSITORY" --body 'examples/custom-schema.json'
```

To add an approval gate, open **Settings → Environments → lab**, add a user or team under **Required reviewers**, and save the protection rule. The deployment job already targets this environment, so no workflow change is needed. Environment protection rules are available on public repositories on every GitHub plan.

### One-time OIDC and Azure access setup

Enable immutable OIDC subjects for this repository:

```bash
gh api --method PUT "repos/$GITHUB_REPOSITORY/actions/oidc/customization/sub" \
  -F use_default=true \
  -F use_immutable_subject=true
```

The federated credential on the deployment identity must use the immutable subject for the protected environment. The owner and repository IDs are available from the GitHub API; they are intentionally represented as placeholders here:

```bash
export AZURE_SUBSCRIPTION_ID='YOUR_SUBSCRIPTION_ID'
export AZURE_RESOURCE_GROUP='YOUR_RESOURCE_GROUP'
export AZURE_MANAGED_IDENTITY_NAME='YOUR_DEPLOYMENT_IDENTITY_NAME'
export AZURE_APP_NAME='YOUR_APP_NAME'
export GITHUB_REPOSITORY='OWNER/REPOSITORY'
export GITHUB_OWNER='YOUR_GITHUB_OWNER'
export GITHUB_REPOSITORY_NAME='YOUR_GITHUB_REPOSITORY'
export GITHUB_OWNER_ID='YOUR_GITHUB_OWNER_ID'
export GITHUB_REPOSITORY_ID='YOUR_GITHUB_REPOSITORY_ID'
export GITHUB_ENVIRONMENT='YOUR_GITHUB_ENVIRONMENT'
github_subject="repo:${GITHUB_OWNER}@${GITHUB_OWNER_ID}/${GITHUB_REPOSITORY_NAME}@${GITHUB_REPOSITORY_ID}:environment:${GITHUB_ENVIRONMENT}"

az identity federated-credential create \
  --name github-actions-deployment \
  --identity-name "$AZURE_MANAGED_IDENTITY_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --issuer https://token.actions.githubusercontent.com \
  --subject "$github_subject" \
  --audiences api://AzureADTokenExchange \
  --subscription "$AZURE_SUBSCRIPTION_ID"
```

Grant the deployment identity `Contributor` on the target resource group. Because the Bicep deployment maintains the Container App's `AcrPull` role assignment, also grant `Role Based Access Control Administrator` with a condition that permits only that role and the app's pull identity:

```bash
subscription_id="$AZURE_SUBSCRIPTION_ID"
resource_group="$AZURE_RESOURCE_GROUP"
deploy_principal_id="$(az identity show --name "$AZURE_MANAGED_IDENTITY_NAME" --resource-group "$resource_group" --subscription "$subscription_id" --query principalId --output tsv)"
pull_principal_id="$(az identity show --name "${AZURE_APP_NAME}-pull" --resource-group "$resource_group" --subscription "$subscription_id" --query principalId --output tsv)"
resource_group_scope="/subscriptions/$subscription_id/resourceGroups/$resource_group"
acr_pull_role_id="$(az role definition list --name AcrPull --query '[0].name' --output tsv)"
rbac_admin_role_id="$(az role definition list --name 'Role Based Access Control Administrator' --query '[0].name' --output tsv)"

az role assignment create \
  --assignee-object-id "$deploy_principal_id" \
  --assignee-principal-type ServicePrincipal \
  --role Contributor \
  --scope "$resource_group_scope"

condition="((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$acr_pull_role_id} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {$pull_principal_id})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$acr_pull_role_id} AND @Resource[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {$pull_principal_id}))"

az role assignment create \
  --assignee-object-id "$deploy_principal_id" \
  --assignee-principal-type ServicePrincipal \
  --role "$rbac_admin_role_id" \
  --scope "$resource_group_scope" \
  --condition "$condition" \
  --condition-version 2.0
```

Verify the setup before enabling deployments:

```bash
az identity federated-credential list \
  --identity-name "$AZURE_MANAGED_IDENTITY_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --subscription "$AZURE_SUBSCRIPTION_ID"

az role assignment list \
  --assignee-object-id "$deploy_principal_id" \
  --all \
  --query '[].{role:roleDefinitionName,scope:scope,condition:condition}'
```

For another repository or environment, use its owner/repository names and immutable IDs in the subject, create a matching federated credential, and update the repository variables. Never reuse a subject from another repository.

The deployment creates a Consumption Container Apps environment, one scale-to-zero app, a user-assigned identity with only `AcrPull` on the selected registry, and a Basic ACR. When `CUSTOM_SCHEMA_PATH` is set, it also creates a standard storage account with a classic Azure Files share. It does not create Log Analytics, Application Insights, a VNet, Dapr, or a database.

The app has external HTTPS ingress and no authentication. REST, MCP, schema, and lint-rule endpoints are public; do not deploy a Sentinel snapshot or custom catalog whose table, function, parameter, or column names are not approved for public disclosure. When configured, the deployment mounts the catalog read-only and passes the full Git revision into the image, so the discovery endpoint and validation responses can report the immutable source revision alongside the content-derived schema version.

REST and MCP requests share a production token bucket of 10 requests with one replenished token per second per client IP. Excess requests receive HTTP 429 and `Retry-After: 1`; health probes are exempt. Analysis is bounded to five seconds and can return HTTP 504. Readiness fails for an active analysis older than 10 seconds, while liveness fails after 30 seconds. Container Apps uses `/health/ready` and `/health/live` for deployment routing and restart decisions.

The local gate covers restore, formatting, build, tests, dependency auditing, publishing, and Bicep compilation. GitHub Actions additionally runs CodeQL, dependency review, high-severity container scanning, and weekly zizmor analysis. The app exposes privacy-safe analysis meters, but this lab deployment does not provision an exporter or telemetry backend.

## Optional budget alert

Budgets notify but do not cap or stop spending:

```bash
az deployment sub create \
  --location YOUR_AZURE_REGION \
  --template-file infra/budget.bicep \
  --parameters \
    amount=10 \
    startDate="$(date -u +%Y-%m-01)" \
    contactEmails='["YOUR_ALERT_EMAIL"]'
```

## Inspect or remove the lab

```bash
az resource list --resource-group "$AZURE_RESOURCE_GROUP" --output table
az containerapp show --resource-group "$AZURE_RESOURCE_GROUP" --name "$AZURE_APP_NAME"
```

Deleting the dedicated resource group removes the app, environment, identity, registry, and stored images. Do this only when the lab is no longer needed:

```bash
az group delete --name "$AZURE_RESOURCE_GROUP"
```
