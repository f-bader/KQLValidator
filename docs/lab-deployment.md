# Azure lab deployment

Maintainer setup for CI deployment, custom domains, Azure access, and teardown. Start with [self-hosting](self-hosting.md) to create the dedicated lab resources and configure optional custom catalogs.

## One-time resources

Complete one [local Azure deployment](self-hosting.md#azure-container-apps) before configuring CI. It creates the `${AZURE_APP_NAME}-pull` identity needed for the scoped role assignment below. Use a dedicated resource group and globally unique ACR name.

## Build, deploy, and validate

With the [deployment variables](self-hosting.md#azure-container-apps) set, validate and deploy:

```bash
./scripts/validate-local.sh
./scripts/deploy-lab.sh
```

The helper builds the Linux image in the lab's Basic ACR, deploys its immutable digest, and runs REST/MCP smoke checks. It passes the full Git revision into the image; discovery and validation responses report it alongside the content-derived schema version.

### Custom domain and certificate binding

The default URL uses the generated Container Apps HTTPS hostname. For a custom domain, create the DNS records and Azure-managed certificate in the selected environment first, then set both variables:

```bash
export AZURE_CUSTOM_DOMAIN='YOUR_CUSTOM_HOSTNAME'
export AZURE_MANAGED_CERTIFICATE_NAME='YOUR_EXISTING_MANAGED_CERTIFICATE_NAME'
```

These map to Bicep `customDomainName` and `managedCertificateName` and create an `SniEnabled` binding. Deployment and smoke checks use the custom hostname. For GitHub Actions, set the same variables in the `lab` environment:

```bash
export GITHUB_REPOSITORY='OWNER/REPOSITORY'
gh variable set AZURE_CUSTOM_DOMAIN --repo "$GITHUB_REPOSITORY" --env lab --body 'YOUR_CUSTOM_HOSTNAME'
gh variable set AZURE_MANAGED_CERTIFICATE_NAME --repo "$GITHUB_REPOSITORY" --env lab --body 'YOUR_EXISTING_MANAGED_CERTIFICATE_NAME'
```

An incomplete pair is rejected before Azure changes. Leaving both unset or empty deploys an empty binding list and removes any existing custom-domain binding on redeployment.

## GitHub Actions deployment

CI deploys after validation passes for pushes and manual runs from `main`, using the GitHub `lab` environment. Pull requests and other branches skip deployment. Configure required reviewers if repository policy requires approval.

The workflow uses GitHub OIDC with an existing user-assigned managed identity. Store tenant, subscription, and client IDs as repository secrets to mask them in public logs; use variables for the remaining settings:

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

For a custom catalog, set both variables. `CUSTOM_SCHEMA_PATH` is relative to the repository root:

```bash
gh variable set AZURE_STORAGE_ACCOUNT_NAME --repo "$GITHUB_REPOSITORY" --body 'YOUR_STORAGE_ACCOUNT_NAME'
gh variable set CUSTOM_SCHEMA_PATH --repo "$GITHUB_REPOSITORY" --body 'examples/custom-schema.json'
```

To require deployment approval, add **Required reviewers** under **Settings → Environments → lab**. The deployment job already targets this environment.

### One-time OIDC and Azure access setup

Enable immutable OIDC subjects for this repository:

```bash
gh api --method PUT "repos/$GITHUB_REPOSITORY/actions/oidc/customization/sub" \
  -F use_default=true \
  -F use_immutable_subject=true
```

The deployment identity's federated credential must match the environment's immutable subject. Obtain owner and repository IDs from the GitHub API and replace the placeholders:

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
export GITHUB_ENVIRONMENT='lab'
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

Grant `Contributor` on the resource group and `Role Based Access Control Administrator` restricted to the `AcrPull` role and app pull identity:

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

For another repository or environment, create a matching subject and federated credential using its names and immutable IDs, then update repository settings.

## Operations

See [hosting limits and health](self-hosting.md#limits-and-health) and [public-schema disclosure](self-hosting.md#public-schema-disclosure). The lab provisions no Log Analytics, Application Insights, VNet, Dapr, database, or telemetry exporter. Analysis meters exclude query text.

The [local gate](../CONTRIBUTING.md#local-quality-gate) covers build checks. GitHub Actions adds CodeQL, dependency review, container scanning, and weekly zizmor analysis.

## Optional budget alert

Budget alerts send notifications; charges continue after the threshold is reached:

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

Confirm the resource-group name before deletion. This removes all resources in the group, including the app, environment, identities, registry, images, and any catalog storage:

```bash
az group delete --name "$AZURE_RESOURCE_GROUP"
```
