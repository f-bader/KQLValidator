targetScope = 'resourceGroup'

@description('Globally unique Container App name used to derive the managed environment name.')
@minLength(2)
@maxLength(32)
param appName string = 'kql-validator-lab'

@description('Azure region for the self-hosted resources.')
param location string = resourceGroup().location

@description('Globally unique Basic Azure Container Registry name.')
@minLength(5)
@maxLength(50)
param registryName string

@description('Globally unique standard storage account name for the static catalog file.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('Classic Azure Files share that holds custom-schema.json.')
param schemaShareName string = 'schema-catalog'

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource schemaShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileService
  name: schemaShareName
  properties: {
    accessTier: 'TransactionOptimized'
    enabledProtocols: 'SMB'
  }
}

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: '${appName}-env'
  location: location
  properties: {
    zoneRedundant: false
  }
}

resource pullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-pull'
  location: location
}

output managedEnvironmentName string = environment.name
output registryName string = registry.name
output registryServer string = registry.properties.loginServer
output storageAccountName string = storage.name
output schemaShareName string = schemaShare.name
output pullIdentityPrincipalId string = pullIdentity.properties.principalId
