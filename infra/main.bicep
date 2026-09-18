targetScope = 'resourceGroup'

@description('Globally unique Container App name.')
@minLength(2)
@maxLength(32)
param appName string = 'kql-validator-lab'

@description('Azure region for the Container App.')
param location string = resourceGroup().location

@description('Immutable private ACR image reference, preferably tagged with a Git commit SHA.')
param image string

@description('Registry provisioned by foundation.bicep containing the image.')
param registryName string

@description('Managed environment provisioned by foundation.bicep.')
param managedEnvironmentName string = '${appName}-env'

@description('Whether to mount an Azure Files custom schema catalog.')
param customSchemaEnabled bool = false

@description('Storage account provisioned by foundation.bicep for the optional read-only catalog mount.')
param storageAccountName string = ''

@description('Classic Azure Files share containing custom-schema.json.')
param schemaShareName string = 'schema-catalog'

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
}

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' existing = {
  name: managedEnvironmentName
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = if (customSchemaEnabled) {
  name: storageAccountName
}

resource schemaStorage 'Microsoft.App/managedEnvironments/storages@2025-01-01' = if (customSchemaEnabled) {
  parent: environment
  name: 'custom-schema'
  properties: {
    azureFile: {
      accountName: storage.name
      accountKey: storage!.listKeys().keys[0].value
      shareName: schemaShareName
      accessMode: 'ReadOnly'
    }
  }
}

resource pullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: '${appName}-pull'
}

var customSchemaEnvironmentVariables = customSchemaEnabled ? [
  {
    name: 'SchemaOverlay__Path'
    value: '/mnt/custom-schema/custom-schema.json'
  }
] : []

var customSchemaVolumeMounts = customSchemaEnabled ? [
  {
    volumeName: 'custom-schema'
    mountPath: '/mnt/custom-schema'
  }
] : []

var customSchemaVolumes = customSchemaEnabled ? [
  {
    name: 'custom-schema'
    storageType: 'AzureFile'
    storageName: 'custom-schema'
  }
] : []

module registryAccess './registry-access.bicep' = {
  name: '${appName}-acr-pull'
  params: {
    registryName: registryName
    principalId: pullIdentity.properties.principalId
  }
}

resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${pullIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: registry.properties.loginServer
          identity: pullIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'validator'
          image: image
          env: concat([
            {
              name: 'ASPNETCORE_ENVIRONMENT'
              value: 'Production'
            }
            {
              name: 'ReverseProxy__TrustForwardedHeaders'
              value: 'true'
            }
          ], customSchemaEnvironmentVariables)
          volumeMounts: customSchemaVolumeMounts
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health/live'
                port: 8080
                scheme: 'HTTP'
              }
              initialDelaySeconds: 5
              periodSeconds: 30
              timeoutSeconds: 5
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health/ready'
                port: 8080
                scheme: 'HTTP'
              }
              initialDelaySeconds: 2
              periodSeconds: 10
              timeoutSeconds: 5
              failureThreshold: 3
            }
          ]
        }
      ]
      volumes: customSchemaVolumes
      scale: {
        minReplicas: 0
        maxReplicas: 1
        rules: [
          {
            name: 'http-concurrency'
            custom: {
              type: 'http'
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
  dependsOn: [
    registryAccess
  ]
}

output appId string = app.id
output fqdn string = app.properties.configuration.ingress.fqdn
output url string = 'https://${app.properties.configuration.ingress.fqdn}'
output principalId string = pullIdentity.properties.principalId
output registryServer string = registry.properties.loginServer
