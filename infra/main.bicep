targetScope = 'resourceGroup'

@description('Globally unique Container App name.')
@minLength(2)
@maxLength(32)
param appName string = 'kql-validator-lab'

@description('Azure region for the Container Apps environment.')
param location string = resourceGroup().location

@description('Immutable private ACR image reference, preferably tagged with a Git commit SHA.')
param image string

@description('Existing Azure Container Registry name containing the image.')
param registryName string

@description('Resource group containing the existing registry.')
param registryResourceGroupName string = resourceGroup().name

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
  scope: resourceGroup(registryResourceGroupName)
}

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: '${appName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'none'
    }
    zoneRedundant: false
  }
}

resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: appName
  location: location
  identity: {
    type: 'SystemAssigned'
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
          identity: 'system'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'validator'
          image: image
          env: [
            {
              name: 'ASPNETCORE_ENVIRONMENT'
              value: 'Production'
            }
          ]
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
}

module registryAccess './registry-access.bicep' = {
  name: '${appName}-acr-pull'
  scope: resourceGroup(registryResourceGroupName)
  params: {
    registryName: registryName
    principalId: app.identity.principalId
  }
}

output appId string = app.id
output fqdn string = app.properties.configuration.ingress.fqdn
output url string = 'https://${app.properties.configuration.ingress.fqdn}'
output principalId string = app.identity.principalId
output registryServer string = registry.properties.loginServer
