targetScope = 'subscription'

@description('Name of the optional lab budget.')
param budgetName string = 'kql-validator-lab'

@description('Monthly alert threshold in billing currency. This sends alerts and does not stop resources.')
@minValue(1)
param amount int = 10

@description('Recipients for actual and forecast budget notifications.')
param contactEmails array

@description('Budget start date, aligned to the first day of a month.')
param startDate string

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = if (length(contactEmails) > 0) {
  name: budgetName
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
    }
    notifications: {
      Actual80: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: contactEmails
        contactGroups: []
        contactRoles: []
      }
      Forecast100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: contactEmails
        contactGroups: []
        contactRoles: []
      }
    }
  }
}

output budgetCreated bool = length(contactEmails) > 0
