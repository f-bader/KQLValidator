# Azure Monitor transformation validation

`POST /api/v1/validate-transformation` and the MCP tool `validate_azure_monitor_transformation` statically validate one DCR `transformKql` or `transform.KQL` expression. They do not accept a full DCR document and never contact Azure or execute the query.

## Request

Supply the transformation query and the typed columns exposed by Azure Monitor's virtual `source` table. Add `destinationColumns` when output compatibility should also be checked.

```json
{
  "query": "source | extend TimeGenerated = todatetime(Time) | project TimeGenerated, Message",
  "sourceColumns": [
    {"name": "Time", "type": "string"},
    {"name": "Message", "type": "string"}
  ],
  "destinationColumns": [
    {"name": "TimeGenerated", "type": "datetime"},
    {"name": "Message", "type": "string"}
  ]
}
```

Column names may require KQL bracket quoting, such as `['CEF Message']`. Types must be KQL scalar types. The query is limited to 64 KiB, and both schemas are limited to 5,000 columns combined.

## Validation behavior

The response includes inferred output columns, referenced source columns and functions, source spans, and Microsoft documentation links. Errors make `valid` false; warnings do not.

- Only Microsoft's documented transformation statements, operators, functions, and scalar-argument user-defined functions are accepted.
- A transformation must return tabular output with no more than one row per input record.
- `TimeGenerated` must be present with type `datetime`.
- A `parse` statement with 6–10 extracted columns produces performance warning `KQLP007`; more than 10 produces error `KQLT004`.
- Destination columns omitted from output are allowed. Output types that disagree with the destination are errors; extra output columns are warnings because Azure discards them after ingestion.

Invalid KQL is returned as HTTP 200 with `valid: false`. Invalid request shapes use Problem Details with HTTP 400.

The feature follows Microsoft's [supported transformation KQL](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql) and [query optimization guidance](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/query-optimization#break-up-large-parse-commands).
