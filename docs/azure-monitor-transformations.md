# Azure Monitor transformation validation

`POST /api/v1/validate-transformation` and MCP `validate_azure_monitor_transformation` statically validate a DCR `transformKql` or `transform.KQL` expression. Extract the expression from the DCR before calling. Validation runs locally without contacting Azure or executing KQL.

## Request

Supply the query and actual incoming columns exposed by Azure Monitor's virtual `source` table. Add `destinationColumns` to check output compatibility. For MCP, pass this object as `arguments` to `validate_azure_monitor_transformation`:

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

Use KQL scalar types and bracket-quote column names when needed, such as `['CEF Message']`. The query limit is 65,536 characters; source and destination schemas allow 5,000 columns combined.

## Validation behavior

Responses include inferred output columns, referenced source columns/functions, diagnostic spans, and Microsoft documentation links. See [response semantics and limits](api-and-mcp.md#responses-and-limits).

- Supported features follow Microsoft's transformation catalog. User-defined functions require scalar arguments.
- A transformation must return tabular output with no more than one row per input record.
- `TimeGenerated` must be present with type `datetime`.
- A `parse` statement with 6–10 extracted columns produces performance warning `KQLP007`; more than 10 produces error `KQLT004`.
- Destination columns omitted from output are allowed. Output types that disagree with the destination are errors; extra output columns are warnings because Azure discards them after ingestion.
- Equivalent KQL scalar type aliases, such as `long` and `int64`, are compatible.

The feature follows Microsoft's [supported transformation KQL](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql) and [query optimization guidance](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/query-optimization#break-up-large-parse-commands).
