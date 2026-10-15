# API and MCP

REST and Streamable HTTP MCP share the same validation and schema catalogs. `/openapi/v1.json` describes REST endpoints; MCP clients connect to `/mcp`. See the [quick start](../README.md#run-locally) for setup.

## Validate a query

Use `POST /api/v1/validate` with `query`, `environment`, and `profile`. Choose the intended platform: `xdr` for Defender XDR, `sentinel` for Sentinel, or `unified` for their combined catalog. Profiles are `general` for general-purpose queries, `hunting` for investigations, and `detection` for alert rules. Clarify an uncertain platform before validating.

MCP `tools/call` parameters:

```json
{
  "name": "validate_kql",
  "arguments": {
    "query": "DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId, FileName",
    "environment": "xdr",
    "profile": "hunting"
  }
}
```

Optional `target` selects deployment constraints. Hunting and detection requests infer a target when omitted; NRT requires an explicit platform target. See [lint configuration](lint-rules.md#configuration) for combinations, defaults, and lint controls.

Supply known custom schemas through request `extensions` or a [persistent catalog](custom-schema-catalog.md). Obtain actual declarations for missing objects before validating.

For DCR `transformKql` or `transform.KQL`, use `POST /api/v1/validate-transformation` or `validate_azure_monitor_transformation`. Supply the extracted expression and incoming stream columns. See [transformation requests](azure-monitor-transformations.md#request).

## MCP tools

| Task | Tool |
| --- | --- |
| Validate a query or detection rule | `validate_kql` |
| Validate a DCR transformation | `validate_azure_monitor_transformation` |
| List environments, versions, counts, and profiles | `list_kql_environments` |
| Find a table, column, or catalog function | `search_kql_schema` |
| Get a known table's columns and types | `get_kql_table` |
| Get a catalog function's signature and return schema | `get_kql_function` |
| Find structured columns and discriminator keys | `list_kql_structured_columns` |
| Inspect nested fields and parsing guidance | `get_kql_structured_column` |
| Inspect correlation keys and caveats | `get_kql_column_relations` |
| Inspect lint controls, applicability, and sources | `list_kql_lint_rules` |

Validate new or changed KQL and revalidate after repairs. Use [schema discovery](schema-catalog.md) when identifiers or types are uncertain. Tool and parameter descriptions provide the calling details.

## Responses and limits

- Inspect `valid`, diagnostics with source spans, and inferred output columns. A successful tool call can return `valid: false`; warnings can remain with `valid: true`.
- Invalid KQL returns HTTP 200 with `valid: false`. Invalid REST request shapes return HTTP 400 Problem Details.
- Queries are limited to 65,536 characters; HTTP request bodies are limited to 256 KiB.
- Responses retain up to 500 diagnostics, prioritizing errors, and add `KQLV001` on truncation. Validity uses all diagnostics.
- Analysis has a five-second deadline and can return HTTP 504. Production rate limits return HTTP 429 with `Retry-After: 1`; see [hosting limits](self-hosting.md#limits-and-health).

Static analysis uses bundled and mounted schemas without inspecting a live workspace. Runtime success, payload coverage, and detection effectiveness require checks against actual data.

All endpoints are unauthenticated. On deployments with external ingress, [catalog metadata is public](self-hosting.md#public-schema-disclosure).
