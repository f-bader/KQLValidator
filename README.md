# KQL Validator

[![ci](https://github.com/f-bader/KQLValidator/actions/workflows/ci.yml/badge.svg)](https://github.com/f-bader/KQLValidator/actions/workflows/ci.yml)

An unauthenticated, stateless static KQL validator for Microsoft Defender XDR, Microsoft Sentinel, and Azure Monitor transformations. It offers REST and Streamable HTTP MCP; it never executes, stores, or logs submitted KQL.

## Start here

- [Run and self-host with Docker or Azure Container Apps](docs/self-hosting.md)
- [Add a persistent custom schema catalog](docs/custom-schema-catalog.md)
- [Connect an MCP client and use the API](#api-and-mcp)
- [Validate Azure Monitor transformations](docs/azure-monitor-transformations.md)
- [Configure lint rules](docs/lint-rules.md)
- [Maintain the Azure lab deployment](docs/lab-deployment.md)

## Run locally

Requires the .NET SDK pinned in `global.json`:

```bash
dotnet restore kql-validator.slnx
dotnet run --project src/KqlValidator.Api --urls http://127.0.0.1:8080
```

```bash
curl --fail-with-body http://127.0.0.1:8080/api/v1/validate \
  --header 'content-type: application/json' \
  --data '{"query":"DeviceEvents | take 1","environment":"xdr","profile":"general"}'
```

## API and MCP

`POST /api/v1/validate` validates KQL. `POST /api/v1/validate-transformation` validates transform KQL. `GET /api/v1/environments`, schema search and table/function lookup expose the effective catalog; `/openapi/v1.json` describes every REST endpoint. Health probes are `/health/live` and `/health/ready`.

Connect a Streamable HTTP MCP client to `http://127.0.0.1:8080/mcp`:

```bash
codex mcp add kql-validator --url http://127.0.0.1:8080/mcp
```

The MCP initialization instructions and tool/parameter descriptions guide agents during KQL authoring, editing, and review. Validate new or changed supported KQL, inspect diagnostics, and revalidate after repairs. Schema discovery is useful when identifiers or types are uncertain; skip it when the required schema is already known.

| Intent | Tool |
| --- | --- |
| Validate a query, advanced hunting query, or detection rule | `validate_kql` |
| Validate a DCR `transformKql` or `transform.KQL` expression | `validate_azure_monitor_transformation` |
| Discover effective schema environments, versions, counts, and profiles | `list_kql_environments` |
| Find an unknown table, column, or catalog function name | `search_kql_schema` |
| Inspect columns/types for a known table | `get_kql_table` |
| Inspect a known catalog function's signature and return schema | `get_kql_function` |
| Choose correlation keys and inspect relation caveats for a known table | `get_kql_column_relations` |
| Discover lint controls or explain a lint rule and its source | `list_kql_lint_rules` |

Choose `xdr` for Defender XDR, `sentinel` for Sentinel, or `unified` for their combined catalog. Choose `general` for general-purpose queries, `hunting` for investigations, or `detection` for alert rules. Use the intended platform; resolve ambiguity instead of using `unified` to hide schema errors. Catalogs include mounted custom declarations, but do not inspect a live workspace. Missing custom schemas must be supplied from known declarations, not invented.

Column relations from [XDRInternals](https://xdrinternals.com/data/column-relations.json) are bundled for offline discovery through `get_kql_column_relations` and `GET /api/v1/environments/{environment}/tables/{table}/relations?column=...`. Both endpoints must exist in the effective schema. Results include a catalog version and SHA-256 digest, identifier families, nested paths, guidance, notes, and available query examples. These relationships are community guidance, not an exhaustive list of valid joins or a guarantee of live matches. SchemaSync refreshes the snapshot and records its digest in the manifest.

The opt-in `community-correlations` lint set checks incompatible identifier families, case folding of token/AWS/GCP resource keys, and process-key joins missing device scope. It follows resolved columns through aliases and supported expressions; unfamiliar or ambiguous lineage remains unchecked. Select it alongside your desired existing sets, or enable individual `KQLR001`–`KQLR003` rules. See [lint rules](docs/lint-rules.md#column-correlations) for details.

Example `tools/call` parameters for hunting:

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

When omitted, `target` is inferred as `interactive-hunting` for hunting, `sentinel-scheduled` for Sentinel detection, or `defender-scheduled` for XDR/unified detection; general queries have no inferred target. NRT requires an explicit target: `sentinel-nrt` with `sentinel`/`detection`, or `defender-nrt` with `xdr` or `unified`/`detection`.

For a DCR, extract the transformation expression and supply the actual incoming stream schema. Do not pass the full DCR document:

```json
{
  "name": "validate_azure_monitor_transformation",
  "arguments": {
    "query": "source | extend TimeGenerated = todatetime(Time) | project TimeGenerated, Message",
    "sourceColumns": [{"name": "Time", "type": "string"}, {"name": "Message", "type": "string"}],
    "destinationColumns": [{"name": "TimeGenerated", "type": "datetime"}, {"name": "Message", "type": "string"}]
  }
}
```

For schema discovery, call `search_kql_schema` with `{"environment":"xdr","query":"Device","kind":"table","limit":10}`, then pass a returned name to `get_kql_table`. Search uses case-insensitive substrings; lookups use exact names, case-insensitively, and return no result when absent (null, represented as empty MCP content). Continue a search with its `nextCursor` and unchanged filters until `nextCursor` is null. Function lookup covers catalog functions, not every built-in KQL scalar function.

To inspect transformation rules, call `list_kql_lint_rules` with `{"profile":"transformation","target":"azure-monitor-transformation","environment":"azure-monitor"}`. Omit filters to discover all rules. See [lint controls and defaults](docs/lint-rules.md) before customizing ordinary query linting.

A successful tool call can return `valid: false`. Inspect `valid`, diagnostics with source spans, and inferred output columns; warnings can remain when `valid` is true. Static validation does not prove runtime success or detection effectiveness.

All REST and MCP endpoints are public when deployed with external ingress. Schema catalogs are enumerable, so do not put sensitive table, function, column, or workspace metadata in built-in snapshots or mounted custom catalogs.

## Quality gate

```bash
bash scripts/validate-local.sh
```

This runs locked restore, formatting, Release build, tests, publish, dependency checks, Bicep compilation, and a Docker build when Docker is available.
