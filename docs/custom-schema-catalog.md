# Persistent custom schema catalogs

`SchemaOverlay__Path` is an optional startup-only setting pointing to a strict JSON catalog. The file is loaded once before readiness; a missing, malformed, or invalid file prevents the process from starting. Restart the container (or create a new Container Apps revision) after every catalog update.

The catalog describes only table and function contracts. It never stores or executes KQL function bodies.

Start with [examples/custom-schema.json](../examples/custom-schema.json):

```json
{
  "common": { "tables": [], "functions": [] },
  "environments": {
    "xdr": { "tables": [], "functions": [] },
    "sentinel": { "tables": [], "functions": [] },
    "unified": { "tables": [], "functions": [] }
  }
}
```

Every property uses lower camel case and is checked strictly. Tables use `name` and a non-empty `columns` list; a column uses `name` and KQL scalar `type`. Functions use `name`, optional `parameters`, and `returns`. A return is either `{ "kind": "scalar", "type": "string" }` or `{ "kind": "tabular", "columns": [...] }`; tabular returns may set `preserveInput: true`. Optional function parameters must follow required parameters.

`common` is applied to XDR and Sentinel. The service then makes Unified using its normal XDR-over-Sentinel conflict behavior, and finally applies the corresponding `xdr`, `sentinel`, and `unified` sections. Existing tables merge columns by name; a declared column replaces its type. New tables need their full column list. A declared function fully replaces its contract. The explicit Unified section wins over conflicts.

Unknown properties, duplicate declarations in a section, invalid identifiers/types, duplicate columns or parameters, malformed function signatures, and invalid return contracts cause startup failure. The process does not watch the file or read it per request.

## Docker

Build the image and bind-mount a catalog read-only:

```bash
docker build --tag kql-validator:local .
docker run --rm --publish 8080:8080 \
  --mount type=bind,src="$PWD/examples/custom-schema.json",dst=/catalog/custom-schema.json,readonly \
  --env SchemaOverlay__Path=/catalog/custom-schema.json \
  kql-validator:local
curl --fail http://127.0.0.1:8080/health/ready
```

After editing the file, stop and start the container again. Diagnose a failed startup with `docker logs`: the error identifies the catalog path and the strict-format problem.

## REST and MCP discovery

Persistent entries behave like ordinary environment schema entries and appear in validation, schema search, lookup, environment counts, and the content-derived schema version:

```bash
curl --fail http://127.0.0.1:8080/api/v1/environments/xdr/tables/SharedAudit
curl --fail http://127.0.0.1:8080/api/v1/environments/xdr/functions/NormalizeActor
curl --fail-with-body http://127.0.0.1:8080/api/v1/validate \
  --header 'content-type: application/json' \
  --data '{"query":"SharedAudit | project TimeGenerated, Actor","environment":"xdr","profile":"general"}'
```

For MCP, call `get_kql_table` with `{ "environment": "xdr", "table": "SharedAudit" }`, `get_kql_function` with `{ "environment": "xdr", "function": "NormalizeActor" }`, or `search_kql_schema`. These calls return the same effective catalog as REST.

## Persistent versus request-scoped

Use the mounted catalog for stable, server-wide workspace metadata shared by many callers. Its tables and functions are public to every client and request-scoped `extensions.tables` or `extensions.functions` cannot shadow them. Use request extensions for one-off validation, tenant-specific temporary schemas, and watchlist fields. Watchlists remain request-scoped because their fields are selected from a request's `_GetWatchlist` call.

The REST and MCP schema APIs are public on a public deployment. Table/function names, parameters, and columns are discoverable, so never place sensitive metadata in this catalog.
