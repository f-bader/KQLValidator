# Persistent custom schema catalogs

Set optional `SchemaOverlay__Path` to a strict JSON catalog. It loads once before readiness; a missing or invalid file prevents startup. Restart the container or create a new Container Apps revision after updates.

Catalogs declare table and function contracts. Function bodies are never stored or executed.

## Format and precedence

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

Properties use lower camel case. Tables require `name` and non-empty `columns`; columns require `name` and a KQL scalar `type`. Functions use `name`, optional `parameters`, and `returns`: `{"kind":"scalar","type":"string"}` or `{"kind":"tabular","columns":[...]}`. Tabular returns may set `preserveInput: true`. Required parameters precede optional parameters.

Apply order: `common` to XDR/Sentinel, then their environment sections, then the [Unified merge](schema-catalog.md#sources-and-precedence), then the `unified` section. Existing tables merge columns by name; declared types replace existing types. New tables require all columns. Function declarations replace the full contract. The `unified` section wins final conflicts.

Unknown properties, duplicate declarations/columns/parameters, invalid identifiers/types, and malformed signatures or returns cause startup failure.

## Docker

Build the image as described in [self-hosting](self-hosting.md#local-docker), then bind-mount the catalog read-only. Remove an existing container with the same name before running:

```bash
docker run --detach --name kql-validator --publish 8080:8080 \
  --mount type=bind,src="$PWD/examples/custom-schema.json",dst=/catalog/custom-schema.json,readonly \
  --env SchemaOverlay__Path=/catalog/custom-schema.json \
  kql-validator:local
```

Once `/health/ready` succeeds, verify the example catalog:

```bash
./scripts/smoke-test.sh http://127.0.0.1:8080 SharedAudit NormalizeActor
```

After editing, restart with `docker restart kql-validator`. Inspect `docker logs kql-validator` for catalog errors.

## REST and MCP discovery

Persistent entries appear in validation, discovery, environment counts, and the content-derived schema version. With the example catalog mounted:

```bash
curl --fail http://127.0.0.1:8080/api/v1/environments/xdr/tables/SharedAudit
curl --fail http://127.0.0.1:8080/api/v1/environments/xdr/functions/NormalizeActor
curl --fail-with-body http://127.0.0.1:8080/api/v1/validate \
  --header 'content-type: application/json' \
  --data '{"query":"SharedAudit | project TimeGenerated, Actor","environment":"xdr","profile":"general"}'
```

MCP uses the same catalog. Call `get_kql_table` with `{"environment":"xdr","table":"SharedAudit"}` or `get_kql_function` with `{"environment":"xdr","function":"NormalizeActor"}`.

## Persistent versus request-scoped

Mounted catalogs provide stable, server-wide declarations visible to every client. Request `extensions.tables` and `extensions.functions` cannot shadow them. Use request extensions for temporary schemas and `extensions.watchlists` for typed `_GetWatchlist` fields.

Apply the [public-schema disclosure guidance](self-hosting.md#public-schema-disclosure) to mounted catalogs.
