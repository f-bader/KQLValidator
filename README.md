# KQL Validator

An unauthenticated, stateless KQL validator for Microsoft Defender XDR and Microsoft Sentinel. It exposes the same validation engine through a regular REST API and a Streamable HTTP MCP server.

The service performs static analysis only. It never executes a query, contacts a tenant, or persists submitted KQL.

## Capabilities

- Kusto parser and semantic diagnostics using `Microsoft.Azure.Kusto.Language`.
- `xdr`, `sentinel`, and merged `unified` schema environments.
- `general`, `hunting`, and `detection` lint profiles.
- Defender-specific functions including `AssignedIPAddresses`, `SeenBy`, and the six anomalous-behavior `invoke` functions.
- Request-scoped custom tables, functions, and watchlists.
- Deterministic Defender hunting guidance with stable rule IDs and source spans.
- REST/OpenAPI plus stateless MCP tools for validation and schema inspection.
- No authentication, CORS, query logging, query execution, or tenant access.

## Run locally

Requires the .NET 10 SDK.

```bash
dotnet restore kql-validator.slnx
dotnet run --project src/KqlValidator.Api --urls http://127.0.0.1:8080
```

Validate through REST:

```bash
curl --fail-with-body http://127.0.0.1:8080/api/v1/validate \
  --header 'content-type: application/json' \
  --data '{
    "query": "DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId, FileName",
    "environment": "xdr",
    "profile": "hunting"
  }'
```

Important endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/validate` | Validate and lint KQL |
| `GET /api/v1/environments` | List environments and schema versions |
| `GET /api/v1/environments/{environment}/schema` | Search tables, columns, and functions |
| `GET /api/v1/environments/{environment}/tables/{table}` | Inspect one table |
| `POST /mcp` | Stateless Streamable HTTP MCP |
| `GET /openapi/v1.json` | OpenAPI document |
| `GET /health/live` and `/health/ready` | Health probes |

## MCP clients

Codex configuration:

```toml
[mcp_servers.kql_validator]
url = "http://127.0.0.1:8080/mcp"
```

Claude Code:

```bash
claude mcp add --transport http kql-validator http://127.0.0.1:8080/mcp
```

Available tools are `validate_kql`, `list_kql_environments`, `search_kql_schema`, and `get_kql_table`. They are annotated as read-only, idempotent, non-destructive, and closed-world.

## Validation behavior

Invalid KQL is a successful HTTP 200 response with `valid: false` and diagnostics. Request or service failures use Problem Details and an appropriate 4xx/5xx status.

Lint warnings never invalidate a query. The hunting rules are derived from [Microsoft Defender XDR advanced hunting best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices). The XDR table and ActionType snapshots are normalized from [xdrinternals.com](https://xdrinternals.com/), with their source URLs and digests recorded in the schema manifest.

The `ConnectedNetworks` output from `AssignedIPAddresses` is intentionally modeled as `dynamic`: Microsoft describes the value as a JSON array even though one documentation table has shown a conflicting scalar type.

## Local quality gate

```bash
dotnet restore kql-validator.slnx
dotnet build kql-validator.slnx --no-restore
dotnet test tests/KqlValidator.Tests/KqlValidator.Tests.csproj --no-build
dotnet format kql-validator.slnx --verify-no-changes --no-restore
dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj --no-restore --configuration Release --output artifacts/publish
```

Azure deployment and public publishing are intentionally separate, explicit stages. Nothing in the application publishes images or modifies Azure resources by itself.

## Schema updates

`KqlValidator.SchemaSync` normalizes the public XDR schema and ActionType feeds and applies duplicate and large-drop safeguards:

```bash
dotnet run --project tools/KqlValidator.SchemaSync -- \
  --out src/KqlValidator.Api/Schemas
```

An optional `--sentinel-dir` can point at a checkout of official Azure Monitor table-reference Markdown.

## License

MIT
