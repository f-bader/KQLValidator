# KQL Validator

An unauthenticated, stateless KQL validator for Microsoft Defender XDR and Microsoft Sentinel. It exposes the same validation engine through a regular REST API and a Streamable HTTP MCP server.

The service performs static analysis only. It never executes a query, contacts a tenant, or persists submitted KQL.

## Capabilities

- Kusto parser and semantic diagnostics using `Microsoft.Azure.Kusto.Language`.
- `xdr`, `sentinel`, and merged `unified` schema environments.
- `general`, `hunting`, and `detection` lint profiles.
- Target-aware scheduled and NRT linting for Defender XDR and Sentinel.
- Caller-selectable rule sets, per-rule overrides, severity filtering, and public rule discovery.
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
| `GET /api/v1/lint-rules` | List and filter every lint rule and original source |
| `GET /api/v1/environments` | List environments and schema versions |
| `GET /api/v1/environments/{environment}/schema` | Search tables, columns, and functions |
| `GET /api/v1/environments/{environment}/tables/{table}` | Inspect one table |
| `POST /mcp` | Stateless Streamable HTTP MCP |
| `GET /openapi/v1.json` | OpenAPI document |
| `GET /health/live` and `/health/ready` | Health probes |

All validation, schema, lint-rule, and MCP endpoints are unauthenticated and publicly accessible when the service is deployed with external ingress. Schema and lint-rule catalogs are publicly enumerable; health probes are intentionally not rate limited.

### Public API safeguards

- Request bodies are limited to 256 KiB; the KQL query is limited to 65,536 characters.
- Each request may include at most 100 tables, functions, or watchlists, 5,000 declared output columns in aggregate, and 1,000 function parameters. Each lint selection list is limited to 100 entries.
- Diagnostics are capped at 500 results. Oversized or malformed requests return Problem Details with HTTP 400 or 413.
- Production REST and MCP traffic is partitioned by client IP with a token bucket of 10 requests and one replenished token per second. Rejected requests return HTTP 429 and `Retry-After: 1`; the analysis queue can reject additional work with HTTP 429.
- Analysis has a five-second deadline. A deadline returns HTTP 504; client cancellation returns HTTP 499 where the client connection remains writable.
- Readiness becomes unhealthy when an active analysis exceeds 10 seconds; liveness becomes unhealthy after 30 seconds. Completed analyses immediately clear both conditions.

When deployed behind a reverse proxy, forwarded client addresses are trusted only when `ReverseProxy:TrustForwardedHeaders` is enabled. The Azure Container Apps deployment enables this setting for its ingress; local deployments leave it disabled by default.

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

Available tools are `validate_kql`, `list_kql_lint_rules`, `list_kql_environments`, `search_kql_schema`, and `get_kql_table`. They are annotated as read-only, idempotent, non-destructive, and closed-world.

## Validation behavior

Invalid KQL is a successful HTTP 200 response with `valid: false` and diagnostics. Request or service failures use Problem Details and an appropriate 4xx/5xx status.

Lint warnings never invalidate a query. The hunting rules are derived from [Microsoft Defender XDR advanced hunting best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices). The XDR table and ActionType snapshots are normalized from [xdrinternals.com](https://xdrinternals.com/), with their source URLs and digests recorded in the schema manifest.

`target` is optional and inferred for ordinary hunting and scheduled detections. XDR and Unified detections use Defender targets; Sentinel detections use Sentinel targets. Set it explicitly to `defender-nrt` or `sentinel-nrt` for target-specific validation. The optional `lint` object selects rule sets, enables or disables stable rule IDs, filters severity, or disables custom lint while leaving parser and semantic diagnostics active. Community detection recommendations are disabled unless the caller explicitly selects `community-detection` or enables an individual community rule.

See [docs/lint-rules.md](docs/lint-rules.md) for configuration, applicability, examples, every rule ID, and its original source.

The `ConnectedNetworks` output from `AssignedIPAddresses` is intentionally modeled as `dynamic`: Microsoft describes the value as a JSON array even though one documentation table has shown a conflicting scalar type.

`FileProfile` is modeled as a row-preserving XDR enrichment function. `| invoke FileProfile()`, `| invoke FileProfile(SHA1)`, and `| invoke FileProfile(SHA1, 1000)` are supported; any in-scope string alias of a file hash, such as `LoadedDLLSHA1`, is also accepted. The optional second argument is the 1–1000 enrichment limit. Its output schema includes the live Defender fields such as `SignerHash`, signature metadata, `Publisher`, `SoftwareName`, and `ProfileAvailability`.

Schema responses expose a content-derived version in the form `sha256:<24 hex characters>`. The service discovery response and validation responses expose the service revision when the image was built with `SOURCE_REVISION`.

## Local quality gate

```bash
dotnet restore kql-validator.slnx
dotnet build kql-validator.slnx --no-restore
dotnet test tests/KqlValidator.Tests/KqlValidator.Tests.csproj --no-build
dotnet format kql-validator.slnx --verify-no-changes --no-restore
dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj --no-restore --configuration Release --output artifacts/publish
```

CI additionally runs a locked dependency vulnerability audit, dependency review on pull requests, CodeQL, high-severity container scanning, and weekly pinned-action analysis with zizmor. Dependabot checks GitHub Actions, NuGet, and Docker dependencies weekly.

The application instruments analysis requests with the `KqlValidator.Analysis` meter (`kql.analysis.requests`, `kql.analysis.deadline_exceeded`, `kql.analysis.queue_rejected`, and `kql.analysis.duration`). The default deployment does not configure an exporter or telemetry backend, and these instruments never include submitted query text.

Azure deployment and public publishing are intentionally separate, explicit stages. Nothing in the application publishes images or modifies Azure resources by itself.

See [docs/lab-deployment.md](docs/lab-deployment.md) for the isolated ACR build, immutable deployment, validation, budget, and cleanup runbook.

The lab deployment expects an existing Azure Container Registry, which may be in a different resource group. In West Europe a separate Basic registry has a current public retail floor of approximately US$5.07/month; reusing an existing registry avoids that incremental fixed cost. Light Container Apps usage normally remains inside the monthly Consumption free grant. `infra/budget.bicep` therefore defaults to a US$10-equivalent monthly alert threshold. Budget alerts do not stop spending.

## Schema updates

`KqlValidator.SchemaSync` normalizes the public XDR schema and ActionType feeds and applies duplicate and large-drop safeguards:

```bash
dotnet run --project tools/KqlValidator.SchemaSync -- \
  --out src/KqlValidator.Api/Schemas
```

The sync discovers every `advanced-hunting-*-table.md` document in the public Defender XDR documentation directory, derives its table name from the H1 heading, and generates `xdr-official-table-sources.json` plus the companion `xdr-official-tables.json` snapshot. These official definitions supplement XDRInternals for tables that can be absent from a tenant because of licensing. A failed directory listing, download, or Markdown parse retains the checked-in catalog and last known schema; ordinary syncs only add or update tables and never remove them. Intentional removals require the explicit `--prune-official-xdr-tables` flag.

The daily GitHub Actions `schema-sync` workflow already runs this command and opens a review PR whenever the generated schemas or source digests change.

An optional `--sentinel-dir` can point at a checkout of official Azure Monitor table-reference Markdown.

### Sentinel workspace sync

To validate against the tables visible in a specific Sentinel Log Analytics workspace, generate the checked-in snapshot before building the image. The snapshot contains only table names, column names, and KQL types. `sentinel.json` is part of the public schema catalog and is included in Docker and ACR builds.

Prerequisites:

- Azure CLI installed and signed in to the correct tenant.
- The Log Analytics **Workspace ID** (a GUID), rather than its Azure resource name.
- The signed-in identity has Log Analytics API `Data.Read` permission and Reader access to that workspace. See [Azure Monitor API access and authentication](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api).

```bash
az login
az account set --subscription YOUR_SUBSCRIPTION_ID

dotnet run --project tools/KqlValidator.SchemaSync -- \
  --out src/KqlValidator.Api/Schemas \
  --sentinel-workspace-id YOUR_WORKSPACE_ID \
  --sentinel-only

./scripts/validate-local.sh
./scripts/deploy-lab.sh
```

The sync calls the [Log Analytics Metadata API](https://learn.microsoft.com/en-us/rest/api/logsquery/metadata/post?view=rest-logsquery-v1), not a telemetry query. After `sentinel.json` is generated, builds and deployments use that offline file as the authoritative Sentinel schema and do not contact Azure Log Analytics. Re-run the sync explicitly to refresh it; deployment scripts never do so automatically. If no local snapshot exists, the validator uses its small built-in Sentinel baseline.

Custom Log Analytics tables (the Azure-required `_CL` suffix) are excluded by default. Include them only when needed:

```bash
dotnet run --project tools/KqlValidator.SchemaSync -- \
  --out src/KqlValidator.Api/Schemas \
  --sentinel-workspace-id YOUR_WORKSPACE_ID \
  --include-custom-tables
```

The deployed API exposes Sentinel schema-search endpoints publicly, and the committed snapshot is enumerable through that API. Only generate it from a workspace whose table and column names are approved for public disclosure. Custom Log Analytics tables remain excluded unless `--include-custom-tables` is explicitly supplied.

For a future CI/CD integration, run the identical sync command after an `azure/login` OIDC step. Supply the workspace ID as a protected environment variable and grant the federated identity the same workspace access; do not add a client secret. Review the resulting `sentinel.json` diff before publishing it.

`_GetWatchlist()` also recognizes the union of fields from Microsoft Sentinel's built-in watchlist templates. This checks documented column spelling without assuming a particular watchlist alias; workspace-specific columns can still be supplied with request extensions.

### Public Sentinel native functions

The committed `sentinel-native-functions.json` catalog models Microsoft-documented Sentinel functions independently of a workspace snapshot. It includes `_GetWatchlistAlias`, the ASIM helper functions, and public ASIM built-in parser names and parameters. This means those functions validate in both `sentinel` and `unified` even when the workspace metadata endpoint does not list them.

To refresh the public ASIM parser catalog, use a temporary checkout of the official Azure Sentinel repository:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel.git /tmp/azure-sentinel
git -C /tmp/azure-sentinel sparse-checkout set Parsers

dotnet run --project tools/KqlValidator.SchemaSync -- \
  --out src/KqlValidator.Api/Schemas \
  --sentinel-workspace-id YOUR_WORKSPACE_ID \
  --sentinel-only \
  --asim-dir /tmp/azure-sentinel/Parsers
```

The generator reads only parser YAML metadata (built-in parser name, ASIM schema, and declared parameters), never parser bodies. Parser result schemas expose portable ASIM fields for semantic validation; a parser that exists only in a private workspace remains opt-in through request extensions.

## License

MIT
