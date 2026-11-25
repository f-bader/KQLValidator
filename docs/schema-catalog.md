# Schema catalogs

Validation and discovery use the effective catalog: bundled schemas plus [mounted custom declarations](custom-schema-catalog.md). Catalogs are loaded locally and provide no live workspace data.

## Sources and precedence

The bundled XDRInternals snapshot takes precedence over Microsoft documentation for XDR tables; Microsoft documentation supplies missing tables. Unified combines XDR and Sentinel, using the complete effective XDR definition for shared tables and adding Sentinel's `TimeGenerated` column when absent. See [custom catalog precedence](custom-schema-catalog.md#format-and-precedence) for overlays.

## Find tables and functions

| MCP tool | REST endpoint |
| --- | --- |
| `list_kql_environments` | `GET /api/v1/environments` |
| `search_kql_schema` | `GET /api/v1/environments/{environment}/schema` |
| `get_kql_table` | `GET /api/v1/environments/{environment}/tables/{table}` |
| `get_kql_function` | `GET /api/v1/environments/{environment}/functions/{function}` |

Search accepts `query`, `kind` (`table`, `column`, or `function`), `limit`, and `cursor`. For example, call `search_kql_schema` with `{"environment":"xdr","query":"Device","kind":"table","limit":10}`, then pass a returned name to `get_kql_table`.

Search matches case-insensitive substrings. Lookups match exact names case-insensitively; missing tables/functions return HTTP 404 in REST or null (empty content) in MCP. Function lookup covers catalog functions; built-in KQL scalar functions have separate language support.

Search defaults to 50 results and clamps `limit` to 1–100. Pass `nextCursor` with unchanged environment, filters, and limit until it is null.

## Structured columns

[XDRInternals structured-column guidance](https://xdrinternals.com/data/structured-columns/index.json) describes captured and illustrative nested shapes. Fields may be absent or have other types; additional fields and variants can occur. These observations add no validation errors or required nested fields.

| MCP tool | REST endpoint |
| --- | --- |
| `list_kql_structured_columns` | `GET /api/v1/environments/{environment}/structured-columns` |
| `get_kql_structured_column` | `GET /api/v1/environments/{environment}/tables/{table}/columns/{column}/structures` |

Discovery accepts optional exact `table` and `column` filters, matched case-insensitively. Detail accepts `discriminators`, such as `{"OperationName":"Add service principal"}`: a key/value object in MCP or URL-encoded JSON in REST. All entries must match. Keys and values are case-sensitive, whitespace is significant, and absent keys fail the filter.

Discovery defaults to 50 columns per page; detail defaults to 10 discriminator combinations. Both clamp `limit` to 1–100 and accept `cursor`. Reuse all filters/options with `nextCursor`. Ordering is deterministic within a snapshot. `totalCount` and detail `status` cover the full filtered result, including combinations without shapes. Examples default off (`includeExamples=false`).

Responses include provenance, a digest, coverage flags, and shape origins, including mixed observed and illustrative shapes. Detail status is one of `target-unavailable`, `no-catalog-match`, `known-combination-without-shape`, `illustrative-only`, or `observed-shapes-available`.

### Parsing nested values

Paths describe structure. Translate array expansion and named-property selectors into KQL, checking the encoding and effective column type first. JSON strings, native dynamic values, and XML strings require different handling. `::<json>` marks another JSON decoding boundary: use `parse_json(tostring(value))` on the extracted string. `parse_json` alone passes dynamic values through, including encoded JSON strings. Cast extracted values and handle missing fields.

For an `AuditLogs` query, fetch the table and inspect `AdditionalDetails` filtered by `OperationName` before extracting an `AppId` entry. Account for events without that entry when assessing coverage.

## Column relations

Use `get_kql_column_relations` or `GET /api/v1/environments/{environment}/tables/{table}/relations`, optionally filtered by `column`. Both relation endpoints must exist in the effective schema. Responses include catalog version, SHA-256 digest, identifier families, nested paths, timing guidance, notes, and available examples.

The bundled [XDRInternals relations](https://xdrinternals.com/data/column-relations.json) provide community guidance with incomplete coverage. Adapt examples to the environment and data; live matches depend on collection and retention. Related checks are available through the opt-in [community-correlations lint set](lint-rules.md#column-correlations).

## Snapshot maintenance

SchemaSync refreshes relation and structured-column snapshots and records their digests in the manifest. Structured columns refresh even with `--sentinel-only`. The refresh rejects malformed references and large drops in entries, combinations, or known actions before replacing the structured snapshot.

## Column observations

`get_kql_table` includes optional column `observations` with explanations, resolved source credits, and reviewed guidance. Use `get_kql_column_observations` or `GET /api/v1/environments/{environment}/column-observations` to inspect the catalog, optionally filtering by `table`, `column`, and `path`. Table and column filters match exact names case-insensitively; nested paths are case-sensitive. Omit `path` to include all paths, or pass an empty path for the whole column. Results include the source URL and snapshot digest and are filtered against the effective environment schema. Missing observations indicate incomplete coverage.

The standalone [XDRInternals column observation catalog](https://xdrinternals.com/data/column-observations.json) is authoritative for validator enrichment. Embedded upstream full-schema observations are generated exports. The catalog credits [Olaf Hartong](https://github.com/olafhartong) for the supplied `CaseInconsistentFields.json` dataset, retaining all 252 table/column pairs, including references outside the bundled schemas. Value casing observations do not establish safe case folding. AAD Graph token format guidance preserves identifier case and distinguishes padding removal from GUID-shaped values.

SchemaSync refreshes observations during full and `--sentinel-only` runs. Before a source change is published, review a local catalog with:

```sh
dotnet run --project tools/KqlValidator.SchemaSync -- --out src/KqlValidator.Api/Schemas --observations-only --observations-file /absolute/path/column-observations.json
```

The local input is validated and recorded under the canonical public source URL with its digest. This command updates only the observation snapshot and its manifest entry. Ordinary refreshes require the source catalog to be published first.
