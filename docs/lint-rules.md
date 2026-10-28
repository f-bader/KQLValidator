# Lint rules

Parser and semantic validation always run. Lint controls select additional checks, individual rules, and minimum severity.

Discover rules through `GET /api/v1/lint-rules` or MCP `list_kql_lint_rules`. Diagnostics include `ruleId`, `ruleSet`, `category`, `sourceKind`, `sourceName`, and `documentationUrl`.

## Configuration

When `target` is omitted, it is inferred as follows:

| Request | Inferred target |
| --- | --- |
| `profile: hunting` | `interactive-hunting` |
| `environment: xdr` or `unified`, `profile: detection` | `defender-scheduled` |
| `environment: sentinel`, `profile: detection` | `sentinel-scheduled` |
| Other requests | No target |

NRT requires an explicit target: `defender-nrt` with `xdr`/`unified` and `detection`, or `sentinel-nrt` with `sentinel` and `detection`. Scheduled targets use the same platform/profile combinations; `interactive-hunting` requires `hunting`.

```json
{
  "query": "DeviceEvents | where ActionType == 'ProcessCreated'",
  "environment": "xdr",
  "profile": "detection",
  "target": "defender-nrt",
  "lint": {
    "enabled": true,
    "ruleSets": ["baseline", "defender-xdr", "defender-nrt"],
    "enableRules": [],
    "disableRules": ["KQLH006"],
    "minimumSeverity": "warning"
  }
}
```

- Omit `ruleSets` to use profile and target defaults. Supplying it selects exactly those rule sets.
- `enableRules` adds individual rules from any rule set.
- `disableRules` always wins.
- `minimumSeverity: warning` suppresses informational lint diagnostics. Parser and semantic diagnostics remain unchanged.
- `enabled: false` disables lint while preserving parser and semantic validation.
- Unknown rule IDs and rule-set names are rejected with HTTP 400.
- Rules still require an applicable profile, environment, and target.

The [transformation endpoint](azure-monitor-transformations.md) always applies its platform rules and accepts no lint-selection options.

## Defender continuous NRT constraints

For `target: defender-nrt` in `xdr`/`unified` detection requests, the query must reference exactly one table and omit `join`, `union`, `externaldata`, and comments. Checks use Microsoft's [continuous-NRT requirements][defender-detections], [KQL feature allowlist][nrt-kql-features], and [verified operand overrides](../src/KqlValidator.Api/Schemas/defender-nrt-overrides.json).

- `xdr` tables: `AlertEvidence`, `CloudAppEvents`, `DeviceEvents`, `DeviceFileCertificateInfo`, `DeviceFileEvents`, `DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, `DeviceInfo`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `EmailAttachmentInfo`, `EmailEvents`, `EmailPostDeliveryEvents`, `EmailUrlInfo`, `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityQueryEvents`, and `UrlClickEvents`.
- `unified` accepts the preceding XDR tables plus `ABAPAuditLog_CL`, `ABAPChangeDocsLog_CL`, `AuditLogs`, `AWSCloudTrail`, `AWSGuardDuty`, `AzureActivity`, `CommonSecurityLog`, `GCPAuditLogs`, `MicrosoftGraphActivityLogs`, `OfficeActivity`, `Okta_CL`, `OktaV2_CL`, `ProofpointPOD`, `ProofPointTAPClicksPermitted_CL`, `ProofPointTAPMessagesDelivered_CL`, `SecurityAlert`, `SecurityEvent`, and `SigninLogs`.
- Allowed tabular operations: `where`, `extend`, `project`, `project-away`, `project-rename`, `parse`, `print`, and `datatable`.
- Scalar support combines Microsoft's list with the override catalog's 207 operand forms verified on 2026-10-14. String literal lists work with `has_any`, `has_all`, `in~`, and `!in~`; `has_any` also accepts literal-valued string variables and mixed variable/literal lists. Tested `between`/`!between` forms and dynamic-array, scalar-variable, or column operands for `in`/`!in` are rejected. Additional forms need scoped evidence. UDF arguments must be scalar. `matches regex` accepts correctly escaped literals and the verified string-variable form; column operands are rejected.
- `EmailEvents.LatestDeliveryLocation` and `EmailEvents.LatestDeliveryAction` are not eligible. Time predicates on `Timestamp`, `TimeGenerated`, `ingestion_time()`, or a direct alias trigger `KQLN007` because they can skip events. `KQLN007` also applies to `sentinel-nrt` detection requests; the other constraints in this section remain Defender-specific.

## Diagnostics and repairs

See [response semantics](api-and-mcp.md#responses-and-limits) for validity and truncation. Parser and semantic errors retain their Kusto IDs and blocking severity. `KQLV002` flags a statically known FileProfile enrichment limit outside 1–1000 and remains active when lint is disabled. FileProfile column selectors are checked against invocation input columns. `KQLV003` reports [column projections](api-and-mcp.md#column-wildcard-projections) that retain zero columns and remains active when lint is disabled.

Time-filter rules `KQLH010`/`KQLH011` accept `>` or `>=`, optional whitespace before `ago`, and filters inside join branches.

For unknown tables/functions, inspect the selected environment and supply known custom contracts through `extensions.tables`/`extensions.functions`. Check unknown columns against their source table; declare typed `_GetWatchlist()` fields through `extensions.watchlists`.

For `KQLX002`, use `dynamic([{"Kind":"Account","Value":"example"}])` with one to three objects, required string `Kind`, and optional string `Value`. For `KQLD001`, retain `TimeGenerated` in the final output projection.

## Rule sets and categories

| Rule set | Default selection |
| --- | --- |
| `baseline` | All requests; its individual rules still apply only to their documented profiles/targets |
| `microsoft-kusto` | Interactive hunting |
| `defender-xdr` | XDR and unified environments |
| `sentinel-detection` | Sentinel detection |
| `defender-nrt` | Explicit `defender-nrt` target, plus `sentinel-nrt` for shared `KQLN007` time-filter validation |
| `azure-monitor-transformation` | Always for `validate-transformation`; never selected by ordinary validation profiles |
| `community-detection` | Never; caller opt-in only |
| `community-correlations` | Never; caller opt-in only |

Categories are `correctness`, `correlation`, `performance`, `reliability`, `detection`, `detection-quality`, `maintainability`, `nrt`, `sentinel`, `transformation`, and `xdr`. `sourceKind` is `microsoft` or `community`.

## Complete rule catalog

“Default” indicates eligibility under profile defaults. Explicit rule-set selection also includes rows marked “No”; applicability still applies. [Correlation rules](#column-correlations) follow the main catalog.

| ID | Severity | Rule set / category | Default | Trigger and preferred pattern | Original source |
| --- | --- | --- | ---: | --- | --- |
| `KQLH001` | Warning | baseline / performance | Yes | `search "x"` → scope with `search in (Table)` or start from a table. | [Defender hunting best practices][defender-bp] |
| `KQLH002` | Warning | baseline / performance | Yes | `* contains "x"` → search a named column. | [Defender hunting best practices][defender-bp] |
| `KQLH003` | Warning | baseline / performance | Yes | `union *` or an unbounded source union → enumerate required tables. | [Defender hunting best practices][defender-bp] |
| `KQLH004` | Warning | baseline / performance | Yes | `tolower(Column) == "x"` → use a suitable case-aware string operator when semantics permit. | [Defender hunting best practices][defender-bp] |
| `KQLH005` | Information | baseline / performance | Yes | `extract()` or `matches regex` on structured input → prefer `parse` or `parse_json`; regex remains valid when required. | [Defender hunting best practices][defender-bp] |
| `KQLH006` | Information | baseline / performance | Yes | A string term shorter than three characters is not term-indexed; narrow the data first. | [Kusto term-index semantics](https://learn.microsoft.com/en-us/kusto/query/has-any-operator) |
| `KQLH007` | Warning | baseline / performance | Yes | `extend X=... \| where X...` → filter the source column before calculating `X` when equivalent. | [Defender hunting best practices][defender-bp] |
| `KQLH008` | Warning | baseline / detection-quality | Yes | Hunting with exact command-line equality → parse or independently match stable components. | [Defender hunting best practices][defender-bp] |
| `KQLH009` | Information | baseline / correctness | Yes | `join (...)` → specify `kind`; the default `innerunique` deduplicates the left input. | [Defender hunting best practices][defender-bp] |
| `KQLH010` | Warning | baseline / performance | Yes | Interactive XDR hunting without an early `Timestamp` or `TimeGenerated` predicate → bound the scan. | [Defender hunting best practices][defender-bp] |
| `KQLH011` | Warning | baseline / performance | Yes | Interactive hunting join branch without its own time predicate → time-bound both inputs. | [Defender hunting best practices][defender-bp] |
| `KQLH012` | Warning | baseline / performance | Yes | Parsing or row transformation before a selective filter → filter first. | [Defender hunting best practices][defender-bp] |
| `KQLH013` | Information | baseline / performance | Yes | Interactive hunting without `take`, `limit`, `top`, `count`, or aggregation → bound development results. | [Defender hunting best practices][defender-bp] |
| `KQLH014` | Warning | baseline / correctness | Yes | `ProcessId` without a unique ID or creation time → include `ProcessUniqueId` or `ProcessCreationTime`. | [Defender hunting best practices][defender-bp] |
| `KQLH015` | Information | community-detection / performance | No | Known event-stream join uses only categorical keys (`ActionType`, `EventID`, etc.) → review multiplicative row growth and intended entity keys. Semi/anti, snapshot/dimension, and aggregated inputs are excluded. | [Inner join](https://learn.microsoft.com/en-us/kusto/query/join-inner) |
| `KQLD001` | Error | sentinel-detection / detection | Yes | Sentinel scheduled/NRT output omits `TimeGenerated` → retain it in the final projection; filtering on it alone is insufficient. | [Sentinel scheduled rules][sentinel-rules] |
| `KQLD002` | Warning | defender-xdr / detection | Yes | Defender detection output contains neither `Timestamp` nor `TimeGenerated` → prefer one in the final projection; otherwise alert event time is derived from the lookback period. | [Defender custom detections][defender-detections] |
| `KQLD003` | Warning | defender-xdr / detection | Yes | Defender event output drops `ReportId`, or endpoint output drops `DeviceId` → retain these identifiers to preserve event identity and device scope. | [Defender custom detections][defender-detections] |
| `KQLD004` | Warning | defender-xdr / detection-quality | Yes | Defender output lacks a supported automatic impacted-asset field → retain a device, mailbox, or account identifier. | [Defender custom detections][defender-detections] |
| `KQLD005` | Warning | defender-xdr / detection-quality | Yes | Detection uses exact command-line equality → tolerate quoting, spacing, and argument-order changes. | [Defender hunting best practices][defender-bp] |
| `KQLD006` | Warning | baseline / reliability | Yes | Alert query uses `take` or `limit` → use deterministic filters or aggregation. | [Azure Monitor log alerts][alert-queries] |
| `KQLD007` | Information | community-detection / detection-quality | No | Known endpoint filename/path equality with demonstrable Windows path context → review whether case variations should match. Case sensitivity can be intentional; arbitrary AD attributes and unproven platform context are excluded. | [Windows case sensitivity](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity) |
| `KQLD008` | Information | community-detection / maintainability | No | More than ten distinct static IOC-shaped values or literals on a known indicator column → consider managed indicator data. Ten is a project heuristic; recommendations respect the environment and target, including Defender NRT restrictions. | [Sentinel threat intelligence](https://learn.microsoft.com/en-us/azure/sentinel/understand-threat-intelligence) |
| `KQLD009` | Warning | defender-xdr / detection | Yes | Final event time and `ReportId` originate from independent aggregates, such as `max(Timestamp)` and `take_any(ReportId)` → use a joint `arg_max` or `take_any` when one event must supply both. Unknown lineage is skipped. | [Defender custom detections][defender-detections] |
| `KQLX001` | Warning | defender-xdr / xdr | Yes | Literal `ActionType` is absent from the bundled current catalog → verify schema spelling and availability. | [XDRInternals schema][xdrinternals] |
| `KQLX002` | Error | defender-xdr / xdr | Yes | Invalid `GetAnomalousBehaviorsAbout` literal → use `dynamic([{"Kind":"Account","Value":"example"}])`; supply one to three objects with string `Kind` and optional string `Value`. | [GetAnomalousBehaviorsAbout][about-function] |
| `KQLX003` | Information | defender-xdr / xdr | Yes | Native XDR detection returns only `TimeGenerated` → prefer native `Timestamp` for event time. Unified validation treats both as event-time columns. | [Defender custom detections][defender-detections] |
| `KQLP001` | Information | microsoft-kusto / performance | Yes | `contains "FullTerm"` → consider `has "FullTerm"` only when full-term semantics are intended. | [Kusto query best practices][kusto-bp] |
| `KQLP002` | Information | microsoft-kusto / performance | Yes | `Column =~ "a" or Column =~ "b"` → `Column in~ ("a", "b")`. | [Kusto `in` operator][in-operator] |
| `KQLP003` | Information | microsoft-kusto / performance | Yes | `evaluate bag_unpack(Bag)` → declare `: (Column:type, ...)` OutputSchema when known. | [bag_unpack plugin][bag-unpack] |
| `KQLP004` | Warning | microsoft-kusto / performance | Yes | `where format_datetime(Time, ...) == ...` → compare the datetime value or range directly. | [Kusto query best practices][kusto-bp] |
| `KQLP005` | Information | microsoft-kusto / maintainability | Yes | Known string equality/inequality with `""` → consider `isempty(Column)` or `isnotempty(Column)` for clarity. Equality is valid; whitespace-only strings are excluded. | [isempty function][isempty] |
| `KQLP006` | Information | microsoft-kusto / performance | Yes | `Column has "192.0.2.1"` → use `has_ipv4` or `has_any_ipv4` where supported. Suppressed for Defender NRT, which rejects these forms. | [Kusto query best practices][kusto-bp] |
| `KQLP007` | Warning | baseline / performance | Yes | One `parse` statement extracts more than five columns → split it into smaller parse statements. Transformations allow at most ten. | [Azure Monitor query optimization][azure-monitor-query-optimization] |
| `KQLP008` | Information | microsoft-kusto / performance | Yes | `count_distinct` or `count_distinctif` → consider `dcount`/`dcountif` only when approximate counts meet detection requirements. | [Count distinct](https://learn.microsoft.com/en-us/kusto/query/count-distinct-aggregation-function) |
| `KQLP009` | Information | microsoft-kusto / performance | No | `make_list`, `make_set`, or `_if` variants without `maxSize` → consider an explicit bound only when dropping excess values is acceptable. The default cap is 1,048,576 elements. | [Array aggregation](https://learn.microsoft.com/en-us/kusto/query/make-set-aggregation-function) |
| `KQLP010` | Information | microsoft-kusto / performance | Yes | Nonempty plain-literal `matches regex` → consider `contains_cs` for case-sensitive substring matching. Regex features and escapes are excluded. | [Kusto best practices](https://learn.microsoft.com/en-us/kusto/query/best-practices) |
| `KQLP011` | Warning | baseline / correctness | Yes | Known non-string equality with typed null → `isnull`; `isnull` on a known string → `isempty` if empty/missing is intended. Inequality with typed null can act as a non-null filter in a `where` clause. | [Null values](https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/null-values) |
| `KQLP012` | Information | baseline / correctness | Yes | A second `parse_json` on a dynamic field derived from JSON parsing passes the argument through → use `tostring` first only if the field contains encoded JSON text; access an existing object directly. A statically proven encoded JSON string upgrades this diagnostic to Warning. | [parse_json](https://learn.microsoft.com/en-us/kusto/query/parse-json-function) |
| `KQLP013` | Information | microsoft-kusto / performance | Yes | Static `has_any` input has more than 128 terms → text-index optimization is disabled. This check counts statically known inputs. | [has_any](https://learn.microsoft.com/en-us/kusto/query/has-any-operator) |
| `KQLP014` | Warning | baseline / correctness | Yes | Static `has_any` input exceeds 10,000 distinct values → only up to 10,000 are considered. Deduplicate for this limit; this diagnostic supersedes `KQLP013`. | [has_any](https://learn.microsoft.com/en-us/kusto/query/has-any-operator) |
| `KQLP015` | Warning | baseline / correctness | Yes | `in~`/`!in~` has known non-ASCII letters → case-insensitive membership supports ASCII only. Normalize explicitly when Unicode matching is intended; conflicting `KQLH004` advice is suppressed for Unicode membership normalization. | [Membership operator](https://learn.microsoft.com/en-us/kusto/query/in-operator) |
| `KQLP016` | Information | baseline / correctness | Yes | Tabular RHS of `in` variants or `has_any` has multiple known columns → only the first participates; explicitly project the intended field. | [Membership operator](https://learn.microsoft.com/en-us/kusto/query/in-operator) |
| `KQLP017` | Warning | baseline / reliability | Yes | Reused `let`/`as` expression contains randomness, sampling, or unsorted `take`/`limit` → consider `toscalar` or `materialize`/`hint.materialized=true` when shared evaluation is intended. Already materialized and ordinary deterministic reuse are excluded. | [Named expressions](https://learn.microsoft.com/en-us/kusto/query/named-expressions) |
| `KQLP018` | Information | microsoft-kusto / performance | Yes | Single-string-key `leftsemi` without extra predicates or strategy hints → consider `in` with an explicit RHS projection when semantics and service limits permit. | [Kusto best practices](https://learn.microsoft.com/en-us/kusto/query/best-practices) |
| `KQLS001` | Error | sentinel-detection / sentinel | Yes | Sentinel detection query exceeds 10,000 characters; the diagnostic reports the measured length → shorten it or move large literal lists and pattern data into a watchlist or other managed external source. | [Sentinel scheduled rules][sentinel-rules] |
| `KQLS002` | Warning | baseline / sentinel | Yes | `_GetWatchlist('assets') \| project Tags` or `['IP Address']` → define the optional field first, for example `\| extend Tags = column_ifexists('Tags', '')`, to avoid deployment failures when the watchlist lacks that column. | [Fabian Bader][fabian-bader] |
| `KQLN001` | Error | defender-nrt / nrt | Yes | Defender NRT query references anything other than exactly one table, or uses `join`, `union`, or `externaldata` → rewrite as a single-input query or use a scheduled detection. | [Defender custom detections][defender-detections] |
| `KQLN002` | Error | defender-nrt / nrt | Yes | Defender NRT query contains a line or block comment → remove it from deployed NRT KQL or use a scheduled target if comments must remain. | [Defender custom detections][defender-detections] |
| `KQLN003` | Error | defender-nrt / nrt | Yes | Defender NRT query uses a table outside Microsoft’s NRT allowlist for `xdr` or `unified` → select a supported source table. | [Defender custom detections][defender-detections] |
| `KQLN004` | Error | defender-nrt / nrt | Yes | Defender NRT query uses a feature outside the support catalog or a non-scalar-argument UDF → use a cataloged form, verify query compatibility, or use a scheduled detection. | [Defender NRT compatibility catalog](../src/KqlValidator.Api/Schemas/defender-nrt-overrides.json) |
| `KQLN005` | Error | defender-nrt / nrt | Yes | Invalid or unsupported `matches regex` operand → use a correctly escaped KQL string literal or the verified string-variable form. | [Defender custom detections][defender-detections] |
| `KQLN006` | Error | defender-nrt / nrt | Yes | `EmailEvents` uses `LatestDeliveryLocation` or `LatestDeliveryAction` → remove the unsupported column. | [Defender custom detections][defender-detections] |
| `KQLN007` | Warning | defender-nrt / nrt | Yes | Defender or Sentinel NRT query filters `Timestamp`, `TimeGenerated`, `ingestion_time()`, or a direct alias → remove the time filter or use a scheduled detection. | [Defender custom detections][defender-detections] |
| `KQLT001` | Error | azure-monitor-transformation / transformation | Yes | Transformation uses an invalid source, returns a non-tabular value, or can expand one input into multiple rows. | [Supported transformation KQL][nrt-kql-features] |
| `KQLT002` | Error | azure-monitor-transformation / transformation | Yes | Transformation uses an unsupported tabular operator. | [Supported transformation KQL][nrt-kql-features] |
| `KQLT003` | Error | azure-monitor-transformation / transformation | Yes | Transformation uses an unsupported scalar/string feature or a UDF with a tabular argument. | [Supported transformation KQL][nrt-kql-features] |
| `KQLT004` | Error | azure-monitor-transformation / transformation | Yes | One transformation `parse` statement extracts more than ten columns. | [Supported transformation KQL][nrt-kql-features] |
| `KQLT005` | Warning | azure-monitor-transformation / transformation | Yes | `parse kind=regex` requires a full-input match in transformations. | [Supported transformation KQL][nrt-kql-features] |
| `KQLT006` | Error | azure-monitor-transformation / transformation | Yes | Transformation output omits `TimeGenerated:datetime`. | [Create a transformation][azure-monitor-transformations-create] |
| `KQLT007` | Error | azure-monitor-transformation / transformation | Yes | Output column type differs from the supplied destination schema. | [Create a transformation][azure-monitor-transformations-create] |
| `KQLT008` | Warning | azure-monitor-transformation / transformation | Yes | Output column is absent from the supplied destination and Azure will discard it after ingestion. | [Create a transformation][azure-monitor-transformations-create] |
| `KQLQ001` | Information | community-detection / detection-quality | No | Detection filters identity-like display names → prefer stable IDs where available. | [Detection Engineering Best Practices, part 1][dxbp1] |
| `KQLQ002` | Information | community-detection / detection-quality | No | `DeviceProcessEvents` filename detection omits original-file-name metadata → consider the original filename to tolerate renamed binaries. | [Detection Engineering Best Practices, part 1][dxbp1] |
| `KQLQ003` | Information | community-detection / maintainability | No | Inline negative filter has no same-line explanation → document rationale and ownership or centralize the allowlist. | [Detection Engineering Best Practices, part 2][dxbp2] |
| `KQLQ004` | Warning | community-detection / detection-quality | No | Sentinel NRT query joins or unions events → consider a single-event NRT rule because different ingestion windows can cause missed correlation. | [FalconForce NRT research][falcon-nrt] |
| `KQLQ005` | Information | community-detection / detection-quality | No | Known event-stream join exposes both timestamps and lacks a recognized cross-input time proximity constraint → review whether temporal correlation is required. Snapshot/dimension and aggregated inputs, semi/anti joins, proven event-identity joins, and ambiguous self-join timestamp lineage are excluded. Choose a window appropriate for the detected behavior. | [Defender hunting best practices][defender-bp] |

## Advisory checks

Semantic advisory checks use resolved types, literals, aliases, static `let` lists, and conservative column lineage. They ignore query-like comments/strings and skip unknown lineage. Review changes to exactness, array completeness, case semantics, or correlation intent before applying advice. Submitted KQL is never rewritten.

`KQLP009` requires explicit `microsoft-kusto` selection or individual enablement. `KQLH015`, `KQLD007`, `KQLD008`, and `KQLQ005` are community heuristics supported by Microsoft references; enable them through community opt-in or individually. `KQLH015` also applies to hunting.

## Scope

Query text cannot establish live cardinality, ingestion delay, alert volume, SOC classification quality, or detection coverage. Join ordering, broadcast/shuffle strategy, tuning thresholds, retirement, and maintenance intervals require workload evidence. Path canonicalization, configured Sentinel entity mapping, and watchlist `SearchKey` optimization require additional semantic or configuration context and remain unchecked. Native dynamic array indexing is supported.

## Column correlations

The opt-in `community-correlations` set uses bundled [XDRInternals relations](schema-catalog.md#column-relations). All three rules emit warnings for general, hunting, and detection queries; syntax and schema validity remain unchanged.

| Rule | Trigger and guidance |
| --- | --- |
| `KQLR001` | Resolved join keys belong to different known identifier families, such as token versus session, Defender versus Entra device, or SHA-1 versus SHA-256. Choose identifiers with compatible meanings. |
| `KQLR002` | A join key derived from a token, AWS resource, or GCP resource identifier uses `tolower` or `toupper`. Preserve case and compare exactly. Azure ARM resource and file-hash case normalization is not flagged. |
| `KQLR003` | A known process-start-key relationship omits a matching DeviceId key and both inputs are not demonstrably restricted to the same non-empty device ID. Match DeviceId alongside the process key; retain tenant context and account for process creation time. |

```json
{
  "query": "DeviceProcessEvents | join kind=inner DeviceNetworkEvents on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId",
  "environment": "xdr",
  "profile": "general",
  "lint": { "ruleSets": ["baseline", "defender-xdr", "community-correlations"] }
}
```

Checks follow resolved columns through aliases, projections, `let` inputs, static dot/bracket paths, string conversion/JSON parsing, case transforms, and Base64-padding removal with `trim_end(@"=+", key)`. Exact-equality join keys include shorthand and conjunctions. Unknown functions, ambiguous union lineage, dynamic paths, and unresolved columns are skipped. Missing catalog relationships leave joins valid. Nested JSON property names are case-sensitive.

Relation guidance covers timing windows, empty keys, inventory snapshots, event applicability, AAD Graph token padding, and identity/workspace tenant distinctions. Adapt upstream examples to actual data and account for retention and collection gaps. Correlation alone cannot establish causation.

## References

[defender-bp]: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices
[defender-detections]: https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules
[nrt-kql-features]: https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql#supported-kql-features
[sentinel-rules]: https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview
[alert-queries]: https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-log-query
[kusto-bp]: https://learn.microsoft.com/en-us/kusto/query/best-practices
[in-operator]: https://learn.microsoft.com/en-us/kusto/query/in-cs-operator
[bag-unpack]: https://learn.microsoft.com/en-us/kusto/query/bag-unpack-plugin
[isempty]: https://learn.microsoft.com/en-us/kusto/query/isempty-function
[azure-monitor-query-optimization]: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/query-optimization#break-up-large-parse-commands
[azure-monitor-transformations-create]: https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-create
[xdrinternals]: https://xdrinternals.com/
[about-function]: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-getanomalousbehaviorsabout-function
[dxbp1]: https://kqlquery.com/posts/dxbp-part1/
[dxbp2]: https://kqlquery.com/posts/dxbp-part2/
[falcon-nrt]: https://falconforce.nl/falconfriday-need-for-speed-going-underground-with-near-real-time-nrt-rules-0xff26/
[fabian-bader]: https://github.com/f-bader/KQLValidator/blob/main/docs/lint-rules.md

## Column observations

The `community-observations` rule set is opt-in. `KQLO001` reports informational guidance for case-sensitive comparisons on eight cataloged filename/path fields in `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceImageLoadEvents`, with demonstrated Windows path context. The source dataset is attributed to [Olaf Hartong](https://github.com/olafhartong).

The rule checks `==`, `!=`, `<>`, `in`, and `!in` against nonempty string constants inside filters. It follows unambiguous column aliases, requires explicit `windows-path-case-review` eligibility, and preserves intentional case-sensitive matching. Membership checks initially support literal string lists. Queries containing joins, transformed values, nested paths, unresolved origins, token identifiers, URLs, and serialized payload comparisons are skipped. Imported observations without reviewed eligibility remain available as metadata.

When both `KQLO001` and `KQLD007` apply to the same comparison, the observation advisory takes precedence. `KQLD007` retains its existing behavior when enabled independently. No query is rewritten and no casing observation creates a validation error.
