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

Available tools are `validate_kql`, `validate_azure_monitor_transformation`, `list_kql_lint_rules`, `list_kql_environments`, `search_kql_schema`, `get_kql_table`, and `get_kql_function`.

All REST and MCP endpoints are public when deployed with external ingress. Schema catalogs are enumerable, so do not put sensitive table, function, column, or workspace metadata in built-in snapshots or mounted custom catalogs.

## Quality gate

```bash
bash scripts/validate-local.sh
```

This runs locked restore, formatting, Release build, tests, publish, dependency checks, Bicep compilation, and a Docker build when Docker is available.
