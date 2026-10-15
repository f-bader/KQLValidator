# KQL Validator

[![ci](https://github.com/f-bader/KQLValidator/actions/workflows/ci.yml/badge.svg)](https://github.com/f-bader/KQLValidator/actions/workflows/ci.yml)

A stateless KQL validator for Microsoft Defender XDR, Microsoft Sentinel, and Azure Monitor transformations. It provides REST and Streamable HTTP MCP endpoints without authentication. Submitted KQL is never executed, stored, or logged.

## Start here

- [Self-hosting](docs/self-hosting.md): Docker and Azure Container Apps.
- [API and MCP](docs/api-and-mcp.md): validation, tools, and responses.
- [Schema catalogs](docs/schema-catalog.md): discovery, nested fields, and relations.
- [Custom catalogs](docs/custom-schema-catalog.md): persistent and request-scoped declarations.
- [Azure Monitor transformations](docs/azure-monitor-transformations.md): requests and constraints.
- [Lint rules](docs/lint-rules.md): configuration and rule reference.
- [Lab deployment](docs/lab-deployment.md): CI, Azure access, and maintenance.

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

REST validation uses `POST /api/v1/validate` for queries and `POST /api/v1/validate-transformation` for transformations. `/openapi/v1.json` describes all REST endpoints.

Connect a Streamable HTTP MCP client to `http://127.0.0.1:8080/mcp`:

```bash
codex mcp add kql-validator --url http://127.0.0.1:8080/mcp
```

Use `validate_kql` for queries and detection rules, or `validate_azure_monitor_transformation` for DCR expressions. Inspect `valid`, diagnostics, and output columns; revalidate after repairs. Static validation cannot establish runtime success or detection effectiveness. See [API and MCP](docs/api-and-mcp.md) for tool selection and examples.

## Quality gate

```bash
bash scripts/validate-local.sh
```

See [Contributing](CONTRIBUTING.md) for prerequisites and checks.
