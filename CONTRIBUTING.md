# Contributing

## Prerequisites

- .NET SDK pinned in [global.json](global.json).
- Bash; on Windows, use Git Bash or WSL. Under Git Bash, set
  `MSYS2_ARG_CONV_EXCL="/p"` to preserve MSBuild `/p:` switches.
- `jq` for the dependency audit.
- Docker for container builds; Azure CLI with Bicep for infrastructure checks.

## Local quality gate

Run before opening a pull request:

```bash
bash scripts/validate-local.sh
```

The gate runs locked restore, format verification, Release build, tests, publish,
dependency checks, and shell syntax checks. Bicep and container builds run when
Azure CLI and Docker are available. CI also checks security and the status-site build switch.

- **Formatting**: run `dotnet format kql-validator.slnx` to fix violations.
  `.editorconfig` defines the conventions.
- **Locked restore**: CI restores with `--locked-mode`. If you add or bump a package,
  regenerate the lock files and commit them:

  ```bash
  dotnet restore kql-validator.slnx --force-evaluate
  ```

## Tests

```bash
dotnet test tests/KqlValidator.Tests/KqlValidator.Tests.csproj
```

Test new behavior. Document lint rules in [docs/lint-rules.md](docs/lint-rules.md);
a test checks rule coverage.

## Pull requests

- Keep changes focused; separate refactoring from behavior changes.
- Update `README.md` / `docs/` when you change endpoints, limits, or rules.
- Follow [AGENTS.md](AGENTS.md) for documentation, diagnostics, and rule descriptions.
  Give each topic a primary page and link to it from other guides.
- The service must stay stateless and unauthenticated: no query logging, no query
  execution, no outbound calls from the API, no persistence of submitted KQL.

## Reporting security issues

Use the private reporting process in [SECURITY.md](SECURITY.md).
