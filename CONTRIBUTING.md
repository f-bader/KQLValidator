# Contributing

Thanks for considering a contribution! This document covers the mechanics that the CI
gate enforces so your pull request passes on the first try.

## Prerequisites

- .NET SDK 10.0.4xx (see `global.json`).
- Bash for the scripts in `scripts/` — on Windows use Git Bash or WSL.
- Docker (only needed for the container build step of the local gate).
- Azure CLI with Bicep (only needed for the infrastructure validation step).

## Local quality gate

Run the same gate as CI before opening a pull request:

```bash
bash scripts/validate-local.sh
```

It performs: locked restore → `dotnet format` verification → build → tests → publish →
vulnerability audit → Bicep build → container build.

The two checks that most often surprise contributors:

- **Formatting**: CI runs `dotnet format kql-validator.slnx --verify-no-changes`.
  Run `dotnet format kql-validator.slnx` to fix violations; `.editorconfig` pins the
  conventions.
- **Locked restore**: CI restores with `--locked-mode`. If you add or bump a package,
  regenerate the lock files and commit them:

  ```bash
  dotnet restore kql-validator.slnx --force-evaluate
  ```

## Tests

```bash
dotnet test tests/KqlValidator.Tests/KqlValidator.Tests.csproj
```

New behavior needs a test. Lint rules must also be documented in
`docs/lint-rules.md` — a test cross-checks the rule catalog against that file.

## Pull requests

- Keep changes focused; separate refactoring from behavior changes.
- Update `README.md` / `docs/` when you change endpoints, limits, or rules.
- The service must stay stateless and unauthenticated: no query logging, no query
  execution, no outbound calls from the API, no persistence of submitted KQL.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please do not open public issues for
vulnerabilities.
