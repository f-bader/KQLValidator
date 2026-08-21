# Security Policy

## Supported versions

Only the latest release of KQL Validator receives security fixes. The service is
stateless and unauthenticated by design: it performs static analysis only and never
executes a query, contacts a tenant, or persists submitted KQL.

## Reporting a vulnerability

Please **do not** open a public issue for security reports.

Use [GitHub private vulnerability reporting](https://github.com/f-bader/KQLValidator/security/advisories/new)
to report a vulnerability. Include:

- A description of the issue and its impact.
- Steps to reproduce (a request payload or query is usually enough).
- The commit, tag, or container image digest you tested against.

You can expect an acknowledgement within a few days. Please allow a reasonable
disclosure window before publishing details so a fix can ship first.

## Scope notes

- Denial-of-service resistance matters for this project: the API is designed to be
  exposed without authentication, so resource-exhaustion findings (regex blowups,
  deadline bypasses, rate-limit bypasses) are in scope and welcome.
- The bundled schema snapshots contain only Microsoft-published table metadata; they
  are not secrets.
