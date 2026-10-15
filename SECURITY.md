# Security Policy

## Supported versions

Only the latest release receives security fixes. The service is stateless and
unauthenticated. It never executes or logs submitted KQL, contacts a tenant, or
persists queries.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/f-bader/KQLValidator/security/advisories/new)
for vulnerabilities. Keep reports private until disclosure. Include:

- A description of the issue and its impact.
- Steps to reproduce, including a request payload or query.
- The commit, tag, or container image digest you tested against.

Expect an acknowledgement within a few days. Allow time for a fix before publishing details.

## Scope notes

- Resource exhaustion, regex blowups, deadline bypasses, and rate-limit bypasses are in scope.
- Bundled snapshots include Microsoft and community metadata. Schema endpoints also
  expose mounted catalogs; keep sensitive metadata out of public deployments.
