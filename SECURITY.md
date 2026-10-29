# Security policy

## Supported versions

One major at a time: the current one. The previous major receives fixes until the first minor of the new one.
Callers pin an exact release (`version = "X.Y.Z"`, never a range); releases are immutable, so a version always means
the same code.

## Reporting a vulnerability

Use **Report a vulnerability** in this repository's Security tab (GitHub Private Vulnerability Reporting). Do not open a public issue for vulnerabilities.

- Acknowledgement within 3 business days.
- Initial severity assessment (CVSS) within 7 days.
- Fix or documented mitigation for high/critical severity within 30 days.
- Credit to the reporter in the advisory, if desired.

## Scope

The module (`*.tf` at the root): the security posture it applies to a Cloudflare zone (TLS, HSTS, bot and AI
settings, WAF custom and rate limiting rules, managed rulesets, response headers, Turnstile, Email Routing, R2) and
how it handles the values it is given. The Cloudflare provider is covered by
[cloudflare/terraform-provider-cloudflare](https://github.com/cloudflare/terraform-provider-cloudflare/security/policy);
the Aedis Platform reusable workflows this repository calls by
[aedis-build/aedis-platform](https://github.com/aedis-build/aedis-platform/security/policy).

## Practices of this repository

- No credentials in the module: the caller's provider reads `CLOUDFLARE_API_TOKEN`; secrets the module creates (the
  Turnstile secret) only leave through a sensitive output.
- CI runs with no Cloudflare credentials: `terraform test` mocks the provider; nothing is ever applied by this
  repository.
- Every action pinned by commit SHA; `permissions: {}` by default.
- Dependencies updated by Dependabot; OpenSSF Scorecard published; releases immutable and attested by GitHub.
