# Security policy

The verifier is the trust anchor for Verdifax audit bundles: it is
the code that decides whether evidence verifies. Security reports
about it are taken seriously and handled with priority.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through either
channel:

1. **GitHub private vulnerability reporting** (preferred): use the
   "Report a vulnerability" button under this repository's Security
   tab. This keeps the report private while it is triaged.
2. **Email**: robert@verdifax.com with the subject line
   `SECURITY: verdifax-verify`.

Please do not open a public issue for a suspected vulnerability.

## What to include

A description of the issue, the verifier version (`verdifax-verify
--version`), and, if possible, a bundle file or minimal input that
demonstrates the problem. Reports that show the verifier returning
exit code 0 for a bundle that should fail verification are the
highest-severity class and are triaged first.

## Response targets

- Initial acknowledgment: within 7 days, usually much sooner.
- Assessment and fix plan: within 14 days of acknowledgment.
- Credit: reporters are credited in the release notes of the fix
  unless they ask not to be.

## Scope

In scope: this repository (the `verdifax-verify` CLI and its
packages). Hash-collision results against SHA-256 itself are out of
scope. Issues in the hosted Verdifax API belong to
robert@verdifax.com directly rather than this repository.

## Supported versions

The latest tagged release receives security fixes. Older releases
are not patched; upgrade to the latest release to receive fixes.
