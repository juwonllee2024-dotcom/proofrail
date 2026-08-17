# Security Policy

## Scope

Proofrail is an early-stage static scanner. It is not a sandbox, antivirus product, or correctness certificate. Findings can be incomplete or incorrect.

## Reporting A Vulnerability

Do not open a public issue for a vulnerability that could expose users to code execution, secret disclosure, path traversal, or unsafe command execution.

Until a dedicated private advisory channel is configured, report security issues privately to the repository owner through GitHub with the subject `Proofrail security report`. Include a minimal reproduction, affected version or commit, impact, and mitigation if known.

Do not include live credentials or private source code. Redact them before sending a report.

## Security Design Commitments

- No source telemetry by default.
- No automatic execution of repository commands in the static scanner; verification requires both `--run` and `--trust-config`.
- No raw matched secret values in static findings; trusted command output uses capped, best-effort redaction.
- Fixed argument arrays for Git subprocesses.
- Trusted verification runs from a temporary copy with a reduced environment, bounded output, and a timeout, but is not a sandbox.
- The daily publisher keeps API and repository-creation credentials in GitHub Secrets and does not expose them to generated project tests.
- Automatically generated public repositories are not human-reviewed; CI results do not certify generated code as safe.
- Explicit documentation of unsupported isolation guarantees.
- Security regression tests for parser, path, and redaction changes.
