# Security Policy

## Scope

Proofrail is an early-stage static scanner. It is not a sandbox, antivirus product, or correctness certificate. Findings can be incomplete or incorrect.

## Reporting A Vulnerability

Do not open a public issue for a vulnerability that could expose users to code execution, secret disclosure, path traversal, or unsafe command execution.

Until a dedicated private advisory channel is configured, report security issues privately to the repository owner through GitHub with the subject `Proofrail security report`. Include a minimal reproduction, affected version or commit, impact, and mitigation if known.

Do not include live credentials or private source code. Redact them before sending a report.

## Security Design Commitments

- No source telemetry by default.
- No automatic execution of repository commands in the static scanner.
- No raw secret values in reports.
- Fixed argument arrays for Git subprocesses.
- Explicit documentation of unsupported isolation guarantees.
- Security regression tests for parser, path, and redaction changes.
