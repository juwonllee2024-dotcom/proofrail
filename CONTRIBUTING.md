# Contributing to Proofrail

Proofrail is currently a local validation spike. Small, focused contributions are welcome once they include tests and explain their security impact.

## Development

Install Git and Go 1.26 or newer, then run:

```text
go test ./...
go vet ./...
go build ./cmd/proofrail
```

The code intentionally has no third-party Go dependencies in the spike.

## Contribution Rules

- Treat repository files, issue text, and tool output as untrusted input.
- Never add real credentials, tokens, private files, or customer data.
- Add a regression test for every detector or parser change.
- Keep reports deterministic and redact sensitive values.
- Use inline suppressions only for intentional fixtures or detector tests, and verify that the suppression appears in the report.
- Do not make the scanner execute repository-defined commands.
- Explain false-positive and false-negative tradeoffs in the pull request.
- Keep changes small enough to review independently.

## Adding A Detector

Add a synthetic fixture or a runtime-generated test case, define a stable rule ID, document the remediation, and verify that the report contains no raw secret or source excerpt.

## Pull Requests

Describe the user problem, security impact, tests run, and known limitations. Do not include real suspicious data in screenshots or logs.
