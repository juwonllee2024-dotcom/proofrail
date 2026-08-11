# Proofrail

Local evidence for changed code.

Proofrail inspects a Git change set and produces a human-readable or machine-readable report for suspicious secrets, dangerous commands, workflow write permissions, dependency drift, instruction-like text, and missing tests.

It is designed for developers who use AI coding tools and want a provider-neutral review artifact without sending source code to a service.

> Current status: validation spike. The scanner is read-only. Runtime command execution, remote pull-request integration, and sandbox backends are not implemented.

## Five-Minute Quick Start

Requirements: Git and Go 1.26 or newer.

```text
go run ./cmd/proofrail inspect --repo .
```

The default Git mode inspects modified, staged, and untracked files relative to `HEAD`.

Scan every tracked and untracked file instead:

```text
go run ./cmd/proofrail inspect --repo . --all
```

Write a Markdown review artifact:

```text
go run ./cmd/proofrail inspect --repo . --format markdown --output proofrail-report.md --fail-on none
```

Emit SARIF for code-scanning-compatible systems:

```text
go run ./cmd/proofrail inspect --repo . --format sarif --output proofrail.sarif --fail-on high
```

Scan the synthetic risky fixture without executing it:

```text
go run ./cmd/proofrail inspect --repo fixtures/risky-change --fail-on none
```

The fixture intentionally produces findings. It contains no real credentials and no command is run by Proofrail.

## What It Checks

- Secret-like values, with matched values redacted
- Sensitive filenames such as `.env` and `.npmrc`
- Downloaded content piped into shell interpreters
- Destructive commands and force pushes
- GitHub Actions write permissions
- Suspicious dependency placeholder versions
- Direct dependency and `package-lock.json` drift
- Instruction-like text treated as untrusted repository data
- Source changes without a test file in the scanned set

## Safety And Privacy

- Static inspection is the default and does not execute repository content.
- Git arguments are passed as fixed argument arrays, not through a shell.
- Symlinks, binary files, oversized files, and ignored build directories are not scanned.
- Reports never include matched secret values or source excerpts.
- No network request or telemetry is required.
- The report is evidence, not a correctness or security certification.

This spike does not provide a complete sandbox. Do not interpret it as protection against arbitrary code execution in a hostile repository.

## Output Formats

- `text` for terminal review
- `markdown` for pull-request attachments and human review
- `json` for scripts and future evidence-schema consumers
- `sarif` for code-scanning-compatible ingestion

Exit status is `1` when a finding meets or exceeds `--fail-on high` by default. Use `--fail-on none` for observation-only runs.

Intentional fixture or test lines may use an explicit inline suppression such as `// proofrail:ignore secrets.candidate`. Suppressions are recorded in JSON reports and counted in the summary. Suppression is not a security bypass for other rules or other lines.

## Development

```text
go test ./...
go vet ./...
go build ./cmd/proofrail
```

The tests create temporary Git repositories and use synthetic values at runtime. No external API is required.

## Roadmap

1. Add a versioned local policy file and explicit check runner.
2. Add more package-manager and workflow detectors.
3. Add GitHub Action packaging with read-only permissions.
4. Add optional offline OSV evidence.
5. Design and test platform-specific sandbox backends before enabling execution.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/validation.md](docs/validation.md).
