# Proofrail

Local evidence for changed code.

Proofrail inspects a Git change set and produces a human-readable or machine-readable report for suspicious secrets, dangerous commands, workflow write permissions, dependency drift, instruction-like text, and missing tests.

It is designed for developers who use AI coding tools and want a provider-neutral review artifact without sending source code to a service.

> Current status: validation spike. Static inspection remains the default. An explicit, trusted verification runner is available, but it is not a sandbox and remote pull-request integration is not implemented.

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

## Opt-In Verification

Add a versioned `.proofrail.yml` to describe checks:

```yaml
version: 1
checks:
  - id: unit
    program: go
    args: [test, ./...]
    timeout_seconds: 120
```

Inspect the change and record configured checks without executing them:

```text
go run ./cmd/proofrail verify --repo . --format markdown --fail-on high
```

Run checks only when the repository and configuration are trusted:

```text
go run ./cmd/proofrail verify --repo . --run --trust-config --format markdown --fail-on high
```

Both flags are required. Commands use fixed argument arrays, run from a temporary repository copy with a reduced environment, have timeouts and output caps, and have no sandbox or network restriction. A trusted check can still execute arbitrary code or access external services.

## Daily AI Project Publisher

The repository includes an optional scheduled publisher at `.github/workflows/daily-project.yml`. It checks Vancouver local time at 05:00, asks an OpenAI-compatible Responses API for a small standard-library-only Go project, runs Proofrail plus `go test`, `go vet`, and `go build`, and creates a new public repository only after those checks pass. The generated repository name comes from the model and never includes the date by requirement.

The workflow is skipped until these values are configured in GitHub repository settings:

- Secret `OPENAI_API_KEY`
- Repository variable `OPENAI_MODEL`
- Secret `REPO_PUBLISH_TOKEN` with permission to create public repositories

Never commit or paste either secret into an issue, workflow file, or chat. The publisher refuses path traversal, duplicate names, secret-like content, external Go dependencies, network/process capabilities, oversized projects, and generated `.github` files. These checks reduce risk but do not constitute human review or a sandbox; fully automatic public publishing can still publish an unsuitable project.

## What It Checks

- Secret-like values, with matched values redacted
- Sensitive filenames such as `.env` and `.npmrc`
- Downloaded content piped into shell interpreters
- Destructive commands and force pushes
- GitHub Actions write permissions
- GitHub Actions that are not pinned to full commit SHAs
- Suspicious dependency placeholder versions
- Direct dependency and `package-lock.json` drift
- Instruction-like text treated as untrusted repository data
- Source changes without a test file in the scanned set

## Safety And Privacy

- Static inspection is the default and does not execute repository content.
- Git arguments are passed as fixed argument arrays, not through a shell.
- Symlinks, binary files, oversized files, and ignored build directories are not scanned.
- Static findings never include matched secret values or source excerpts; verification output is capped and best-effort redacted.
- No network request or telemetry is required for static inspection. Trusted verification commands may use the network.
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

1. Add more package-manager and workflow detectors.
2. Add optional offline OSV evidence.
3. Design and test platform-specific sandbox backends before enabling stronger isolation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/validation.md](docs/validation.md).
