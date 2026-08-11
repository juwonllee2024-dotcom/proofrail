# Validation Notes

## Critical Assumption

Developers will use a local, provider-neutral report when it makes suspicious changes and verification gaps visible without requiring a paid AI or security service.

## Synthetic Experiment

The test suite creates temporary Git repositories and exercises these cases:

- Secret-like values are detected and redacted.
- Unchanged committed files are excluded from a change-set scan.
- Risky workflow permissions are reported.
- Downloaded shell commands are reported without execution.
- Prompt-injection-like repository text is treated as data.
- Suspicious dependency versions and lockfile drift are reported.
- Malformed package metadata is reported.
- Destructive command text is reported without execution.
- Traversal and absolute Git paths are rejected by the path guard.
- A directory without Git can still be scanned as a fixture.
- JSON output is deterministic.
- SARIF output has the expected schema and severity mapping.
- Inline suppressions are explicit and counted rather than silently discarded.

Run the experiment with:

```text
go test ./...
go run ./cmd/proofrail inspect --repo fixtures/risky-change --fail-on none
go run ./cmd/proofrail inspect --repo fixtures/clean-change --fail-on high
```

## Current Result

The synthetic gate passes. The risky fixture produces eight findings, including four high-severity findings. The clean fixture produces no findings. The test suite confirms that a runtime-generated secret is absent from the JSON report.

This is not external user validation. Before a public launch, the project still needs testing on real repositories and feedback from developers who use AI coding tools.

## Invalidation Criteria

Reconsider the product if users prefer their existing CI and code-review tools, if false positives dominate, or if users do not attach or act on the reports.
