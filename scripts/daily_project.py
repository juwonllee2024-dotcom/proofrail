#!/usr/bin/env python3
"""Generate one bounded Go project for the scheduled publisher."""

import json
import os
import posixpath
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_FILES = 40
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,49}$")
SECRET_PATTERN = re.compile(
    r"(?i)(?:ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:api[_-]?key|secret[_-]?key|password)\b\s*[:=])"
)
FORBIDDEN_PATTERN = re.compile(
    r"(?m)(?:\b(?:os/exec|net/http|net\.|syscall|unsafe|plugin)\b|"
    r"\bgo:generate\b|\b(?:curl|wget)\s|\brm\s+-rf\b|"
    r"\b(?:powershell|cmd)\s|\bos\.RemoveAll\b)"
)

SYSTEM_PROMPT = """
You generate one small, original Go project for a daily public repository.
Return only the JSON object required by the response schema.

Rules:
- The project name must be a memorable lowercase kebab-case slug, not a date.
- Make the idea materially different from ordinary hello-world examples.
- Use only the Go standard library. Do not add dependencies, network clients,
  subprocess execution, shell commands, unsafe code, generated code, or
  filesystem deletion.
- Include go.mod, README.md, at least one normal .go file, and at least one
  *_test.go file. Tests must be deterministic and fast.
- Do not include .github files; the publisher adds the trusted CI workflow.
- Do not include secrets, credentials, private keys, telemetry, or tokens.
- Keep the complete project small enough to review in one sitting.
""".strip()

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "files": {
            "type": "array",
            "minItems": 4,
            "maxItems": MAX_FILES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    "required": ["name", "description", "files"],
}

PUBLISHER_WORKFLOW = """name: CI

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Check out source
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Set up Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: '1.26.x'
          cache: true
      - name: Test
        run: go test ./...
      - name: Vet
        run: go vet ./...
      - name: Build
        run: go build ./...
"""

PUBLISHER_GITIGNORE = """proofrail-report.json
coverage.out
"""


def stop(message):
    raise SystemExit(message)


def response_text(payload):
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct
    chunks = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
    if not chunks:
        stop("OpenAI response did not contain output text")
    return "".join(chunks)


def request_project():
    api_key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("OPENAI_MODEL", "")
    if not api_key:
        stop("OPENAI_API_KEY is not configured")
    if not model:
        stop("OPENAI_MODEL repository variable is not configured")

    seed = os.environ.get("DAILY_PROJECT_SEED", "scheduled-run")
    prompt = (
        "Create one project now. Use this private uniqueness seed only to vary "
        "the idea; never put the seed or a date in the project name.\n"
        f"Seed: {seed}\n"
    )
    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": SYSTEM_PROMPT}]},
            {"role": "user", "content": [{"type": "input_text", "text": prompt}]},
        ],
        "max_output_tokens": 16000,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "daily_project",
                "strict": True,
                "schema": SCHEMA,
            }
        },
    }
    request = Request(
        os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1/responses"),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=120) as response:
            body = response.read(2 * 1024 * 1024)
    except HTTPError as error:
        stop(f"OpenAI API request failed with HTTP {error.code}")
    except URLError as error:
        stop(f"OpenAI API request failed: {error.reason}" if error.reason else "OpenAI API request failed")

    try:
        output = response_text(json.loads(body.decode("utf-8")))
        project = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        stop(f"OpenAI response was not valid JSON: {error}")
    return validate_project(project)


def validate_project(project):
    if not isinstance(project, dict):
        stop("generated project must be an object")
    name = project.get("name")
    description = project.get("description")
    files = project.get("files")
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        stop("generated project has an invalid repository name")
    if not isinstance(description, str) or not description.strip() or len(description) > 160 or "\n" in description:
        stop("generated project has an invalid description")
    if not isinstance(files, list) or not 4 <= len(files) <= MAX_FILES:
        stop("generated project has an invalid file count")

    normalized_files = {}
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            stop("generated project contains an invalid file entry")
        raw_path = item["path"].replace("\\", "/")
        clean_path = posixpath.normpath(raw_path)
        if (
            raw_path != clean_path
            or clean_path.startswith("/")
            or clean_path == "."
            or clean_path == ".."
            or clean_path.startswith("../")
            or clean_path == ".git"
            or clean_path.startswith(".git/")
            or clean_path == ".github"
            or clean_path.startswith(".github/")
            or clean_path == ".gitignore"
        ):
            stop(f"generated project contains an unsafe path: {item['path']!r}")
        if clean_path in normalized_files:
            stop(f"generated project contains a duplicate path: {clean_path}")
        content = item["content"]
        size = len(content.encode("utf-8"))
        if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
            stop("generated project exceeds the file size limit")
        if SECRET_PATTERN.search(content):
            stop(f"generated project contains a secret-like value in {clean_path}")
        if FORBIDDEN_PATTERN.search(content):
            stop(f"generated project contains a forbidden capability in {clean_path}")
        normalized_files[clean_path] = content
        total_bytes += size

    if "README.md" not in normalized_files or "go.mod" not in normalized_files:
        stop("generated project must include README.md and go.mod")
    if not any(path.endswith(".go") and not path.endswith("_test.go") for path in normalized_files):
        stop("generated project must include a Go source file")
    if not any(path.endswith("_test.go") for path in normalized_files):
        stop("generated project must include a Go test file")
    go_mod = normalized_files["go.mod"]
    if not re.search(r"(?m)^\s*module\s+\S+\s*$", go_mod):
        stop("generated go.mod is missing a module declaration")
    if re.search(r"(?m)^\s*(?:require|replace)\b", go_mod):
        stop("generated project must not add external Go dependencies")

    normalized_files[".github/workflows/ci.yml"] = PUBLISHER_WORKFLOW
    normalized_files[".gitignore"] = PUBLISHER_GITIGNORE
    return {"name": name, "description": description.strip(), "files": normalized_files}


def write_project(project):
    destination_value = os.environ.get("DAILY_PROJECT_DIR", "")
    metadata_value = os.environ.get("DAILY_PROJECT_METADATA", "")
    if not destination_value or not metadata_value:
        stop("DAILY_PROJECT_DIR and DAILY_PROJECT_METADATA are required")
    destination = Path(destination_value)
    metadata_path = Path(metadata_value)
    if destination.exists():
        stop("daily project directory already exists")
    destination.mkdir(parents=True)
    for relative, content in project["files"].items():
        target = destination.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as output:
            output.write(content)
    metadata_path.write_text(
        json.dumps({"name": project["name"], "description": project["description"]}),
        encoding="utf-8",
    )
    print(f"generated project: {project['name']}")


if __name__ == "__main__":
    try:
        write_project(request_project())
    except KeyboardInterrupt:
        stop("generation interrupted")
