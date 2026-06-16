# skill-gate

A CLI that gates Agent Skill PRs by evaluating the **prose and guidance** of a skill
bundle — not its code — for content that could steer an agent toward unsafe behavior.
It runs a skill's markdown through a YAML rule pack and produces a single verdict:
**AUTO-PASS**, **WARN**, or **ESCALATE**.

> **Status: early scaffold.** The command tree is not built out yet; this repo
> currently holds the project structure, tooling, and architecture decisions. Usage
> below describes the intended v1 surface and will become real as the package is
> built.

## Why it exists

Most skill scanners target *untrusted-author maliciousness* (prompt injection, code
execution, exfiltration). skill-gate sits in a different lane: **trusted-author
content evaluation** — skills written in good faith whose guidance could still direct
an agent toward unsafe actions (logging credentials, over-broad permissions,
unguarded destructive commands, ambiguous scope). It evaluates instructional content,
not code logic.

## How it works

A two-stage pipeline over every markdown file in a skill bundle:

1. **Static patterns** — regex rules for criteria with clear lexical signatures
   (credential references, hardcoded secrets in examples, destructive verbs, external
   URLs), with a heuristic that avoids flagging cautionary documentation examples.
2. **LLM-as-judge** — rubric-based evaluation for criteria that need semantic
   judgment (unsanitized user input, ambiguous scope, missing guardrails).

Each rule declares a severity tier. The verdict is the highest tier any rule triggers:

| Verdict | Exit code | Meaning |
|---|---|---|
| AUTO-PASS | `0` | No rules fired. |
| WARN | `1` | Advisory findings; author resolves before opening a PR. |
| ESCALATE | `2` | Blocking findings; requires security review. |

## Install

```sh
go install github.com/mongodb/skill-gate/cmd/skill-gate@latest
```

## Usage

```sh
# Scan a skill bundle
skill-gate scan ./my-skill/

# Machine-readable output / PR comments / CI annotations
skill-gate scan ./my-skill/ -o json
skill-gate scan ./my-skill/ -o markdown
skill-gate scan ./my-skill/ --emit-annotations

# Overlay your own rule packs
skill-gate scan ./my-skill/ --rules-dir ./rules.d/
```

The LLM client is configured by environment:

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | API key. |
| `ANTHROPIC_BASE_URL` | API base URL (defaults to the public Anthropic API). |
| `ANTHROPIC_AUTH_HEADER` | Auth header name (`x-api-key` default; `api-key` for gateway-fronted endpoints). |

## Extending it

skill-gate is built to be reusable in other projects:

- **Bring your own rules** — rule packs are plain YAML loaded via `--rules-dir`; no Go
  required.
- **Bring your own LLM client** — implement the `llm.Client` interface and wire it
  into `scanner.Scan`. See `examples/custom-client/` for a supported, CI-built
  example.

See [`docs/architecture.md`](docs/architecture.md) for the package layout and the
public API surface.

## Development

```sh
make fmt      # format (gofumpt via golangci-lint)
make lint     # static analysis + license-header check
make test     # race tests
make build    # build the binary

make install-hooks   # install pre-commit hooks (requires the pre-commit framework)
```

`golangci-lint` is the single source of truth for lint and format, shared by the
pre-commit hook and CI.

## License

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
