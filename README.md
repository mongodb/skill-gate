# skill-gate

A CLI that gates Agent Skill PRs by evaluating the **prose and guidance** of a skill
bundle — not its code — for content that could steer an agent toward unsafe behavior.
It runs a skill's markdown through a YAML rule pack and produces a single verdict:
**AUTO-PASS**, **WARN**, or **ESCALATE**.

> **Status: both stages implemented.** The CLI (`scan`, `version`, `rules list`,
> `rules lint`), the static-pattern engine, the LLM-as-judge stage, the `core` +
> `mongodb` rule packs, and the full output surface needed to gate PRs in CI
> (`text`, `json`, `markdown`, and GitHub Actions `--emit-annotations`) are working
> today.

## Why it exists

Most skill scanners target *untrusted-author maliciousness* (prompt injection, code
execution, exfiltration). skill-gate sits in a different lane: **trusted-author
content evaluation** — skills written in good faith whose guidance could still direct
an agent toward unsafe actions (logging credentials, over-broad permissions,
unguarded destructive commands, ambiguous scope). It evaluates instructional content,
not code logic.

## How it works

A two-stage pipeline over every markdown file in a skill bundle:

1. **Static patterns** *(implemented)* — regex rules for criteria with clear lexical
   signatures (credential references, hardcoded secrets in examples, destructive verbs,
   external URLs), with a heuristic that *downgrades* matches reading as cautionary
   documentation examples ("never log credentials") to an advisory WARN rather than
   silently dropping them — so a real instruction disguised with cautionary phrasing
   can never slip through to AUTO-PASS.
2. **LLM-as-judge** *(implemented)* — rubric-based evaluation for criteria that need
   semantic judgment (unsanitized user input, PII handling, over-broad permissions,
   admin-command scope, ambiguous scope, missing guardrails). Each `llm_judge` rule carries a rubric and a
   JSON-schema'd finding contract; the judge fails closed — a refusal, truncation, or
   invalid response is a tool error, never a silent pass — and caches results per
   `(model, rule, file)` so unchanged skills aren't re-evaluated.

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
# Scan a skill bundle (text output; exit code 0/1/2 = AUTO-PASS/WARN/ESCALATE)
# Stage 2 needs an LLM client (see below); add --static-only to run stage 1 alone.
skill-gate scan ./my-skill/

# Machine-readable output / PR comment
skill-gate scan ./my-skill/ -o json
skill-gate scan ./my-skill/ -o markdown

# CI: pin findings to lines in the PR diff via GitHub Actions annotations
skill-gate scan ./my-skill/ --emit-annotations

# Treat WARN as a blocking exit code (per-repo CI policy)
skill-gate scan ./my-skill/ --strict

# Filter low-confidence static findings: below the floor, ESCALATE→WARN or WARN drops
# (static stage only; judge confidence is uncalibrated, so the floor doesn't gate it)
skill-gate scan ./my-skill/ --min-confidence 0.6

# Choose which built-in packs run (default: all)
skill-gate scan ./my-skill/ --packs core          # core only
skill-gate scan ./my-skill/ --packs none --rules-dir ./rules.d/   # only your packs

# Overlay your own rule packs (added on top of the selected built-ins)
skill-gate scan ./my-skill/ --rules-dir ./rules.d/

# Run only the static stage (no LLM client required)
skill-gate scan ./my-skill/ --static-only

# Inspect and validate rule packs
skill-gate rules list
skill-gate rules lint --rules-dir ./rules.d/
```

`--emit-annotations` writes GitHub Actions workflow commands (`::error` / `::warning`)
to stdout in addition to the chosen `-o` format, so a CI job can both produce a report
artifact and pin each finding to its line in the diff. The annotation paths are
resolved relative to the directory the scan is launched from.

The LLM-as-judge stage uses a client configured by environment —
`ANTHROPIC_API_KEY` (required), `ANTHROPIC_BASE_URL` (default
`https://api.anthropic.com`), and `ANTHROPIC_AUTH_HEADER` (default `x-api-key`; set
`api-key` for an Azure-fronted gateway) — with the model set by `--llm-model`
(default `claude-sonnet-4-6`). When the selected packs contain `llm_judge` rules but
no client is configured, the scan **fails closed** (a tool error) rather than skipping
them; pass `--static-only` to run stage 1 alone. The static stage needs no
configuration.

The judge result cache is **opt-in** and off by default (`--cache-dir <path>` enables
it): its validity is keyed only on public inputs and the author's own content, so a
committed cache could be forged to force a pass. In CI, point `--cache-dir` at an
ephemeral, never-committed location (or leave caching off); locally, treat it as
scratch. Skill content sent to the judge is fenced as untrusted input, so prose that
tries to talk the judge out of a finding does not change the verdict.

## Extending it

skill-gate is built to be reusable in other projects:

- **Bring your own rules** *(available now)* — rule packs are plain YAML loaded via
  `--rules-dir`; no Go required. Validate them with `skill-gate rules lint`.
- **Choose your packs** *(available now)* — `--packs` selects which built-in packs run
  (e.g. `--packs core` for a non-MongoDB repo, or `--packs none` to run only your own
  overlays). The default runs every built-in pack.
- **Embed the scanner** *(available now)* — call `scanner.Scan` and read the returned
  `Report`. The `verdict` package is the stable vocabulary for tiers and exit codes.
- **Bring your own LLM client** *(available now)* — implement the `llm.Client`
  interface (one `Judge` method) and pass it to `scanner.Scan` via `Config.Client`,
  e.g. for Bedrock or a custom gateway. See [`examples/custom-client`](examples/custom-client).

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
