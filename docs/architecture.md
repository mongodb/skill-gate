# skill-gate — Architecture Decisions

**Status:** accepted for v1
**Audience:** contributors implementing skill-gate's v1 feature work

This document captures the structural decisions made while scaffolding the repo, so
the implementation work inherits them rather than re-litigating them. It is
deliberately about *structure and the public API surface*; the product context that
shapes the package boundaries (threat model, two-stage pipeline, rule packs, verdict
mapping) is summarized in [§6](#6-product-context-that-shapes-the-boundaries).

---

## 1. Module and tooling

- **Module path:** `github.com/mongodb/skill-gate`. Baked into every import; chosen
  for MongoDB-org ownership.
- **Lint + format:** `golangci-lint` (v2 config in `.golangci.yml`) is the single
  source of truth for both. `golangci-lint fmt` runs the `gofumpt` formatter;
  `golangci-lint run` runs the static linters (errcheck, govet, ineffassign,
  staticcheck, unused).
- **Before-commit enforcement:** the pre-commit framework consumes golangci-lint's
  own official hooks (`.pre-commit-config.yaml`, rev-pinned). A `Makefile` exposes
  the same commands (`make fmt/lint/test/build`) for those who don't use pre-commit.
- **CI** (`.github/workflows/ci.yml`) mirrors the local checks: a `lint` job
  (golangci-lint + `fmt --diff`) and a `test` job (race tests + build on
  ubuntu/windows). The golangci-lint version is pinned in the pre-commit rev and the
  CI `version:` — **keep them in sync.**

## 2. Package layout

```
cmd/skill-gate/main.go          # reference wiring: default anthropic client -> scanner.Scan
examples/custom-client/main.go  # supported bring-your-own-client example (built in CI)
llm/                            # Client, JudgeRequest, JudgeResponse        (public)
scanner/                        # Scan, Config, Report                       (public entry point)
verdict/                        # Severity tiers + exit-code mapping         (public)
internal/
  cli/                          # cobra commands: root, scan, version, rules
  judge/                        # stage 2: LLM-as-judge runner + (rule_id, content_hash) cache
  static/                       # stage 1: regex engine + doc-example suppression
  rules/                        # YAML pack loading, rule types, pack registry
  report/                       # output: text / json / markdown / GH annotations
rules/                          # shipped packs, go:embed'd: core/ + mongodb-atlas/
```

## 3. Public API surface (Posture B — embeddable core)

The reusability story has three tiers, ordered by how many users hit them:

1. **Run it** — `skill-gate scan`, `--rules-dir`, env config. No Go API.
2. **Bring your own packs** — author YAML rule packs against the documented schema;
   validate with `rules lint`. No Go API (rules are data).
3. **Bring your own client / embed it** — the Go-API tier, kept deliberately small:
   implement `llm.Client`, pass it to `scanner.Scan`, read a `Report`.

Tiers 1-2 cover the large majority of reuse with zero Go API. Tier 3 is the only
part that exports Go symbols, and it exists to honor a core goal: an org can supply
its own LLM client (e.g. Bedrock+IRSA) without touching the rest of the codebase.

### What is public, and why

| Package | Visibility | Rationale |
|---|---|---|
| `llm` (`Client`, `JudgeRequest`, `JudgeResponse`) | **public** | The extension contract. |
| `scanner` (`Scan`, `Config`, `Report`) | **public** | The one embeddable entry point + result type. |
| `verdict` (severity tiers, exit-code mapping) | **public** | Stable, dependency-free vocabulary. |
| `judge`, `static`, `rules`, `report`, scanner internals | **internal** | Implementation over churning types; promote on demand. |

### The rule we applied: contract vs. implementation

- A **contract** is something others plug into across the package boundary (an
  interface they implement, or a type that crosses it). Contracts must be public.
- An **implementation** is concrete logic others might call. Exporting it is
  elective and freezes a shape we must then maintain. Promoting later is cheap and
  non-breaking; un-publishing is a breaking change. So: keep implementations
  `internal/` until a concrete consumer appears.

Applying it:

- **`llm.Client` is public (forced).** It is *the* extension point. Keep it
  **narrow**: a public package cannot usefully expose `internal/` types, so whatever
  `Client`'s signature references is dragged public. In particular, **`Judge` must
  not return a severity** — severity is a property of the *rule* (each rule declares
  its tier), not of the LLM's judgment. `Judge` reports whether
  a rule fired, with confidence/rationale/source spans; the scanner looks up the
  declared tier afterward. This keeps `verdict` out of `llm`'s forced closure.
- **`verdict` is public (elective, low-regret).** A tiny vocabulary: the three tiers,
  max-tier aggregation, and tier→exit-code mapping. Stable by construction (the tier
  set is fixed at three values; exit codes are already a CLI contract). Near-zero
  cost, near-zero churn.
- **`scanner.Scan` is public (elective).** Its marginal commitment is small because
  `Report` mirrors the `-o json` schema we commit to the moment we ship JSON output.
  `Config` is an **options struct** so fields can be added without breaking callers.
- **`judge` stays internal.** Its runner is welded to the types most likely to churn
  (pack types, prompt assembly, the cache). The two realistic "modify the judge"
  desires are already served without a Go API: different model/provider → the
  `llm.Client` seam; different rubric/criteria → rule packs as data. Standalone
  in-process use of the judge pipeline is speculative; promote on demand against
  stabilized types.

## 4. The bring-your-own-client seam

`cmd/skill-gate/main.go` is the reference wiring: it constructs the default
`anthropic` client and passes it to `scanner.Scan`. `examples/custom-client/main.go`
shows the same wiring with a bespoke `llm.Client`. **Both are built by
`go build ./...` in CI**, so the seam is continuously verified.

This is a supported v1 path, not just documentation. It benefits us too: swapping
our own LLM client (e.g. a gateway change) is the same operation the example
performs, so CI catches breakage to the seam regardless of who relies on it. It also
relieves pressure on the deferred `exec` client — custom-auth providers have the
thin-binary path in the meantime.

## 5. Command surface (v1 lean, not hard-committed)

- `skill-gate scan <bundle>` — primary command.
- `skill-gate version`.
- `skill-gate rules list` / `rules lint` — let pack authors inspect and validate
  packs without running a scan. Cheap to add, high value given packs-as-data is core.

## 6. Product context that shapes the boundaries

These product decisions are restated here only where they shape package boundaries:

- **LLM client config:** one `anthropic` client in v1, configured via
  `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_HEADER` / `ANTHROPIC_API_KEY`. Plain
  `net/http`, no third-party SDK. (`exec` client deferred.)
- **Rule packs as data:** `core` + `mongodb-atlas` ship `go:embed`'d so `go install`
  works standalone; `--rules-dir` / `rules.d/` overlay external packs at runtime.
  The `rules/` directory must live inside the module for embedding.
- **Verdict mapping:** max tier across triggered rules → AUTO-PASS (exit 0) /
  WARN (exit 1) / ESCALATE (exit 2), with reserved codes for tool errors.
- **Caching:** per-rule LLM results keyed by `(rule_id, content_hash)`.
