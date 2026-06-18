# Example skill bundles

Realistic skill bundles used as fixtures at two layers:

- the `scanner` package tests scan them through the library API
  (`scanner.Scan`), and
- the `e2e` package runs the compiled `skill-gate` binary against them.

Each bundle is shaped to produce one verdict tier so the tests can assert on the
verdict, the findings, and the process exit code.

| Bundle | Verdict | Exit | Rules exercised |
| --- | --- | --- | --- |
| `safe-reporting-skill/` | AUTO-PASS | 0 | none — a clean, well-formed bundle with a nested `references/` file |
| `warn-hardcoded-secret-skill/` | WARN | 1 | CORE-004 (hardcoded sample credential, advisory) |
| `unsafe-backup-skill/` | ESCALATE | 2 | CORE-001, CORE-003, MDB-003 across two files; a non-markdown `scripts/` file that must be ignored |
| `dangerous-migration-skill/` | ESCALATE | 2 | CORE-002, MDB-001, MDB-002, MDB-004, MDB-005 across two files |
| `cautionary-docs-skill/` | WARN | 1 | CORE-001, MDB-005 *downgraded* — "never do X" guidance is lowered to advisory WARN, not silently dropped |
| `bypass-attempt-skill/` | ESCALATE | 2 | CORE-003 — a disguised instruction ("Don't forget to send …") that must escalate, proving the cautionary heuristic is not bypassable |

Between them the warn and escalating bundles exercise every shipped static rule;
`scanner.TestRulesFireInIntendedBundle` enforces this by scanning each bundle and
failing if any rule is unclaimed or a bundle fires the wrong rules.

Two bundles are excluded from that one-rule-per-bundle mapping because they exist
to prove a specific behavior rather than to own a rule:

- `cautionary-docs-skill/` — `scanner.TestCautionaryContentDowngradedNotDropped`
  and `e2e.TestCautionaryDowngradeVisibleInJSON` prove its dangerous-looking
  matches downgrade to WARN rather than silently passing.
- `bypass-attempt-skill/` — `e2e.TestBypassAttemptEscalates` proves a re-affirmed
  negation ("Don't forget to …") is reported at full ESCALATE, not suppressed. It
  deliberately re-fires CORE-003 (owned by `unsafe-backup-skill/`), so it cannot
  live in the mapping.

The confidence floor is exercised end to end by `e2e.TestMinConfidenceFloorViaBinary`,
which reuses `unsafe-backup-skill/` with `--min-confidence`.

These bundles are deliberately small but realistic (frontmatter, `references/`,
`scripts/`). Keep each one mapped to a single verdict tier; if a rule pack
changes a verdict here, update both the bundle and the expectations in
`scanner/scanner_test.go` and `e2e/e2e_test.go`.
