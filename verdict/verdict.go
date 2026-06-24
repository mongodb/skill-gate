// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package verdict is skill-gate's stable, dependency-free vocabulary for rule
// severities and scan outcomes. It defines the two severity tiers a rule may
// declare, the three aggregate verdicts a scan can produce, the max-tier
// aggregation rule that maps the former to the latter, and the exit codes the
// CLI commits to.
//
// It is deliberately tiny and has no dependencies so that it can be imported
// from anywhere — the public scanner API, internal stages, and external
// embedders — without dragging in implementation types.
package verdict

// Severity is the tier a rule declares. Severity is a property of the rule (the
// checklist criterion it encodes), not of any particular finding: every finding
// a rule produces inherits the rule's declared tier.
type Severity string

const (
	// SeverityWarn marks an advisory criterion. The author resolves it before
	// opening a PR; the Docs team confirms resolution during review.
	SeverityWarn Severity = "WARN"
	// SeverityEscalate marks a blocking criterion. A Security team member must
	// review and approve before the PR can be opened.
	SeverityEscalate Severity = "ESCALATE"
)

// Valid reports whether s is a recognized severity tier.
func (s Severity) Valid() bool {
	return s == SeverityWarn || s == SeverityEscalate
}

// Verdict is the aggregate outcome of a scan: the highest tier any rule
// triggered, or AutoPass when nothing fired.
type Verdict string

const (
	// AutoPass means no rules fired; the skill proceeds directly to a PR.
	AutoPass Verdict = "AUTO-PASS"
	// Warn means only advisory rules fired.
	Warn Verdict = "WARN"
	// Escalate means at least one blocking rule fired.
	Escalate Verdict = "ESCALATE"
)

// Exit codes the CLI commits to. Codes 0-2 map to the three verdicts; codes at
// or above ExitError are reserved for tool errors (bad usage, unreadable
// bundle, malformed rule pack) so a caller can distinguish a clean ESCALATE
// from skill-gate itself failing.
const (
	ExitAutoPass = 0
	ExitWarn     = 1
	ExitEscalate = 2
	// ExitError is the first reserved tool-error code. Callers should treat any
	// code >= ExitError as "skill-gate failed to run", not as a scan verdict.
	ExitError = 3
)

// Bound applies skill-gate's central suppression invariant to a single match.
// Given a rule's declared tier and whether some stage decided to suppress the
// match (a cautionary-example heuristic, a confidence floor, or any future
// axis), it returns the tier to report at, whether that is a downgrade, and
// whether the match should be dropped entirely.
//
// The bound is the security guarantee that no suppression path can turn a
// dangerous match into a silent AUTO-PASS: a suppressed ESCALATE downgrades to
// WARN (still seen by a human), and only a suppressed WARN — which has no lower
// tier — drops. The static stage routes its matches through here (both the
// cautionary-example heuristic and the confidence floor). The LLM-judge stage
// applies no suppression and so does not call Bound — a fired judge finding
// always reports at its declared tier, which trivially satisfies the same
// guarantee.
func Bound(declared Severity, suppressed bool) (tier Severity, downgraded, drop bool) {
	if !suppressed {
		return declared, false, false
	}
	if declared == SeverityEscalate {
		return SeverityWarn, true, false
	}
	return declared, false, true
}

// FromSeverities returns the max-tier verdict across the severities of the
// rules that triggered. The ordering is AutoPass < Warn < Escalate: any
// Escalate wins, otherwise any Warn wins, otherwise AutoPass.
func FromSeverities(severities []Severity) Verdict {
	v := AutoPass
	for _, s := range severities {
		switch s {
		case SeverityEscalate:
			return Escalate
		case SeverityWarn:
			v = Warn
		}
	}
	return v
}

// ExitCode maps a verdict to its committed process exit code. AutoPass is
// matched explicitly and any unrecognized verdict maps to ExitError: this is a
// security tool, so a corrupted verdict must fail closed rather than report a
// false success (exit 0).
func (v Verdict) ExitCode() int {
	switch v {
	case Escalate:
		return ExitEscalate
	case Warn:
		return ExitWarn
	case AutoPass:
		return ExitAutoPass
	default:
		return ExitError
	}
}
