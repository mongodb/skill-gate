// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package static is stage 1 of the pipeline: a regex engine that runs compiled
// rule-pack patterns over markdown content and emits findings, with a per-rule
// heuristic that suppresses matches framed as cautionary documentation
// examples (so a rule that warns "never log credentials" is not itself flagged
// for mentioning credentials).
package static

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mongodb/skill-gate/internal/rules"
	"github.com/mongodb/skill-gate/verdict"
)

// Finding is a single rule match located in a file. Severity is copied from the
// rule's declared tier; Confidence comes from the pattern that matched.
type Finding struct {
	RuleID      string
	Pack        string
	Description string
	Remediation string
	Severity    verdict.Severity
	// Downgraded is set when the cautionary-example heuristic lowered this
	// finding from ESCALATE to WARN rather than dropping it. The Severity field
	// already reflects the downgrade; this records that it happened.
	Downgraded bool
	Criterion  int
	File       string
	Line       int
	Column     int
	Match      string
	Confidence float64
}

// compiledRule pairs a rule with the pack it came from for finding attribution.
type compiledRule struct {
	rule *rules.Rule
	pack string
}

// MinConfidence maps a severity tier to the lowest pattern confidence reported
// at that tier. A static match whose pattern confidence is below the floor for
// its rule's tier is suppressed; suppression is bounded the same way as the
// cautionary heuristic, so an ESCALATE match downgrades to WARN and a WARN match
// drops. A nil map — or a zero floor for a tier — reports every match.
type MinConfidence map[verdict.Severity]float64

// Option configures an Engine at construction.
type Option func(*Engine)

// WithMinConfidence sets the per-tier confidence floor. See MinConfidence.
func WithMinConfidence(m MinConfidence) Option {
	return func(e *Engine) { e.minConf = m }
}

// Engine runs a fixed set of static rules over file content. Build one with
// NewEngine and reuse it across every file in a bundle.
type Engine struct {
	rules   []compiledRule
	minConf MinConfidence
}

// NewEngine flattens the given packs into a runnable engine. The packs must
// already be compiled (as rules.LoadFS does); a rule whose pattern was never
// compiled is a programming error and returns one here rather than silently
// matching nothing.
func NewEngine(packs []rules.Pack, opts ...Option) (*Engine, error) {
	e := &Engine{}
	for _, opt := range opts {
		opt(e)
	}
	for pi := range packs {
		p := &packs[pi]
		for ri := range p.Rules {
			r := &p.Rules[ri]
			if r.Type != rules.RuleTypeStaticRegex {
				continue
			}
			for qi := range r.Patterns {
				if r.Patterns[qi].Regexp() == nil {
					return nil, fmt.Errorf("rule %s: pattern %d not compiled; load packs with rules.LoadFS", r.ID, qi)
				}
			}
			e.rules = append(e.rules, compiledRule{rule: r, pack: p.Name})
		}
	}
	return e, nil
}

// RuleCount reports how many static rules the engine will apply.
func (e *Engine) RuleCount() int { return len(e.rules) }

// ScanFile applies every rule to content and returns the findings, sorted by
// line then rule id. For each rule, at most one finding is reported per line
// (the highest-confidence match), so multiple patterns hitting the same line do
// not produce duplicate noise.
func (e *Engine) ScanFile(path, content string) []Finding {
	starts := lineStarts(content)
	lines := strings.Split(content, "\n")

	var findings []Finding
	for _, cr := range e.rules {
		// best holds the strongest match per line for this rule (see better).
		best := map[int]Finding{}
		for pi := range cr.rule.Patterns {
			pat := &cr.rule.Patterns[pi]
			for _, loc := range pat.Regexp().FindAllStringIndex(content, -1) {
				line, col := position(content, loc[0], starts)
				cautionary := false
				if cr.rule.SuppressInDocExamples {
					matched := content[loc[0]:loc[1]]
					// The suppression check slices the match line by byte, so it
					// needs the 1-based byte column, not the rune column reported in
					// col.
					byteCol := loc[0] - starts[line-1] + 1
					cautionary = isCautionaryExample(matched, lines, line, byteCol)
				}
				severity, downgraded, drop := e.resolveTier(cr.rule.Severity, pat.Confidence, cautionary)
				if drop {
					continue
				}
				cand := Finding{
					RuleID:      cr.rule.ID,
					Pack:        cr.pack,
					Description: cr.rule.Description,
					Remediation: cr.rule.Remediation,
					Severity:    severity,
					Downgraded:  downgraded,
					Criterion:   cr.rule.Criterion,
					File:        path,
					Line:        line,
					Column:      col,
					Match:       truncate(content[loc[0]:loc[1]], 200),
					Confidence:  pat.Confidence,
				}
				// Keep the strongest match per line for this rule: a clean
				// ESCALATE must win the slot over a downgraded WARN regardless of
				// confidence, so a placeholder match cannot mask a real one on the
				// same line. Exact ties keep the first match seen.
				if existing, ok := best[line]; ok && !better(cand, existing) {
					continue
				}
				best[line] = cand
			}
		}
		for _, f := range best {
			findings = append(findings, f)
		}
	}
	sortFindings(findings)
	return findings
}

// lineStarts returns the byte offset at which each line begins.
func lineStarts(content string) []int {
	starts := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// position maps a byte offset into content to a 1-based line and column. The
// column counts Unicode code points (runes), not bytes, so a match that follows
// multibyte characters reports the column a human or editor would expect rather
// than a byte count.
func position(content string, offset int, starts []int) (line, col int) {
	// Binary search for the last line start <= offset.
	lo, hi := 0, len(starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if starts[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1, utf8.RuneCountInString(content[starts[lo]:offset]) + 1
}

// resolveTier applies stage-1 suppression to a single match. Two axes can
// suppress a match at its rule's declared tier: the cautionary-example heuristic
// and the per-tier confidence floor. Suppression is bounded so a dangerous match
// is never silently dropped — an ESCALATE match downgrades to WARN, while a WARN
// match (which has no lower tier) drops. This is the one place that enforces "no
// suppression path turns an ESCALATE into AUTO-PASS", for both axes.
//
// It returns the tier to report at, whether that tier is a downgrade, and
// whether the match should be dropped entirely.
func (e *Engine) resolveTier(declared verdict.Severity, confidence float64, cautionary bool) (tier verdict.Severity, downgraded, drop bool) {
	suppressed := cautionary || confidence < e.minConf[declared]
	if !suppressed {
		return declared, false, false
	}
	if declared == verdict.SeverityEscalate {
		return verdict.SeverityWarn, true, false
	}
	return declared, false, true
}

// better reports whether candidate a should replace b as the kept finding for a
// line: a more severe finding always wins, and within the same severity a
// higher-confidence one wins. Equal severity and confidence is not "better", so
// the first match seen is kept.
func better(a, b Finding) bool {
	if ra, rb := sevRank(a.Severity), sevRank(b.Severity); ra != rb {
		return ra > rb
	}
	return a.Confidence > b.Confidence
}

func sevRank(s verdict.Severity) int {
	switch s {
	case verdict.SeverityEscalate:
		return 2
	case verdict.SeverityWarn:
		return 1
	default:
		return 0
	}
}

// truncate returns s limited to at most n bytes without splitting a multibyte
// UTF-8 rune: if the byte limit falls inside a rune, it backs off to the
// preceding rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}
