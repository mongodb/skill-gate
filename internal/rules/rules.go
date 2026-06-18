// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package rules defines the rule-pack data model and loads packs from a
// filesystem. Rules are data, not code: a pack is a YAML document listing rules
// that each carry a checklist criterion, a declared severity, and one or more
// regex patterns. This package is internal because the pack types churn as the
// schema grows; the public contract is the YAML schema itself, not these Go
// types.
package rules

import (
	"fmt"
	"regexp"

	"github.com/mongodb/skill-gate/verdict"
)

// RuleTypeStaticRegex is the only rule type executed by the static stage. The
// schema reserves room for other types (e.g. an LLM-judge stage), but loading a
// pack that declares an unsupported type is an error today so that packs and
// the engine that runs them stay in lockstep.
const RuleTypeStaticRegex = "static_regex"

// Pack is one named, versioned collection of rules, loaded from a single YAML
// file.
type Pack struct {
	Name    string `yaml:"pack"`
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`

	// Source is the path the pack was loaded from, retained for diagnostics. It
	// is not part of the YAML schema.
	Source string `yaml:"-"`
}

// Rule encodes a single checklist criterion as a matchable unit.
type Rule struct {
	ID          string           `yaml:"id"`
	Description string           `yaml:"description"`
	Type        string           `yaml:"type"`
	Severity    verdict.Severity `yaml:"severity"`
	// Criterion is the PM security-checklist number this rule encodes, retained
	// for traceability back to the policy. Optional.
	Criterion int `yaml:"criterion,omitempty"`
	// Patterns are the regexes that trigger this rule; a rule fires when any one
	// of them matches.
	Patterns []Pattern `yaml:"patterns"`
	// SuppressInDocExamples enables the cautionary-documentation heuristic for
	// this rule: a match that sits in a context framed as "do not do this" is
	// suppressed under a bound — an ESCALATE match downgrades to WARN and only a
	// WARN match drops — so the heuristic can never turn a dangerous match into
	// AUTO-PASS. See package static.
	SuppressInDocExamples bool `yaml:"suppress_in_doc_examples"`
	// Remediation is author-facing guidance shown with a finding. Optional.
	Remediation string `yaml:"remediation,omitempty"`
}

// Pattern is one regex with an associated confidence in (0, 1]. Confidence feeds
// the per-tier confidence floor (scanner.Config.MinConfidence): a match whose
// pattern confidence is below the floor for its rule's tier is suppressed —
// downgraded from ESCALATE to WARN, or dropped at WARN — and it also breaks ties
// when several patterns hit one line. It never raises a rule's declared
// severity. With no floor configured (the default), every match is reported.
type Pattern struct {
	Pattern    string  `yaml:"pattern"`
	Confidence float64 `yaml:"confidence"`

	// re is the compiled form, populated by compile during loading so that
	// pattern errors surface at load time and the engine never recompiles.
	re *regexp.Regexp
}

// Regexp returns the compiled pattern. It is valid only after the owning pack
// has been loaded (or compiled) successfully.
func (p *Pattern) Regexp() *regexp.Regexp { return p.re }

// compile validates and compiles every pattern in the pack in place, defaulting
// an unset confidence to 1.0. It is the single chokepoint that turns raw YAML
// into a runnable pack.
func (p *Pack) compile() error {
	for ri := range p.Rules {
		r := &p.Rules[ri]
		for pi := range r.Patterns {
			pat := &r.Patterns[pi]
			re, err := regexp.Compile(pat.Pattern)
			if err != nil {
				return fmt.Errorf("rule %s: pattern %q: %w", r.ID, pat.Pattern, err)
			}
			pat.re = re
			if pat.Confidence == 0 {
				pat.Confidence = 1.0
			}
		}
	}
	return nil
}
