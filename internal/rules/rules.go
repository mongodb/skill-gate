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
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/mongodb/skill-gate/verdict"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Rule types. static_regex rules run in stage 1 (package static); llm_judge
// rules run in stage 2 (package judge). A pack declaring any other type is a
// load error so packs and the stages that run them stay in lockstep.
const (
	RuleTypeStaticRegex = "static_regex"
	RuleTypeLLMJudge    = "llm_judge"
)

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
	// Patterns are the regexes that trigger a static_regex rule; the rule fires
	// when any one of them matches. Unused by llm_judge rules.
	Patterns []Pattern `yaml:"patterns"`
	// Rubric is the natural-language criterion an llm_judge rule applies. Unused
	// by static_regex rules.
	Rubric string `yaml:"rubric,omitempty"`
	// Exclusions are "do not flag if …" conditions handed to the judge to keep an
	// llm_judge rule from firing on benign content. Optional, llm_judge only.
	Exclusions []string `yaml:"exclusions,omitempty"`
	// SchemaRef is the path (relative to the pack file) of the JSON Schema the
	// judge's response must satisfy. Required for llm_judge rules.
	SchemaRef string `yaml:"schema_ref,omitempty"`
	// SuppressInDocExamples enables the cautionary-documentation heuristic for
	// this rule: a match that sits in a context framed as "do not do this" is
	// suppressed under a bound — an ESCALATE match downgrades to WARN and only a
	// WARN match drops — so the heuristic can never turn a dangerous match into
	// AUTO-PASS. See package static.
	SuppressInDocExamples bool `yaml:"suppress_in_doc_examples"`
	// Remediation is author-facing guidance shown with a finding. Optional.
	Remediation string `yaml:"remediation,omitempty"`

	// schema is the raw JSON Schema loaded from SchemaRef for an llm_judge rule.
	// It is compiled (and so validated) during loading, then passed to the judge
	// client at scan time. Not part of the YAML schema.
	schema json.RawMessage `yaml:"-"`
}

// SchemaBytes returns the raw JSON Schema an llm_judge rule's response must
// satisfy, or nil for a static_regex rule. Valid only after the owning pack has
// loaded successfully.
func (r *Rule) SchemaBytes() json.RawMessage { return r.schema }

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
			// Confidence is documented as (0, 1]. A literal 0 means "unset" and
			// defaults to 1.0; anything outside the range is a malformed pack
			// (it would distort the min-confidence floor and tie-breaking), so
			// reject it here at the single load chokepoint.
			if pat.Confidence < 0 || pat.Confidence > 1 {
				return fmt.Errorf("rule %s: pattern %q: confidence %g out of range (0, 1]", r.ID, pat.Pattern, pat.Confidence)
			}
			if pat.Confidence == 0 {
				pat.Confidence = 1.0
			}
		}
	}
	return nil
}

// compileJSONSchema parses and compiles a JSON Schema document. It is the single
// chokepoint that turns a rule's schema_ref bytes into a runnable validator, so
// a malformed schema surfaces at load time.
func compileJSONSchema(data []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	const id = "skill-gate://rule-schema"
	if err := compiler.AddResource(id, doc); err != nil {
		return nil, fmt.Errorf("add schema resource: %w", err)
	}
	sch, err := compiler.Compile(id)
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return sch, nil
}
