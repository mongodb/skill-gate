// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package llm is skill-gate's extension contract for the LLM-as-judge stage.
// It is the only seam an org needs to bring its own model or provider: implement
// Client and pass it to scanner.Scan.
//
// The contract is deliberately narrow. Judge reports whether a rule fired, with
// a confidence, a rationale, and the source spans it keyed on — it does not
// return a severity. Severity is a property of the rule (the checklist criterion
// it encodes), not of the model's judgment; the scanner applies the rule's
// declared tier afterward. Keeping severity out of this package keeps the
// verdict vocabulary out of Client's forced public closure.
package llm

import (
	"context"
	"encoding/json"
)

// Client evaluates a single rule against a single file's content. Implementations
// must be safe for concurrent use: the judge runner calls Judge from a bounded
// pool of goroutines.
type Client interface {
	// Judge evaluates req and returns whether the rule fired. A non-nil error
	// means the judgment could not be produced (network failure, an unparseable
	// or schema-invalid model response, a refusal, a truncated response); callers
	// treat that as a tool error and fail closed rather than as "did not fire".
	Judge(ctx context.Context, req JudgeRequest) (*JudgeResponse, error)
}

// JudgeRequest is one (rule, file) evaluation. It is provider-agnostic: the
// model id and credentials live on the Client, not here.
type JudgeRequest struct {
	// RuleID is the rule being evaluated, for diagnostics and logging.
	RuleID string
	// Rubric is the natural-language criterion the model applies.
	Rubric string
	// Exclusions are "do not flag if …" conditions that should keep the rule from
	// firing. May be empty.
	Exclusions []string
	// Schema is the JSON Schema the model's response must satisfy. A conforming
	// response decodes into JudgeResponse. It is carried as raw bytes so the
	// contract does not depend on any particular schema library.
	Schema json.RawMessage
	// File is the bundle-relative path of the content being judged, for spans and
	// diagnostics.
	File string
	// Content is the full markdown content of the file.
	Content string
}

// JudgeResponse is the model's verdict for one (rule, file). It carries no
// severity — see the package doc.
type JudgeResponse struct {
	// Fired reports whether the content violates the rule.
	Fired bool `json:"fired"`
	// Confidence is the model's confidence in (0, 1].
	Confidence float64 `json:"confidence"`
	// Rationale is a short, author-facing explanation of the decision.
	Rationale string `json:"rationale"`
	// Spans locate the offending content. Empty when Fired is false, and may be
	// empty even when Fired is true if the model cannot localize the match.
	Spans []Span `json:"spans"`
}

// Span is a location the judge keyed its decision on. Line and Column are
// 1-based; either may be zero when the model cannot pin an exact position.
type Span struct {
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Text   string `json:"text"`
}
