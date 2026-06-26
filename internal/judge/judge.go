// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package judge is stage 2 of the pipeline: it runs each llm_judge rule over the
// markdown content of a bundle through an llm.Client, turning a fired judgment
// into a finding at the rule's declared tier. It owns a bounded worker pool, a
// per-call timeout, and the per-(model, rule, file) result cache (whose entries
// are invalidated by content and rule hashes — see cache.go).
//
// The stage is fail-closed: any client error (network failure, refusal,
// truncation, an unparseable or schema-invalid response) aborts the scan rather
// than being read as "did not fire", so a security gate never passes a skill it
// could not actually evaluate.
package judge

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mongodb/skill-gate/internal/rules"
	"github.com/mongodb/skill-gate/llm"
	"github.com/mongodb/skill-gate/verdict"
)

// DefaultConcurrency bounds the in-flight LLM calls when no other value is set.
const DefaultConcurrency = 4

// Finding is a single llm_judge rule firing on a file. It mirrors the static
// stage's finding shape so the scanner can merge the two, and adds the model's
// Rationale. Severity is always the rule's declared tier — the judge stage
// applies no suppression, so judge findings are never downgraded. Line/Column/
// Match come from the model's first source span, and are zero/empty when the
// model did not localize the match.
type Finding struct {
	RuleID      string
	Pack        string
	Description string
	Remediation string
	Severity    verdict.Severity
	Criterion   int
	File        string
	Line        int
	Column      int
	Match       string
	Confidence  float64
	Rationale   string
}

// File is one markdown file to judge.
type File struct {
	Path    string
	Content string
}

// judgeRule pairs a rule with the pack it came from, for finding attribution.
type judgeRule struct {
	rule *rules.Rule
	pack string
}

// Engine runs the llm_judge rules of a set of packs against bundle files.
//
// The confidence floor (scanner's --min-confidence) deliberately does not apply
// here: a judge rule's confidence is the model's uncalibrated self-report, not a
// comparable, authored weight like a static pattern's, so it is unsafe to gate a
// tier on it. A fired judge finding therefore always reports at the rule's
// declared tier — never downgraded or dropped — which is also the strictly safer
// direction for a security gate.
type Engine struct {
	client      llm.Client
	rules       []judgeRule
	model       string
	concurrency int
	timeout     time.Duration
	cache       *Cache
}

// Option configures an Engine at construction.
type Option func(*Engine)

// WithConcurrency caps the number of in-flight LLM calls. A value <= 0 keeps the
// default.
func WithConcurrency(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.concurrency = n
		}
	}
}

// WithTimeout sets a per-call timeout applied to each LLM request. Zero means no
// per-call timeout (the parent context still applies).
func WithTimeout(d time.Duration) Option { return func(e *Engine) { e.timeout = d } }

// WithCache attaches a result cache. Nil disables caching.
func WithCache(c *Cache) Option { return func(e *Engine) { e.cache = c } }

// NewEngine flattens the llm_judge rules of packs into a runnable engine bound
// to client. If client implements Model() string, that id keys the cache and
// scopes cached results to the model that produced them.
func NewEngine(packs []rules.Pack, client llm.Client, opts ...Option) *Engine {
	e := &Engine{client: client, concurrency: DefaultConcurrency}
	for pi := range packs {
		p := &packs[pi]
		for ri := range p.Rules {
			if r := &p.Rules[ri]; r.Type == rules.RuleTypeLLMJudge {
				e.rules = append(e.rules, judgeRule{rule: r, pack: p.Name})
			}
		}
	}
	if m, ok := client.(interface{ Model() string }); ok {
		e.model = m.Model()
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// RuleCount reports how many llm_judge rules the engine will apply.
func (e *Engine) RuleCount() int { return len(e.rules) }

// ScanFiles evaluates every llm_judge rule against every file, returning the
// findings that fired. It runs calls through a bounded worker pool; the first
// error aborts the rest and is returned, so the scan fails closed.
func (e *Engine) ScanFiles(ctx context.Context, files []File) ([]Finding, error) {
	if len(e.rules) == 0 || len(files) == 0 {
		return nil, nil
	}
	if e.client == nil {
		return nil, fmt.Errorf("judge: no LLM client configured for %d llm_judge rule(s)", len(e.rules))
	}

	type task struct{ fileIdx, ruleIdx int }
	tasks := make([]task, 0, len(files)*len(e.rules))
	for fi := range files {
		for ri := range e.rules {
			tasks = append(tasks, task{fi, ri})
		}
	}

	workers := min(e.concurrency, len(tasks))
	taskCh := make(chan task)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex
		findings []Finding
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel() // stop the feeder and let workers drain
		}
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for t := range taskCh {
				if ctx.Err() != nil {
					continue // drain remaining tasks without work
				}
				f, err := e.judgeOne(ctx, e.rules[t.ruleIdx], files[t.fileIdx])
				if err != nil {
					fail(err)
					continue
				}
				if f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}
		})
	}

	for _, t := range tasks {
		if ctx.Err() != nil {
			break
		}
		taskCh <- t
	}
	close(taskCh)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return findings, nil
}

// judgeOne evaluates a single (rule, file). It consults the cache, calls the
// client on a miss, and turns a fired judgment into a finding at the rule's
// declared tier. A nil finding means the rule did not fire.
func (e *Engine) judgeOne(ctx context.Context, jr judgeRule, f File) (*Finding, error) {
	resp, err := e.evaluate(ctx, jr.rule, f)
	if err != nil {
		return nil, err
	}
	if !resp.Fired {
		return nil, nil
	}
	line, col, match := firstSpan(resp.Spans)
	// The model's line/column are untrusted: clamp an out-of-range line to 0
	// (unknown) so a finding never points a reader or a CI annotation at a line
	// the file does not have.
	if line < 0 || line > lineCount(f.Content) {
		line, col = 0, 0
	}
	if col < 0 {
		col = 0
	}
	return &Finding{
		RuleID:      jr.rule.ID,
		Pack:        jr.pack,
		Description: jr.rule.Description,
		Remediation: jr.rule.Remediation,
		Severity:    jr.rule.Severity,
		Criterion:   jr.rule.Criterion,
		File:        f.Path,
		Line:        line,
		Column:      col,
		Match:       match,
		Confidence:  resp.Confidence,
		Rationale:   resp.Rationale,
	}, nil
}

// evaluate returns the judge response for (rule, file), from cache when valid or
// from the client otherwise. A fresh result is written back best-effort: a cache
// write failure never fails the scan.
func (e *Engine) evaluate(ctx context.Context, r *rules.Rule, f File) (*llm.JudgeResponse, error) {
	cHash := contentHash(f.Content)
	rHash := ruleHash(r)
	var key string
	if e.cache != nil {
		key = cacheKey(e.model, r.ID, f.Path)
		if entry, ok := e.cache.get(key); ok && entry.ContentHash == cHash && entry.RuleHash == rHash {
			resp := entry.Response
			return &resp, nil
		}
	}

	callCtx := ctx
	if e.timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}
	resp, err := e.client.Judge(callCtx, llm.JudgeRequest{
		RuleID:     r.ID,
		Rubric:     r.Rubric,
		Exclusions: r.Exclusions,
		Schema:     r.SchemaBytes(),
		File:       f.Path,
		Content:    f.Content,
	})
	if err != nil {
		return nil, err
	}

	if e.cache != nil {
		_ = e.cache.save(key, &CacheEntry{
			Model:       e.model,
			RuleID:      r.ID,
			File:        f.Path,
			ContentHash: cHash,
			RuleHash:    rHash,
			JudgedAt:    time.Now().UTC(),
			Response:    *resp,
		})
	}
	return resp, nil
}

// firstSpan extracts a reportable location from the model's spans: the first
// span's line/column and a truncated copy of its text. Zero/empty when there are
// no spans.
func firstSpan(spans []llm.Span) (line, col int, match string) {
	if len(spans) == 0 {
		return 0, 0, ""
	}
	s := spans[0]
	return s.Line, s.Column, truncate(s.Text, 200)
}

// lineCount returns the number of 1-based lines in content (the count of
// newlines plus one), used to bound an untrusted span line.
func lineCount(content string) int {
	return strings.Count(content, "\n") + 1
}

// truncate limits s to at most n bytes without splitting a multibyte UTF-8 rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
