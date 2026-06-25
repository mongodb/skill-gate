// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package judge_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/mongodb/skill-gate/internal/judge"
	"github.com/mongodb/skill-gate/internal/rules"
	"github.com/mongodb/skill-gate/llm"
	builtinpacks "github.com/mongodb/skill-gate/rules"
	"github.com/mongodb/skill-gate/verdict"
)

const schemaJSON = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["fired", "confidence", "rationale", "spans"],
  "properties": {
    "fired": {"type": "boolean"},
    "confidence": {"type": "number"},
    "rationale": {"type": "string"},
    "spans": {"type": "array"}
  }
}`

// fakeClient is a deterministic llm.Client for tests. fn produces the response
// per request; calls counts invocations.
type fakeClient struct {
	model string
	mu    sync.Mutex
	calls int
	fn    func(req llm.JudgeRequest) (*llm.JudgeResponse, error)
}

func (c *fakeClient) Judge(_ context.Context, req llm.JudgeRequest) (*llm.JudgeResponse, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.fn(req)
}

func (c *fakeClient) Model() string { return c.model }

func (c *fakeClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// judgePack loads a single-rule llm_judge pack with the given id and severity.
func judgePack(t *testing.T, id string, sev verdict.Severity) []rules.Pack {
	t.Helper()
	body := fmt.Sprintf(`pack: test
version: 0.1.0
rules:
  - id: %s
    description: a judge rule
    type: llm_judge
    severity: %s
    rubric: judge this
    schema_ref: finding.json
`, id, sev)
	packs, err := rules.LoadFS(fstest.MapFS{
		"pack.yaml":    {Data: []byte(body)},
		"finding.json": {Data: []byte(schemaJSON)},
	})
	if err != nil {
		t.Fatalf("load judge pack: %v", err)
	}
	return packs
}

func fired(conf float64) *llm.JudgeResponse {
	return &llm.JudgeResponse{Fired: true, Confidence: conf, Rationale: "because", Spans: []llm.Span{{Line: 4, Column: 2, Text: "bad"}}}
}

func files() []judge.File {
	// Several lines so a span at line 4 (see fired) is within range.
	return []judge.File{{Path: "SKILL.md", Content: "line one\nline two\nline three\nline four\nline five\n"}}
}

func TestScanFilesFired(t *testing.T) {
	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) { return fired(0.9), nil }}
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), c)
	got, err := e.ScanFiles(context.Background(), files())
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.RuleID != "L-001" || f.Severity != verdict.SeverityEscalate || f.Line != 4 || f.Rationale != "because" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestScanFilesClampsOutOfRangeSpan(t *testing.T) {
	// The model reports line 99, but the file has far fewer lines; the finding's
	// location is clamped to 0 (unknown) rather than pointing past the file.
	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) {
		return &llm.JudgeResponse{Fired: true, Confidence: 0.9, Spans: []llm.Span{{Line: 99, Column: 3, Text: "x"}}}, nil
	}}
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), c)
	got, err := e.ScanFiles(context.Background(), []judge.File{{Path: "SKILL.md", Content: "a\nb\n"}})
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(got) != 1 || got[0].Line != 0 || got[0].Column != 0 {
		t.Errorf("expected clamped location 0:0, got %+v", got)
	}
}

func TestScanFilesTruncatesMatchOnRuneBoundary(t *testing.T) {
	// The model can return an arbitrarily long span; the finding's Match is capped
	// at 200 bytes, and the cap must land on a rune boundary so a multibyte rune
	// straddling the limit is dropped whole rather than split into invalid UTF-8.
	// Here "€" is 3 bytes, so byte 200 falls mid-rune and the cut backs up to 199.
	long := strings.Repeat("a", 199) + strings.Repeat("€", 50)
	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) {
		return &llm.JudgeResponse{
			Fired: true, Confidence: 0.9, Rationale: "x",
			Spans: []llm.Span{{Line: 1, Column: 1, Text: long}},
		}, nil
	}}
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), c)
	got, err := e.ScanFiles(context.Background(), []judge.File{{Path: "SKILL.md", Content: "only one line"}})
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	m := got[0].Match
	if len(m) > 200 {
		t.Errorf("match is %d bytes, want <= 200", len(m))
	}
	if !utf8.ValidString(m) {
		t.Errorf("match is not valid UTF-8: %q", m)
	}
	if m != strings.Repeat("a", 199) {
		t.Errorf("expected truncation at the rune boundary (199 'a's), got %q", m)
	}
}

func TestScanFilesNotFired(t *testing.T) {
	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) {
		return &llm.JudgeResponse{Fired: false, Confidence: 0.2}, nil
	}}
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), c)
	got, err := e.ScanFiles(context.Background(), files())
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %+v", got)
	}
}

func TestScanFilesFailClosed(t *testing.T) {
	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) {
		return nil, errors.New("boom")
	}}
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), c)
	if _, err := e.ScanFiles(context.Background(), files()); err == nil {
		t.Error("expected fail-closed error, got nil")
	}
}

func TestScanFilesNoConfidenceSuppression(t *testing.T) {
	// The confidence floor does not apply to judge findings: even a very
	// low-confidence ESCALATE reports at its full declared tier, never downgraded
	// or dropped (model self-confidence is uncalibrated; see Engine doc).
	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) { return fired(0.01), nil }}
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), c)
	got, err := e.ScanFiles(context.Background(), files())
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(got) != 1 || got[0].Severity != verdict.SeverityEscalate {
		t.Errorf("expected one ESCALATE finding (no downgrade), got %+v", got)
	}
}

func TestCacheServesSecondRun(t *testing.T) {
	c := &fakeClient{model: "m", fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) { return fired(0.9), nil }}
	cache := judge.NewCache(t.TempDir())
	packs := judgePack(t, "L-001", verdict.SeverityEscalate)

	e1 := judge.NewEngine(packs, c, judge.WithCache(cache))
	if _, err := e1.ScanFiles(context.Background(), files()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// A fresh engine over the same cache, same content/rule/model: the cached
	// result is served and the client is not called again.
	e2 := judge.NewEngine(packs, c, judge.WithCache(cache))
	got, err := e2.ScanFiles(context.Background(), files())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if c.count() != 1 {
		t.Errorf("client called %d times, want 1 (second run cached)", c.count())
	}
}

func TestCacheInvalidatedByContentChange(t *testing.T) {
	c := &fakeClient{model: "m", fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) { return fired(0.9), nil }}
	cache := judge.NewCache(t.TempDir())
	packs := judgePack(t, "L-001", verdict.SeverityEscalate)

	e := judge.NewEngine(packs, c, judge.WithCache(cache))
	if _, err := e.ScanFiles(context.Background(), []judge.File{{Path: "SKILL.md", Content: "v1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ScanFiles(context.Background(), []judge.File{{Path: "SKILL.md", Content: "v2"}}); err != nil {
		t.Fatal(err)
	}
	if c.count() != 2 {
		t.Errorf("client called %d times, want 2 (content changed between runs)", c.count())
	}
}

func TestNoClientWithRulesErrors(t *testing.T) {
	e := judge.NewEngine(judgePack(t, "L-001", verdict.SeverityEscalate), nil)
	if _, err := e.ScanFiles(context.Background(), files()); err == nil {
		t.Error("expected error when llm_judge rules have no client, got nil")
	}
}

// TestShippedLLMRulesAllFire is the deterministic, CI-safe coverage guard for
// the judge stage (the analog of scanner.TestRulesFireInIntendedBundle for
// static rules): with a stub client that always fires, every shipped llm_judge
// rule must produce a finding at its declared tier. It catches a rule that fails
// to load (bad schema_ref), is misfiled, or carries a wrong severity — without
// any live model.
func TestShippedLLMRulesAllFire(t *testing.T) {
	packs, err := rules.LoadAll(builtinpacks.FS, nil, "")
	if err != nil {
		t.Fatalf("load shipped packs: %v", err)
	}
	want := map[string]verdict.Severity{}
	for pi := range packs {
		for ri := range packs[pi].Rules {
			if r := &packs[pi].Rules[ri]; r.Type == rules.RuleTypeLLMJudge {
				want[r.ID] = r.Severity
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("no shipped llm_judge rules found")
	}

	c := &fakeClient{fn: func(llm.JudgeRequest) (*llm.JudgeResponse, error) { return fired(0.9), nil }}
	got, err := judge.NewEngine(packs, c).ScanFiles(context.Background(), files())
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	seen := map[string]verdict.Severity{}
	for _, f := range got {
		seen[f.RuleID] = f.Severity
	}
	for id, sev := range want {
		switch got, ok := seen[id]; {
		case !ok:
			t.Errorf("shipped llm_judge rule %s did not fire", id)
		case got != sev:
			t.Errorf("rule %s fired at %s, want its declared %s", id, got, sev)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("fired %d rules, want exactly the %d shipped llm_judge rules", len(seen), len(want))
	}
}

func TestNoRulesIsNoop(t *testing.T) {
	// No llm_judge rules: ScanFiles is a no-op even with a nil client.
	e := judge.NewEngine(nil, nil)
	got, err := e.ScanFiles(context.Background(), files())
	if err != nil || got != nil {
		t.Errorf("ScanFiles with no rules = (%v, %v), want (nil, nil)", got, err)
	}
}
