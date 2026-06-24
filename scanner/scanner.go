// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package scanner is skill-gate's single embeddable entry point. Scan loads the
// rule packs, runs them over the markdown in a skill bundle, and returns a
// Report whose verdict is the highest severity tier any rule triggered.
//
// Config is an options struct so fields can be added without breaking callers,
// and it references no internal types: an embedder supplies a rule filesystem
// and/or an overlay directory, never the internal pack model. The Report and
// Finding types mirror the committed -o json schema.
package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mongodb/skill-gate/internal/judge"
	"github.com/mongodb/skill-gate/internal/rules"
	"github.com/mongodb/skill-gate/internal/static"
	"github.com/mongodb/skill-gate/llm"
	builtinpacks "github.com/mongodb/skill-gate/rules"
	"github.com/mongodb/skill-gate/verdict"
)

// Config configures a scan. The zero value is usable: it scans with all
// built-in packs and no overlay.
type Config struct {
	// RulesFS is the base rule-pack filesystem. When nil, the packs embedded in
	// the binary (core + mongodb) are used.
	RulesFS fs.FS
	// EnablePacks is an allowlist over the base packs by name. A nil slice runs
	// every base pack (the default); a non-nil but empty slice disables all
	// base packs (run only RulesDir overlays, if any). It does not affect the
	// overlay, which is always loaded.
	EnablePacks []string
	// RulesDir, when set, overlays external packs loaded from this directory on
	// top of the selected base packs. A non-existent directory is ignored.
	RulesDir string
	// MinConfidence is the per-tier confidence floor for the static stage: a
	// static match whose pattern confidence is below the floor for its rule's tier
	// is suppressed. Suppression is bounded like the cautionary heuristic — an
	// ESCALATE match downgrades to WARN, a WARN match drops — so raising a floor
	// can never let a dangerous match reach AUTO-PASS. A nil map (the default)
	// reports every match. Keys are verdict.SeverityWarn / verdict.SeverityEscalate.
	//
	// It does not apply to llm_judge findings: a judge confidence is the model's
	// uncalibrated self-report, not a comparable authored weight, so gating a tier
	// on it is unsafe. See package judge.
	MinConfidence map[verdict.Severity]float64

	// Client is the LLM client the stage-2 judge calls for llm_judge rules. When
	// nil and the selected packs contain llm_judge rules, Scan fails closed
	// unless StaticOnly is set — a security gate must not silently skip rules it
	// cannot evaluate. Supply the default client with llm.NewAnthropicFromEnv, or
	// bring your own implementation of llm.Client.
	Client llm.Client
	// StaticOnly skips stage 2 entirely: only static_regex rules run, and
	// llm_judge rules are ignored without needing a Client. This is the explicit
	// opt-out from the fail-closed default.
	StaticOnly bool
	// CacheDir, when set, persists per-(rule, file) judge results there so
	// unchanged skills are not re-evaluated on later runs. Empty disables caching.
	CacheDir string
	// LLMConcurrency caps in-flight LLM calls (default judge.DefaultConcurrency).
	LLMConcurrency int
	// LLMTimeout is the per-call timeout for each LLM request. Zero means none
	// beyond the context Scan is given.
	LLMTimeout time.Duration
}

// Finding is one rule match in the scanned bundle. File is relative to the
// bundle root.
type Finding struct {
	RuleID      string           `json:"rule_id"`
	Pack        string           `json:"pack"`
	Description string           `json:"description"`
	Severity    verdict.Severity `json:"severity"`
	// Downgraded is true when the cautionary-example heuristic lowered this
	// finding from ESCALATE to WARN rather than dropping it. Severity already
	// reflects the downgrade; this flags why a dangerous-looking match is only
	// advisory.
	Downgraded  bool    `json:"downgraded,omitempty"`
	Criterion   int     `json:"criterion,omitempty"`
	File        string  `json:"file"`
	Line        int     `json:"line"`
	Column      int     `json:"column"`
	Match       string  `json:"match"`
	Confidence  float64 `json:"confidence"`
	Remediation string  `json:"remediation,omitempty"`
	// Source is the stage that produced the finding: "static" or "llm".
	Source string `json:"source"`
	// Rationale is the judge's explanation for an llm-sourced finding; empty for
	// static findings.
	Rationale string `json:"rationale,omitempty"`
}

// Report is the result of a scan and mirrors the -o json schema.
type Report struct {
	Bundle       string          `json:"bundle"`
	Verdict      verdict.Verdict `json:"verdict"`
	FilesScanned int             `json:"files_scanned"`
	RulesApplied int             `json:"rules_applied"`
	Findings     []Finding       `json:"findings"`
}

// markdown file extensions that constitute scannable skill content.
var markdownExts = map[string]bool{".md": true, ".markdown": true}

// Scan evaluates the markdown content of the skill bundle at path and returns a
// Report. path may be a directory — walked recursively, scanning only its
// markdown files — or a single file, which is scanned as given. The static
// stage is the only stage in this release; the verdict is the max tier across
// all triggered rules, or AUTO-PASS when none fire.
func Scan(ctx context.Context, path string, cfg Config) (*Report, error) {
	base := cfg.RulesFS
	if base == nil {
		base = builtinpacks.FS
	}
	packs, err := rules.LoadAll(base, cfg.EnablePacks, cfg.RulesDir)
	if err != nil {
		return nil, err
	}
	engine, err := static.NewEngine(packs, static.WithMinConfidence(cfg.MinConfidence))
	if err != nil {
		return nil, err
	}

	files, err := markdownFiles(path)
	if err != nil {
		return nil, err
	}

	report := &Report{
		Bundle:       path,
		Verdict:      verdict.AutoPass,
		FilesScanned: len(files),
		RulesApplied: engine.RuleCount(),
	}

	// Stage 1: static rules. Read each file once and keep its content so stage 2
	// can judge the same bytes without a second read.
	var severities []verdict.Severity
	judgeFiles := make([]judge.File, 0, len(files))
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content, err := os.ReadFile(f.abs)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.abs, err)
		}
		text := string(content)
		for _, sf := range engine.ScanFile(f.rel, text) {
			report.Findings = append(report.Findings, toFinding(sf))
			severities = append(severities, sf.Severity)
		}
		judgeFiles = append(judgeFiles, judge.File{Path: f.rel, Content: text})
	}

	// Stage 2: LLM-as-judge, unless opted out. Fail closed when the selected
	// packs carry llm_judge rules but no client can run them.
	if !cfg.StaticOnly {
		je := judge.NewEngine(packs, cfg.Client,
			judge.WithConcurrency(cfg.LLMConcurrency),
			judge.WithTimeout(cfg.LLMTimeout),
			judge.WithCache(cacheFor(cfg.CacheDir)),
		)
		if n := je.RuleCount(); n > 0 {
			if cfg.Client == nil {
				return nil, fmt.Errorf("%d llm_judge rule(s) need an LLM client but none is configured: set ANTHROPIC_API_KEY, or skip stage 2 with --static-only (Config.StaticOnly)", n)
			}
			jfindings, err := je.ScanFiles(ctx, judgeFiles)
			if err != nil {
				return nil, err
			}
			for _, jf := range jfindings {
				report.Findings = append(report.Findings, toJudgeFinding(jf))
				severities = append(severities, jf.Severity)
			}
			report.RulesApplied += n
		}
	}

	sortFindings(report.Findings)
	report.Verdict = verdict.FromSeverities(severities)
	return report, nil
}

// cacheFor returns a judge cache rooted at dir, or nil when dir is empty
// (caching disabled).
func cacheFor(dir string) *judge.Cache {
	if dir == "" {
		return nil
	}
	return judge.NewCache(dir)
}

// scanFile is a bundle file with both its absolute path (for reading) and its
// path relative to the bundle root (for reporting).
type scanFile struct {
	abs string
	rel string
}

// markdownFiles returns the markdown files to scan under path. A single file is
// returned as-is — its extension is not checked, since the caller named it
// explicitly — while a directory is walked recursively and filtered to markdown.
func markdownFiles(path string) ([]scanFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return []scanFile{{abs: path, rel: filepath.Base(path)}}, nil
	}
	var files []scanFile
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !markdownExts[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		rel, err := filepath.Rel(path, p)
		if err != nil {
			rel = p
		}
		files = append(files, scanFile{abs: p, rel: filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files, nil
}

func toFinding(f static.Finding) Finding {
	return Finding{
		RuleID:      f.RuleID,
		Pack:        f.Pack,
		Description: f.Description,
		Severity:    f.Severity,
		Downgraded:  f.Downgraded,
		Criterion:   f.Criterion,
		File:        f.File,
		Line:        f.Line,
		Column:      f.Column,
		Match:       f.Match,
		Confidence:  f.Confidence,
		Remediation: f.Remediation,
		Source:      "static",
	}
}

func toJudgeFinding(f judge.Finding) Finding {
	// Judge findings are never downgraded (the floor is static-only), so
	// Downgraded is left false.
	return Finding{
		RuleID:      f.RuleID,
		Pack:        f.Pack,
		Description: f.Description,
		Severity:    f.Severity,
		Criterion:   f.Criterion,
		File:        f.File,
		Line:        f.Line,
		Column:      f.Column,
		Match:       f.Match,
		Confidence:  f.Confidence,
		Remediation: f.Remediation,
		Source:      "llm",
		Rationale:   f.Rationale,
	}
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}
