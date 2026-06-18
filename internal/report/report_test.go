// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mongodb/skill-gate/internal/report"
	"github.com/mongodb/skill-gate/scanner"
	"github.com/mongodb/skill-gate/verdict"
)

func sampleReport() *scanner.Report {
	return &scanner.Report{
		Bundle:       "my-skill",
		Verdict:      verdict.Escalate,
		FilesScanned: 1,
		RulesApplied: 9,
		Findings: []scanner.Finding{{
			RuleID:      "CORE-001",
			Pack:        "core",
			Description: "logs credentials",
			Severity:    verdict.SeverityEscalate,
			Criterion:   1,
			File:        "SKILL.md",
			Line:        3,
			Column:      1,
			Match:       "log the password",
			Confidence:  0.8,
			Remediation: "do not log secrets",
		}},
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatText, sampleReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ESCALATE", "CORE-001", "SKILL.md:3:1", "logs credentials", "do not log secrets"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
}

func TestWriteDowngradedLabel(t *testing.T) {
	rep := sampleReport()
	rep.Verdict = verdict.Warn
	rep.Findings[0].Severity = verdict.SeverityWarn
	rep.Findings[0].Downgraded = true

	var text bytes.Buffer
	if err := report.Write(&text, report.FormatText, rep); err != nil {
		t.Fatalf("Write text: %v", err)
	}
	if !strings.Contains(text.String(), "WARN (downgraded from ESCALATE)") {
		t.Errorf("text output missing downgrade note:\n%s", text.String())
	}

	var md bytes.Buffer
	if err := report.Write(&md, report.FormatMarkdown, rep); err != nil {
		t.Fatalf("Write markdown: %v", err)
	}
	if !strings.Contains(md.String(), "WARN (downgraded from ESCALATE)") {
		t.Errorf("markdown output missing downgrade note:\n%s", md.String())
	}
}

func TestWriteTextNoFindings(t *testing.T) {
	var buf bytes.Buffer
	rep := &scanner.Report{Bundle: "b", Verdict: verdict.AutoPass}
	if err := report.Write(&buf, report.FormatText, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("expected 'No findings.'\n%s", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatJSON, sampleReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var got scanner.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got.Verdict != verdict.Escalate || len(got.Findings) != 1 || got.Findings[0].RuleID != "CORE-001" {
		t.Errorf("round-tripped report mismatch: %+v", got)
	}
}

func TestWriteJSONEmptyFindingsIsArray(t *testing.T) {
	var buf bytes.Buffer
	rep := &scanner.Report{Bundle: "b", Verdict: verdict.AutoPass}
	if err := report.Write(&buf, report.FormatJSON, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("empty findings should encode as [], got\n%s", buf.String())
	}
}

func TestWriteJSONDoesNotMutateInput(t *testing.T) {
	rep := &scanner.Report{Bundle: "b", Verdict: verdict.AutoPass} // Findings is nil
	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatJSON, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rep.Findings != nil {
		t.Errorf("writeJSON mutated the caller's Report.Findings to %v, want it left nil", rep.Findings)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("nil findings should still encode as []:\n%s", buf.String())
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	if err := report.Write(&bytes.Buffer{}, "yaml", sampleReport()); err == nil {
		t.Error("expected error for unknown format, got nil")
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatMarkdown, sampleReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"## skill-gate — ESCALATE",
		"| Severity | Rule | Location | Finding | Match |",
		"| ESCALATE | CORE-001 | `SKILL.md:3:1` |",
		"<details><summary>How to fix</summary>",
		"do not log secrets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q\n%s", want, out)
		}
	}
}

func TestWriteMarkdownNoFindings(t *testing.T) {
	var buf bytes.Buffer
	rep := &scanner.Report{Bundle: "b", Verdict: verdict.AutoPass}
	if err := report.Write(&buf, report.FormatMarkdown, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "## skill-gate — AUTO-PASS") || !strings.Contains(out, "No findings.") {
		t.Errorf("unexpected no-findings markdown:\n%s", out)
	}
}

func TestWriteMarkdownEscapesPipe(t *testing.T) {
	rep := sampleReport()
	rep.Findings[0].Match = "a | b"
	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatMarkdown, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), `a \| b`) {
		t.Errorf("pipe in match cell was not escaped:\n%s", buf.String())
	}
}

func TestWriteAnnotations(t *testing.T) {
	rep := &scanner.Report{
		Bundle: "my-skill",
		Findings: []scanner.Finding{
			{RuleID: "CORE-001", Severity: verdict.SeverityEscalate, File: "SKILL.md", Line: 3, Column: 1, Description: "blocks at 50% threshold"},
			{RuleID: "CORE-005", Severity: verdict.SeverityWarn, File: "ref.md", Line: 7, Column: 4, Description: "line one\nline two"},
		},
	}
	var buf bytes.Buffer
	if err := report.WriteAnnotations(&buf, rep, "my-skill", "."); err != nil {
		t.Fatalf("WriteAnnotations: %v", err)
	}
	out := buf.String()
	tests := []string{
		"::error file=my-skill/SKILL.md,line=3,col=1,title=skill-gate CORE-001 (ESCALATE)::blocks at 50%25 threshold",
		"::warning file=my-skill/ref.md,line=7,col=4,title=skill-gate CORE-005 (WARN)::line one%0Aline two",
	}
	for _, want := range tests {
		if !strings.Contains(out, want) {
			t.Errorf("annotations missing line:\n  want: %s\n  got:\n%s", want, out)
		}
	}
}

func TestWriteAnnotationsAbsolutePathBecomesWorkDirRelative(t *testing.T) {
	// An absolute bundle path must be reported relative to workDir so GitHub can
	// map the annotation onto the diff.
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(workDir, "path", "to", "skill")
	rep := &scanner.Report{
		Findings: []scanner.Finding{{RuleID: "R", Severity: verdict.SeverityWarn, File: "SKILL.md", Line: 1, Column: 1, Description: "d"}},
	}
	var buf bytes.Buffer
	if err := report.WriteAnnotations(&buf, rep, baseDir, workDir); err != nil {
		t.Fatalf("WriteAnnotations: %v", err)
	}
	if !strings.Contains(buf.String(), "file=path/to/skill/SKILL.md,") {
		t.Errorf("absolute path not made workDir-relative:\n%s", buf.String())
	}
}

func TestWriteAnnotationsIncludesRemediation(t *testing.T) {
	rep := &scanner.Report{
		Findings: []scanner.Finding{{
			RuleID: "CORE-001", Severity: verdict.SeverityEscalate,
			File: "SKILL.md", Line: 3, Column: 1,
			Description: "logs credentials", Remediation: "read it from the environment",
		}},
	}
	var buf bytes.Buffer
	if err := report.WriteAnnotations(&buf, rep, ".", "."); err != nil {
		t.Fatalf("WriteAnnotations: %v", err)
	}
	if !strings.Contains(buf.String(), "logs credentials — read it from the environment") {
		t.Errorf("annotation message missing appended remediation:\n%s", buf.String())
	}
}

func TestWriteAnnotationsRelFallback(t *testing.T) {
	// When the path cannot be made relative to workDir (an absolute bundle path
	// against a relative workDir), annotationFile falls back to the joined path
	// rather than erroring.
	rep := &scanner.Report{
		Findings: []scanner.Finding{{RuleID: "R", Severity: verdict.SeverityWarn, File: "SKILL.md", Line: 1, Column: 1, Description: "d"}},
	}
	var buf bytes.Buffer
	if err := report.WriteAnnotations(&buf, rep, "/abs/bundle", "relative-workdir"); err != nil {
		t.Fatalf("WriteAnnotations: %v", err)
	}
	if !strings.Contains(buf.String(), "file=/abs/bundle/SKILL.md,") {
		t.Errorf("expected fallback to joined absolute path:\n%s", buf.String())
	}
}

func TestWriteMarkdownDedupesRemediations(t *testing.T) {
	rep := &scanner.Report{
		Bundle:  "b",
		Verdict: verdict.Escalate,
		Findings: []scanner.Finding{
			{RuleID: "R1", Severity: verdict.SeverityEscalate, File: "a.md", Line: 1, Column: 1, Description: "first", Remediation: "fix R1"},
			{RuleID: "R1", Severity: verdict.SeverityEscalate, File: "a.md", Line: 9, Column: 1, Description: "again", Remediation: "fix R1"},
			{RuleID: "R2", Severity: verdict.SeverityWarn, File: "a.md", Line: 5, Column: 1, Description: "no fix", Remediation: ""},
		},
	}
	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatMarkdown, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	// R1's guidance appears exactly once despite two findings; R2 has no
	// remediation and contributes no bullet.
	if got := strings.Count(out, "**R1** — fix R1"); got != 1 {
		t.Errorf("R1 remediation listed %d time(s), want 1:\n%s", got, out)
	}
	if strings.Contains(out, "**R2**") {
		t.Errorf("R2 has no remediation and should not appear in fix list:\n%s", out)
	}
}

func TestWriteAnnotationsSkipsUnknownSeverity(t *testing.T) {
	rep := &scanner.Report{
		Findings: []scanner.Finding{{RuleID: "R", Severity: "INFO", File: "SKILL.md", Line: 1, Column: 1, Description: "d"}},
	}
	var buf bytes.Buffer
	if err := report.WriteAnnotations(&buf, rep, ".", "."); err != nil {
		t.Fatalf("WriteAnnotations: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no annotation for unknown severity, got:\n%s", buf.String())
	}
}
