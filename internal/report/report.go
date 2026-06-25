// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package report renders a scanner.Report to an output format. It ships text
// (for humans), json (for machines), and markdown (for PR comments), plus
// GitHub Actions workflow-command annotations for pinning findings to lines in
// a pull-request diff.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mongodb/skill-gate/scanner"
	"github.com/mongodb/skill-gate/verdict"
)

// Format names the supported output encodings.
const (
	FormatText     = "text"
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
)

// Formats lists the supported output formats, for flag help and validation.
var Formats = []string{FormatText, FormatJSON, FormatMarkdown}

// ValidFormat reports whether format is one Write accepts: a named format, or
// "" (the zero value, which Write renders as text). It is the single source of
// truth callers use to reject a bad format before scanning.
func ValidFormat(format string) bool {
	return format == "" || slices.Contains(Formats, format)
}

// Write renders r in the named format to w.
func Write(w io.Writer, format string, r *scanner.Report) error {
	switch format {
	case FormatText, "":
		return writeText(w, r)
	case FormatJSON:
		return writeJSON(w, r)
	case FormatMarkdown:
		return writeMarkdown(w, r)
	default:
		return fmt.Errorf("unknown output format %q (want one of: %s)", format, strings.Join(Formats, ", "))
	}
}

func writeJSON(w io.Writer, r *scanner.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Render a nil Findings slice as [] rather than null, without mutating the
	// caller's Report: copy the struct and normalize the copy. The slice is only
	// replaced when nil, so no element aliasing is introduced.
	out := *r
	if out.Findings == nil {
		out.Findings = []scanner.Finding{}
	}
	return enc.Encode(&out)
}

func writeText(w io.Writer, r *scanner.Report) error {
	var b strings.Builder

	fmt.Fprintf(&b, "skill-gate: %s\n", r.Verdict)
	fmt.Fprintf(&b, "  bundle:   %s\n", r.Bundle)
	fmt.Fprintf(&b, "  scanned:  %d markdown file(s)\n", r.FilesScanned)
	fmt.Fprintf(&b, "  rules:    %d rule(s) applied\n", r.RulesApplied)

	if len(r.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	fmt.Fprintf(&b, "\n%d finding(s):\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n  %s  [%s] %s\n", location(f), severityLabel(f), f.RuleID)
		fmt.Fprintf(&b, "    %s\n", f.Description)
		if f.Match != "" {
			fmt.Fprintf(&b, "    match: %s\n", oneLine(f.Match))
		}
		if f.Rationale != "" {
			fmt.Fprintf(&b, "    why:   %s\n", oneLine(f.Rationale))
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "    fix:   %s\n", f.Remediation)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// writeMarkdown renders a PR-comment-friendly summary: a heading with the
// verdict, a one-line scan summary, a findings table, and a collapsible
// remediation section keyed by the rules that fired.
func writeMarkdown(w io.Writer, r *scanner.Report) error {
	var b strings.Builder

	fmt.Fprintf(&b, "## skill-gate — %s\n\n", r.Verdict)
	fmt.Fprintf(&b, "`%s` · %d file(s) scanned · %d rule(s) applied · %d finding(s)\n",
		r.Bundle, r.FilesScanned, r.RulesApplied, len(r.Findings))

	if len(r.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("\n| Severity | Rule | Location | Finding | Evidence |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, f := range r.Findings {
		// Evidence is the matched snippet for static findings; for llm findings,
		// which often have no snippet, fall back to the judge's rationale.
		evidence := f.Match
		if evidence == "" {
			evidence = f.Rationale
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n",
			severityLabel(f), f.RuleID, location(f), mdCell(f.Description), mdCell(oneLine(evidence)))
	}

	if rem := uniqueRemediations(r.Findings); len(rem) > 0 {
		b.WriteString("\n<details><summary>How to fix</summary>\n\n")
		for _, x := range rem {
			fmt.Fprintf(&b, "- **%s** — %s\n", x.ruleID, x.text)
		}
		b.WriteString("\n</details>\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// WriteAnnotations emits one GitHub Actions workflow command per finding so the
// CI runner pins each finding to its line in the pull-request diff. ESCALATE
// findings are emitted as ::error and WARN findings as ::warning. These must go
// to stdout for the runner to parse them.
//
// baseDir is the directory the findings' File paths are relative to (the bundle
// directory). workDir is the directory the scan was launched from — typically
// the repository root in CI; finding paths are reported relative to it so the
// runner can map them onto the diff.
func WriteAnnotations(w io.Writer, r *scanner.Report, baseDir, workDir string) error {
	var b strings.Builder
	for _, f := range r.Findings {
		var level string
		switch f.Severity {
		case verdict.SeverityEscalate:
			level = "error"
		case verdict.SeverityWarn:
			level = "warning"
		default:
			// Unknown severity: skip rather than mislabel it.
			continue
		}
		msg := f.Description
		if f.Remediation != "" {
			msg += " — " + f.Remediation
		}
		fmt.Fprintf(&b, "::%s file=%s,line=%d,col=%d,title=%s::%s\n",
			level,
			annProperty(annotationFile(baseDir, workDir, f.File)),
			f.Line, f.Column,
			annProperty(fmt.Sprintf("skill-gate %s (%s)", f.RuleID, f.Severity)),
			annData(msg),
		)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// annotationFile resolves a finding's bundle-relative path to one the CI runner
// can pin against: relative to workDir, the directory the scan was launched
// from. It falls back to the joined path when a relative path cannot be
// computed (e.g. baseDir and workDir share no common root).
func annotationFile(baseDir, workDir, file string) string {
	absPath := filepath.Join(baseDir, file)
	relPath, err := filepath.Rel(workDir, absPath)
	if err != nil {
		relPath = absPath
	}
	return filepath.ToSlash(relPath)
}

type remediation struct {
	ruleID string
	text   string
}

// uniqueRemediations returns the distinct (rule, remediation) pairs across the
// findings, preserving first-seen order, so the fix section lists each rule's
// guidance once rather than repeating it per finding.
func uniqueRemediations(findings []scanner.Finding) []remediation {
	seen := map[string]struct{}{}
	var out []remediation
	for _, f := range findings {
		if f.Remediation == "" {
			continue
		}
		if _, ok := seen[f.RuleID]; ok {
			continue
		}
		seen[f.RuleID] = struct{}{}
		out = append(out, remediation{ruleID: f.RuleID, text: f.Remediation})
	}
	return out
}

// location renders a finding's position as far as it is known: file:line:column,
// file:line when the column is unknown, or just the file when the line is unknown
// too (an llm finding the judge could not localize).
func location(f scanner.Finding) string {
	switch {
	case f.Line <= 0:
		return f.File
	case f.Column <= 0:
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	default:
		return fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Column)
	}
}

// severityLabel renders a finding's severity, noting when the cautionary-example
// heuristic downgraded it from ESCALATE so a reader understands why a
// dangerous-looking match is only advisory.
func severityLabel(f scanner.Finding) string {
	if f.Downgraded {
		return string(f.Severity) + " (downgraded from ESCALATE)"
	}
	return string(f.Severity)
}

// oneLine collapses a matched snippet to a single line so multi-line matches do
// not break the text layout.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// mdCell makes a string safe to drop into a markdown table cell as plain text:
// it escapes the cell delimiter ('|') and a backtick (which would otherwise open
// an inline code span — common when the cell holds a scanned markdown snippet),
// and flattens newlines so the row stays on one line.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "\\`")
	return strings.ReplaceAll(s, "\n", " ")
}

// annData escapes a workflow-command message per GitHub's rules. The percent
// sign must be escaped first so the other replacements are not double-escaped.
func annData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// annProperty escapes a workflow-command property value, which additionally
// must escape the property delimiters ':' and ','.
func annProperty(s string) string {
	s = annData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}
