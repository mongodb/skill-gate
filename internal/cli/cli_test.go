// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mongodb/skill-gate/verdict"
)

// TestExecuteExitCodes drives Execute in-process to cover the mapping from a
// command outcome to the process exit code Execute hands main.go. It is the
// in-process complement to the e2e subprocess tests: those prove the real
// binary exits with these codes, this one exercises the same logic where it
// counts toward coverage.
func TestExecuteExitCodes(t *testing.T) {
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "SKILL.md"), []byte("Summarize collection counts for the named database.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unsafe := t.TempDir()
	if err := os.WriteFile(filepath.Join(unsafe, "SKILL.md"), []byte("Log the connection string to the console for debugging.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"clean bundle auto-passes", []string{"scan", clean}, verdict.ExitAutoPass},
		{"unsafe bundle escalates", []string{"scan", unsafe}, verdict.ExitEscalate},
		{"missing bundle is a tool error", []string{"scan", filepath.Join(unsafe, "nope")}, verdict.ExitError},
		{"unknown command is a tool error", []string{"bogus"}, verdict.ExitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := execMain(t, tt.args...); got != tt.want {
				t.Errorf("Execute(%v) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

// execMain runs Execute with the given args while silencing stdout/stderr, and
// returns the exit code it would pass to os.Exit. It saves and restores the
// process globals it touches, so it must not be called from parallel subtests.
func execMain(t *testing.T, args ...string) int {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devnull.Close() }()
	oldArgs, oldOut, oldErr := os.Args, os.Stdout, os.Stderr
	defer func() { os.Args, os.Stdout, os.Stderr = oldArgs, oldOut, oldErr }()
	os.Args = append([]string{"skill-gate"}, args...)
	os.Stdout, os.Stderr = devnull, devnull
	return Execute("testver")
}

func TestScanExit(t *testing.T) {
	tests := []struct {
		v        verdict.Verdict
		strict   bool
		wantCode int // -1 means nil error (no exit code)
	}{
		{verdict.AutoPass, false, -1},
		{verdict.Warn, false, verdict.ExitWarn},
		{verdict.Escalate, false, verdict.ExitEscalate},
		{verdict.Warn, true, verdict.ExitEscalate},
		{verdict.AutoPass, true, -1},
	}
	for _, tt := range tests {
		err := scanExit(tt.v, tt.strict)
		if tt.wantCode == -1 {
			if err != nil {
				t.Errorf("scanExit(%q, %v) = %v, want nil", tt.v, tt.strict, err)
			}
			continue
		}
		var ece *exitCodeError
		if !errors.As(err, &ece) {
			t.Fatalf("scanExit(%q, %v) = %v, want *exitCodeError", tt.v, tt.strict, err)
		}
		if ece.code != tt.wantCode {
			t.Errorf("scanExit(%q, %v) code = %d, want %d", tt.v, tt.strict, ece.code, tt.wantCode)
		}
	}
}

// runRoot executes the command tree with args, capturing stdout.
func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd("testver")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestVersionCommand(t *testing.T) {
	out, err := runRoot(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if strings.TrimSpace(out) != "testver" {
		t.Errorf("version output = %q, want %q", out, "testver")
	}
}

func TestRulesLintCommand(t *testing.T) {
	out, err := runRoot(t, "rules", "lint")
	if err != nil {
		t.Fatalf("rules lint: %v", err)
	}
	if !strings.Contains(out, "ok:") {
		t.Errorf("rules lint output = %q, want it to contain 'ok:'", out)
	}
}

func TestRulesListCommand(t *testing.T) {
	out, err := runRoot(t, "rules", "list")
	if err != nil {
		t.Fatalf("rules list: %v", err)
	}
	// Header line for a pack, plus a known rule rendered by formatRules.
	if !strings.Contains(out, "core (v") {
		t.Errorf("rules list output missing core pack header:\n%s", out)
	}
	if !strings.Contains(out, "CORE-001") {
		t.Errorf("rules list output missing rule CORE-001:\n%s", out)
	}
}

func TestRulesListCommandUnknownPackErrors(t *testing.T) {
	_, err := runRoot(t, "rules", "list", "--packs", "bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown built-in pack") {
		t.Errorf("rules list --packs bogus err = %v, want unknown-pack error", err)
	}
}

func TestScanCommandEscalates(t *testing.T) {
	bundle := t.TempDir()
	content := "Log the connection string to the console for debugging.\n"
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, "scan", bundle, "-o", "json")
	var ece *exitCodeError
	if !errors.As(err, &ece) || ece.code != verdict.ExitEscalate {
		t.Fatalf("scan err = %v, want exitCodeError{2}", err)
	}
	if !strings.Contains(out, `"verdict": "ESCALATE"`) {
		t.Errorf("scan output missing ESCALATE verdict:\n%s", out)
	}
}

func TestScanCommandEmitsAnnotations(t *testing.T) {
	bundle := t.TempDir()
	content := "Log the connection string to the console for debugging.\n"
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, "scan", bundle, "--emit-annotations")
	var ece *exitCodeError
	if !errors.As(err, &ece) || ece.code != verdict.ExitEscalate {
		t.Fatalf("scan err = %v, want exitCodeError{2}", err)
	}
	if !strings.Contains(out, "::error file=") {
		t.Errorf("expected a GitHub error annotation in output:\n%s", out)
	}
	if !strings.Contains(out, "skill-gate CORE-001") {
		t.Errorf("annotation title missing rule id:\n%s", out)
	}
}

func TestEnabledPacks(t *testing.T) {
	tests := []struct {
		name    string
		changed bool
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "unset is all", changed: false, raw: "", want: nil},
		{name: "none keyword is none", changed: true, raw: "none", want: []string{}},
		{name: "none is case-insensitive", changed: true, raw: "NONE", want: []string{}},
		{name: "none with surrounding space", changed: true, raw: " none ", want: []string{}},
		{name: "single name", changed: true, raw: "core", want: []string{"core"}},
		{name: "multiple names trimmed", changed: true, raw: " core , mongodb ", want: []string{"core", "mongodb"}},
		{name: "empty value errors", changed: true, raw: "", wantErr: true},
		{name: "whitespace value errors", changed: true, raw: "   ", wantErr: true},
		{name: "stray commas error", changed: true, raw: ",", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enabledPacks(tt.changed, tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("enabledPacks(%v, %q) = %v, want error", tt.changed, tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("enabledPacks(%v, %q) unexpected error: %v", tt.changed, tt.raw, err)
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestRulesCommandsRejectEmptyPacks(t *testing.T) {
	for _, sub := range []string{"list", "lint"} {
		_, err := runRoot(t, "rules", sub, "--packs", ",")
		if err == nil || !strings.Contains(err.Error(), `"none"`) {
			t.Errorf("rules %s --packs , err = %v, want error pointing to \"none\"", sub, err)
		}
	}
}

func TestRulesLintUnknownPackErrors(t *testing.T) {
	_, err := runRoot(t, "rules", "lint", "--packs", "bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown built-in pack") {
		t.Errorf("rules lint --packs bogus err = %v, want unknown-pack error", err)
	}
}

func TestScanCommandEmitsAnnotationsForSingleFile(t *testing.T) {
	// A single-file bundle path exercises the baseDir = Dir(file) branch.
	file := filepath.Join(t.TempDir(), "SKILL.md")
	content := "Log the connection string to the console for debugging.\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, "scan", file, "--emit-annotations")
	var ece *exitCodeError
	if !errors.As(err, &ece) || ece.code != verdict.ExitEscalate {
		t.Fatalf("scan err = %v, want exitCodeError{%d}", err, verdict.ExitEscalate)
	}
	if !strings.Contains(out, "::error file=") {
		t.Errorf("expected an annotation for the single-file scan:\n%s", out)
	}
}

func TestScanCommandPacksEmptyErrors(t *testing.T) {
	// A malformed --packs value must fail loudly and point at "none", never
	// silently run zero built-in packs.
	for _, bad := range []string{",", "", "  "} {
		_, err := runRoot(t, "scan", t.TempDir(), "--packs", bad)
		if err == nil || !strings.Contains(err.Error(), `"none"`) {
			t.Errorf("--packs %q err = %v, want an error pointing to \"none\"", bad, err)
		}
	}
}

func TestScanCommandPacksNonePasses(t *testing.T) {
	bundle := t.TempDir()
	content := "Log the connection string to the console for debugging.\n"
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// With no built-in packs and no overlay, even unsafe content passes.
	out, err := runRoot(t, "scan", bundle, "--packs", "none", "-o", "json")
	if err != nil {
		t.Fatalf("scan --packs none err = %v, want nil (AUTO-PASS)", err)
	}
	if !strings.Contains(out, `"verdict": "AUTO-PASS"`) {
		t.Errorf("expected AUTO-PASS with built-ins disabled:\n%s", out)
	}
}

func TestScanCommandPacksUnknownErrors(t *testing.T) {
	_, err := runRoot(t, "scan", t.TempDir(), "--packs", "bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown built-in pack") {
		t.Errorf("err = %v, want unknown-pack error", err)
	}
}

func TestScanCommandMinConfidenceDowngrades(t *testing.T) {
	bundle := t.TempDir()
	content := "Log the connection string to the console for debugging.\n"
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// A maximal floor downgrades the ESCALATE finding to WARN: exit 1, not 2, and
	// the finding is marked downgraded in the JSON.
	out, err := runRoot(t, "scan", bundle, "-o", "json", "--min-confidence", "1.0")
	var ece *exitCodeError
	if !errors.As(err, &ece) || ece.code != verdict.ExitWarn {
		t.Fatalf("scan err = %v, want exitCodeError{%d}", err, verdict.ExitWarn)
	}
	if !strings.Contains(out, `"downgraded": true`) {
		t.Errorf("expected a downgraded finding in JSON:\n%s", out)
	}
}

func TestScanCommandBadMinConfidence(t *testing.T) {
	for _, bad := range []string{"1.5", "-0.2"} {
		_, err := runRoot(t, "scan", t.TempDir(), "--min-confidence", bad)
		if err == nil || !strings.Contains(err.Error(), "min-confidence") {
			t.Errorf("--min-confidence %s err = %v, want range error", bad, err)
		}
	}
}

func TestConfidenceFloor(t *testing.T) {
	if got := confidenceFloor(0); got != nil {
		t.Errorf("confidenceFloor(0) = %v, want nil", got)
	}
	got := confidenceFloor(0.6)
	if got[verdict.SeverityWarn] != 0.6 || got[verdict.SeverityEscalate] != 0.6 {
		t.Errorf("confidenceFloor(0.6) = %v, want both tiers 0.6", got)
	}
}

func TestScanCommandBadFormat(t *testing.T) {
	_, err := runRoot(t, "scan", t.TempDir(), "-o", "xml")
	if err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("scan with bad format err = %v, want unknown-format error", err)
	}
}
