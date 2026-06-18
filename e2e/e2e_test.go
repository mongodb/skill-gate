// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package e2e drives the compiled skill-gate binary against the example skill
// bundles in ../testdata, exercising the whole tool end to end: argument
// parsing, the scan pipeline, output rendering, and the process exit code. Unit
// tests cover the packages in isolation; these tests cover the wiring in
// cmd/skill-gate and internal/cli that only runs when the real binary does.
package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mongodb/skill-gate/verdict"
)

// binPath is the freshly built skill-gate binary, set by TestMain.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "skill-gate-e2e")
	if err != nil {
		panic("mkdtemp: " + err.Error())
	}
	// go build -o does not append .exe itself, so the binary is unrunnable on
	// Windows without it.
	name := "skill-gate"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath = filepath.Join(dir, name)
	// Build from the repo root (one level up from this package).
	build := exec.Command("go", "build", "-o", binPath, "./cmd/skill-gate")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		panic("build skill-gate: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// run invokes the built binary with args, returning combined stdout+stderr and
// the process exit code. A non-zero exit surfaces as *exec.ExitError, but the
// code is read from ProcessState either way; any other error (e.g. the binary
// failing to start) is fatal to the test.
func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	out, err := cmd.CombinedOutput()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatalf("run %v: %v", args, err)
	}
	return string(out), cmd.ProcessState.ExitCode()
}

func bundle(name string) string { return filepath.Join("..", "testdata", name) }

func TestScanVerdicts(t *testing.T) {
	tests := []struct {
		name        string
		dir         string
		wantVerdict string
		wantExit    int
		wantRules   []string // rule ids expected in the JSON output
	}{
		{"safe bundle auto-passes", "safe-reporting-skill", "AUTO-PASS", verdict.ExitAutoPass, nil},
		{"hardcoded secret warns", "warn-hardcoded-secret-skill", "WARN", verdict.ExitWarn, []string{"CORE-004"}},
		{"unsafe backup escalates", "unsafe-backup-skill", "ESCALATE", verdict.ExitEscalate, []string{"CORE-001", "CORE-003", "MDB-003"}},
		{"dangerous migration escalates", "dangerous-migration-skill", "ESCALATE", verdict.ExitEscalate, []string{"CORE-002", "MDB-001", "MDB-002", "MDB-004", "MDB-005"}},
		{"cautionary docs downgrade to warn", "cautionary-docs-skill", "WARN", verdict.ExitWarn, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, code := run(t, "scan", bundle(tt.dir), "-o", "json")
			if code != tt.wantExit {
				t.Errorf("exit code = %d, want %d\n%s", code, tt.wantExit, out)
			}
			if !strings.Contains(out, `"verdict": "`+tt.wantVerdict+`"`) {
				t.Errorf("output missing verdict %q:\n%s", tt.wantVerdict, out)
			}
			for _, id := range tt.wantRules {
				if !strings.Contains(out, `"rule_id": "`+id+`"`) {
					t.Errorf("output missing rule %q:\n%s", id, out)
				}
			}
		})
	}
}

// TestNonMarkdownIgnored confirms the python script in the unsafe bundle does
// not contribute findings even though it contains a literal secret.
func TestNonMarkdownIgnored(t *testing.T) {
	out, _ := run(t, "scan", bundle("unsafe-backup-skill"), "-o", "json")
	if strings.Contains(out, "backup.py") {
		t.Errorf("non-markdown script was scanned:\n%s", out)
	}
	if !strings.Contains(out, `"files_scanned": 2`) {
		t.Errorf("expected 2 markdown files scanned (script excluded):\n%s", out)
	}
}

// TestCautionaryDowngradeVisibleInJSON confirms the downgrade flag is wired all
// the way through the binary's JSON output, so a cautionary bundle reports a
// downgraded WARN rather than a silent AUTO-PASS.
func TestCautionaryDowngradeVisibleInJSON(t *testing.T) {
	out, code := run(t, "scan", bundle("cautionary-docs-skill"), "-o", "json")
	if code != verdict.ExitWarn {
		t.Errorf("exit = %d, want %d\n%s", code, verdict.ExitWarn, out)
	}
	if !strings.Contains(out, `"downgraded": true`) {
		t.Errorf("expected a downgraded finding in JSON output:\n%s", out)
	}
}

// TestBypassAttemptEscalates proves the cautionary heuristic is not bypassable
// through the binary: a disguised instruction ("Don't forget to send …") must
// escalate at full severity — never suppressed, never downgraded.
func TestBypassAttemptEscalates(t *testing.T) {
	out, code := run(t, "scan", bundle("bypass-attempt-skill"), "-o", "json")
	if code != verdict.ExitEscalate {
		t.Fatalf("exit = %d, want %d\n%s", code, verdict.ExitEscalate, out)
	}
	if !strings.Contains(out, `"verdict": "ESCALATE"`) {
		t.Errorf("output missing ESCALATE verdict:\n%s", out)
	}
	if !strings.Contains(out, `"rule_id": "CORE-003"`) {
		t.Errorf("expected CORE-003 to fire:\n%s", out)
	}
	if strings.Contains(out, `"downgraded": true`) {
		t.Errorf("disguised instruction was wrongly downgraded:\n%s", out)
	}
}

// TestMinConfidenceFloorViaBinary exercises the confidence floor end to end: a
// maximal floor downgrades the unsafe bundle's ESCALATE findings to WARN (exit 1,
// downgraded flag set), and an out-of-range floor is a tool error (exit 3).
func TestMinConfidenceFloorViaBinary(t *testing.T) {
	out, code := run(t, "scan", bundle("unsafe-backup-skill"), "-o", "json", "--min-confidence", "1.0")
	if code != verdict.ExitWarn {
		t.Fatalf("exit = %d, want %d\n%s", code, verdict.ExitWarn, out)
	}
	if !strings.Contains(out, `"verdict": "WARN"`) || !strings.Contains(out, `"downgraded": true`) {
		t.Errorf("expected a downgraded WARN verdict under a maximal floor:\n%s", out)
	}

	bad, code := run(t, "scan", bundle("unsafe-backup-skill"), "--min-confidence", "2")
	if code != verdict.ExitError {
		t.Errorf("out-of-range floor exit = %d, want %d\n%s", code, verdict.ExitError, bad)
	}
	if !strings.Contains(bad, "min-confidence") {
		t.Errorf("expected a min-confidence diagnostic on stderr:\n%s", bad)
	}
}

// TestStrictPromotesWarn confirms --strict turns a WARN bundle into a blocking
// (ESCALATE-level) exit code while leaving the verdict itself WARN.
func TestStrictPromotesWarn(t *testing.T) {
	out, code := run(t, "scan", bundle("warn-hardcoded-secret-skill"), "-o", "json", "--strict")
	if code != verdict.ExitEscalate {
		t.Errorf("--strict WARN exit = %d, want %d\n%s", code, verdict.ExitEscalate, out)
	}
	if !strings.Contains(out, `"verdict": "WARN"`) {
		t.Errorf("--strict should not change the reported verdict:\n%s", out)
	}
}

// TestEmitAnnotations confirms the GitHub Actions workflow commands are written
// for an escalating bundle.
func TestEmitAnnotations(t *testing.T) {
	out, code := run(t, "scan", bundle("unsafe-backup-skill"), "--emit-annotations")
	if code != verdict.ExitEscalate {
		t.Fatalf("exit = %d, want %d\n%s", code, verdict.ExitEscalate, out)
	}
	if !strings.Contains(out, "::error file=") {
		t.Errorf("expected a GitHub error annotation:\n%s", out)
	}
	if !strings.Contains(out, "skill-gate CORE-001") {
		t.Errorf("annotation missing rule id:\n%s", out)
	}
}

// TestMissingBundleFailsToRun confirms a tool error (not a scan verdict) exits
// with ExitError and prints a diagnostic to stderr.
func TestMissingBundleFailsToRun(t *testing.T) {
	out, code := run(t, "scan", bundle("does-not-exist"))
	if code != verdict.ExitError {
		t.Errorf("missing bundle exit = %d, want %d\n%s", code, verdict.ExitError, out)
	}
	if !strings.Contains(out, "skill-gate:") {
		t.Errorf("expected a 'skill-gate:' diagnostic on stderr:\n%s", out)
	}
}

// TestSingleFileScan confirms a bundle path pointing at a single markdown file
// is scanned directly.
func TestSingleFileScan(t *testing.T) {
	out, code := run(t, "scan", bundle("safe-reporting-skill/SKILL.md"), "-o", "json")
	if code != verdict.ExitAutoPass {
		t.Errorf("single-file scan exit = %d, want %d\n%s", code, verdict.ExitAutoPass, out)
	}
	if !strings.Contains(out, `"files_scanned": 1`) {
		t.Errorf("expected exactly 1 file scanned:\n%s", out)
	}
}
