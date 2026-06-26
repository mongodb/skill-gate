// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package verdict

import "testing"

func TestFromSeverities(t *testing.T) {
	tests := []struct {
		name string
		in   []Severity
		want Verdict
	}{
		{"none fires is auto-pass", nil, AutoPass},
		{"only warn", []Severity{SeverityWarn}, Warn},
		{"only escalate", []Severity{SeverityEscalate}, Escalate},
		{"escalate wins over warn", []Severity{SeverityWarn, SeverityEscalate, SeverityWarn}, Escalate},
		{"multiple warns stay warn", []Severity{SeverityWarn, SeverityWarn}, Warn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromSeverities(tt.in); got != tt.want {
				t.Errorf("FromSeverities(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestVerdictExitCode(t *testing.T) {
	tests := []struct {
		v    Verdict
		want int
	}{
		{AutoPass, ExitAutoPass},
		{Warn, ExitWarn},
		{Escalate, ExitEscalate},
		// An unrecognized verdict must fail closed (ExitError), never exit 0.
		{Verdict("bogus"), ExitError},
		{Verdict(""), ExitError},
	}
	for _, tt := range tests {
		if got := tt.v.ExitCode(); got != tt.want {
			t.Errorf("%q.ExitCode() = %d, want %d", tt.v, got, tt.want)
		}
	}
}

func TestSeverityValid(t *testing.T) {
	for _, s := range []Severity{SeverityWarn, SeverityEscalate} {
		if !s.Valid() {
			t.Errorf("%q.Valid() = false, want true", s)
		}
	}
	for _, s := range []Severity{"", "INFO", "warn", "critical"} {
		if Severity(s).Valid() {
			t.Errorf("%q.Valid() = true, want false", s)
		}
	}
}

func TestBound(t *testing.T) {
	tests := []struct {
		name       string
		declared   Severity
		suppressed bool
		wantTier   Severity
		wantDown   bool
		wantDrop   bool
	}{
		{"not suppressed passes through (escalate)", SeverityEscalate, false, SeverityEscalate, false, false},
		{"not suppressed passes through (warn)", SeverityWarn, false, SeverityWarn, false, false},
		{"suppressed escalate downgrades to warn", SeverityEscalate, true, SeverityWarn, true, false},
		{"suppressed warn drops", SeverityWarn, true, SeverityWarn, false, true},
		// Fail-safe: an unexpected/unknown suppressed tier is kept at its declared
		// level — never downgraded and never silently dropped.
		{"suppressed unknown tier is kept", Severity("INFO"), true, Severity("INFO"), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier, down, drop := Bound(tt.declared, tt.suppressed)
			if tier != tt.wantTier || down != tt.wantDown || drop != tt.wantDrop {
				t.Errorf("Bound(%q, %v) = (%q, %v, %v), want (%q, %v, %v)",
					tt.declared, tt.suppressed, tier, down, drop, tt.wantTier, tt.wantDown, tt.wantDrop)
			}
		})
	}
}
