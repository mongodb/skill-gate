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
