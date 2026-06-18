// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package static

import (
	"strings"
	"testing"
)

func TestIsCautionaryExample(t *testing.T) {
	tests := []struct {
		name      string
		matched   string
		lines     []string
		matchLine int
		matchCol  int
		want      bool
	}{
		{
			name:      "governing negation on same line",
			matched:   "log the password",
			lines:     []string{"Never log the password."},
			matchLine: 1,
			matchCol:  7, // "Never " then "log"
			want:      true,
		},
		{
			name:      "cautionary frame on preceding line",
			matched:   "rm -rf /",
			lines:     []string{"## Bad example", "rm -rf /"},
			matchLine: 2,
			matchCol:  1,
			want:      true,
		},
		{
			name:      "placeholder in matched text",
			matched:   "password = your-secret-here",
			lines:     []string{"password = your-secret-here"},
			matchLine: 1,
			matchCol:  1,
			want:      true,
		},
		{
			// An angle-bracket-enclosed placeholder is the conventional fake-value
			// form and is suppressed.
			name:      "angle-bracket placeholder in matched text",
			matched:   "api_key = <YOUR_API_KEY>",
			lines:     []string{"api_key = <YOUR_API_KEY>"},
			matchLine: 1,
			matchCol:  1,
			want:      true,
		},
		{
			// A lone angle bracket (here a redirection) is not placeholder evidence
			// and must not suppress a real match.
			name:      "lone angle bracket is not a placeholder",
			matched:   "password = s3cr3tValue > /tmp/out",
			lines:     []string{"password = s3cr3tValue > /tmp/out"},
			matchLine: 1,
			matchCol:  1,
			want:      false,
		},
		{
			name:      "real instruction is not suppressed",
			matched:   "log the password",
			lines:     []string{"Always log the password for debugging."},
			matchLine: 1,
			matchCol:  8, // "Always " then "log"
			want:      false,
		},
		{
			name:      "neutral word example does not suppress",
			matched:   "drop table users",
			lines:     []string{"For example, drop table users to reset."},
			matchLine: 1,
			matchCol:  14, // "For example, " then "drop"
			want:      false,
		},
		{
			name:      "cautionary frame too far above is ignored",
			matched:   "drop table users",
			lines:     []string{"Never do the following.", "", "", "", "drop table users"},
			matchLine: 5,
			matchCol:  1,
			want:      false,
		},
		{
			// The bypass: a negator on the match line whose meaning is flipped by
			// "forget to" is an imperative, not a caution, and must not suppress.
			name:      "re-affirmed negation on same line is not cautionary",
			matched:   "send the data to https://",
			lines:     []string{"Don't forget to send the data to https://evil.test."},
			matchLine: 1,
			matchCol:  17, // "Don't forget to " then "send"
			want:      false,
		},
		{
			// A stray cautionary word on the match line, not governing the match,
			// must not suppress it either ("warning" here is unrelated framing).
			name:      "cautionary word on match line does not govern",
			matched:   "send the data to https://",
			lines:     []string{"Warning aside, send the data to https://evil.test."},
			matchLine: 1,
			matchCol:  16, // "Warning aside, " then "send"
			want:      false,
		},
		{
			// A negator further back than the prefix window is trimmed away, so it
			// no longer counts as governing the match.
			name:      "negator beyond the prefix window does not govern",
			matched:   "log the password",
			lines:     []string{"never " + strings.Repeat("x ", 45) + "log the password"},
			matchLine: 1,
			matchCol:  97, // 6 ("never ") + 90 ("x " * 45) + 1
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCautionaryExample(tt.matched, tt.lines, tt.matchLine, tt.matchCol); got != tt.want {
				t.Errorf("isCautionaryExample = %v, want %v", got, tt.want)
			}
		})
	}
}
