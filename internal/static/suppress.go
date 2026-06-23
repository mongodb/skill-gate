// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package static

import (
	"regexp"
	"strings"
)

// cautionaryIndicators frame a *preceding* line as introducing a negative
// example ("Bad example:", "Anti-pattern:", "❌ Don't:"). They are matched only
// against lines strictly above the match, never the match line itself: a
// cautionary word sitting on the same line as an imperative ("Don't forget to
// send the data …") does not make that imperative safe. Same-line negation is
// handled with the tighter hasGoverningNegation check instead.
var cautionaryIndicators = []string{
	"don't", "do not", "never", "avoid", "instead of", "rather than",
	"anti-pattern", "antipattern", "bad example", "incorrect", "wrong:",
	"you should not", "must not", "not recommended", "discouraged",
	"counterexample", "what not to do", "warning:", "caution:",
	"❌", "🚫",
}

// negators mark the matched construct as a cautionary example when one of them
// governs it on the match line ("never log the password"). This list is keyed to
// negation specifically, not to neutral framing words, so an imperative that
// merely sits near "example" is still reported.
var negators = []string{
	"don't", "do not", "never", "avoid", "must not", "should not",
	"cannot", "can not", "won't", "instead of", "rather than",
	"not recommended", "discouraged",
}

// reaffirmers are verbs that flip a negation back into an imperative: "don't
// forget to send …" and "don't hesitate to log …" instruct the agent to send
// and to log, not to refrain. When one appears between the governing negator and
// the match, the negation does not govern the match and we must not treat it as
// cautionary. This is what closes the "Don't forget to …" bypass.
var reaffirmers = []string{
	"forget to", "hesitate to", "fail to", "neglect to",
	"be afraid to", "afraid to", "worry about",
}

// placeholderMarkers identify a matched secret that is obviously fake. They are
// only consulted against the matched text itself (not its surroundings), so
// they suppress sample credentials without hiding a real-looking one nearby.
var placeholderMarkers = []string{
	"your_", "your-", "example", "placeholder", "changeme", "change_me",
	"change-me", "redacted", "dummy", "sample", "fake", "xxxx", "abc123",
	"todo", "...",
}

// angleBracketPlaceholder matches an angle-bracket-enclosed placeholder token
// such as <your-api-key> or <API_KEY>. This is deliberately tighter than
// treating any stray "<" or ">" as a placeholder: a lone bracket — a shell
// redirection (`>> /tmp/out`) or a comparison — no longer suppresses a match,
// while the conventional <...> placeholder form still does. Like
// placeholderMarkers, it is consulted only against the matched text itself.
var angleBracketPlaceholder = regexp.MustCompile(`<[^<>\n]{1,40}>`)

// cautionaryWindow is how many lines *above* the match to inspect for cautionary
// framing. Cautionary lead-ins ("Never run the following:") precede the
// offending line; the line after the match is deliberately not consulted, since
// trailing framing is the easiest to abuse and the least common in real docs.
const cautionaryWindow = 2

// prefixWindow bounds how much of the match line, working back from the match,
// is examined for a governing negator — roughly a clause. It keeps a negator at
// the far start of a long line from being read as governing a match at its end.
const prefixWindow = 80

// isCautionaryExample reports whether a match should be treated as a cautionary
// documentation example rather than a real instruction. matched is the exact
// text the pattern matched; lines is the file split on "\n"; matchLine is the
// 1-based line and matchCol the 1-based *byte* column the match starts at (byte,
// not rune, because the prefix is sliced out of the line by byte offset).
//
// A true result only *downgrades* an ESCALATE finding to WARN — it never drops
// it (see Engine.ScanFile). The heuristic therefore cannot turn a dangerous
// match into AUTO-PASS even when it is fooled; the worst case is a WARN that a
// human reviews.
func isCautionaryExample(matched string, lines []string, matchLine, matchCol int) bool {
	if hasPlaceholderMarker(matched) {
		return true
	}
	if hasGoverningNegation(matchLinePrefix(lines, matchLine, matchCol)) {
		return true
	}
	return hasPrecedingFraming(lines, matchLine)
}

func hasPlaceholderMarker(matched string) bool {
	lower := strings.ToLower(matched)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return angleBracketPlaceholder.MatchString(matched)
}

// matchLinePrefix returns the lower-cased text on the match line that precedes
// the match, trimmed to the prefixWindow bytes nearest the match. matchCol is a
// 1-based byte column.
func matchLinePrefix(lines []string, matchLine, matchCol int) string {
	if matchLine < 1 || matchLine > len(lines) {
		return ""
	}
	line := lines[matchLine-1]
	end := matchCol - 1
	end = max(end, 0)
	end = min(end, len(line))
	prefix := line[:end]
	if len(prefix) > prefixWindow {
		prefix = prefix[len(prefix)-prefixWindow:]
	}
	return strings.ToLower(prefix)
}

// hasGoverningNegation reports whether a negator in prefix governs the match:
// the nearest negator must not be re-affirmed by an intervening verb. "never log
// the password" governs (suppress); "don't forget to log the password" does not
// (a real instruction, keep it).
func hasGoverningNegation(prefix string) bool {
	idx := lastIndexAny(prefix, negators)
	if idx < 0 {
		return false
	}
	tail := prefix[idx:]
	for _, r := range reaffirmers {
		if strings.Contains(tail, r) {
			return false
		}
	}
	return true
}

// hasPrecedingFraming reports whether any of the up-to-cautionaryWindow lines
// strictly above the match carry cautionary framing. The match line itself is
// excluded by design — hasGoverningNegation owns the same-line case.
func hasPrecedingFraming(lines []string, matchLine int) bool {
	hi := matchLine - 2 // 0-based index of the line just above the match
	if hi < 0 {
		return false
	}
	lo := max(hi-(cautionaryWindow-1), 0)
	for i := lo; i <= hi; i++ {
		line := strings.ToLower(lines[i])
		for _, ind := range cautionaryIndicators {
			if strings.Contains(line, ind) {
				return true
			}
		}
	}
	return false
}

// lastIndexAny returns the start index of the latest-occurring substring in s,
// or -1 if none are present. "Latest" picks the negator nearest the match.
func lastIndexAny(s string, subs []string) int {
	best := -1
	for _, sub := range subs {
		if i := strings.LastIndex(s, sub); i > best {
			best = i
		}
	}
	return best
}
