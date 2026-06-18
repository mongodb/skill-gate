// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mongodb/skill-gate/internal/rules"
	builtinpacks "github.com/mongodb/skill-gate/rules"
)

const validPack = `pack: test
version: 0.1.0
rules:
  - id: T-001
    description: a test rule
    type: static_regex
    severity: WARN
    patterns:
      - pattern: 'foo'
        confidence: 0.5
`

func mapFS(body string) fstest.MapFS {
	return fstest.MapFS{"pack.yaml": {Data: []byte(body)}}
}

func TestLoadFSValid(t *testing.T) {
	packs, err := rules.LoadFS(mapFS(validPack))
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(packs) != 1 || packs[0].Name != "test" || len(packs[0].Rules) != 1 {
		t.Fatalf("unexpected packs: %+v", packs)
	}
	if got := packs[0].Rules[0].Patterns[0].Regexp(); got == nil {
		t.Error("pattern was not compiled")
	}
}

func TestLoadFSDefaultsConfidence(t *testing.T) {
	body := strings.Replace(validPack, "        confidence: 0.5\n", "", 1)
	packs, err := rules.LoadFS(mapFS(body))
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if got := packs[0].Rules[0].Patterns[0].Confidence; got != 1.0 {
		t.Errorf("default confidence = %v, want 1.0", got)
	}
}

func TestLoadFSErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"missing pack name", "version: 1\nrules: []\n", "missing 'pack' name"},
		{"missing version", "pack: t\nrules: []\n", "missing 'version'"},
		{
			"missing rule id",
			"pack: t\nversion: 1\nrules:\n  - description: d\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: x\n",
			"missing 'id'",
		},
		{
			"missing description",
			"pack: t\nversion: 1\nrules:\n  - id: A\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: x\n",
			"missing 'description'",
		},
		{
			"unknown field rejected",
			"pack: t\nversion: 1\nbogus: x\nrules: []\n",
			"field bogus not found",
		},
		{
			"unsupported rule type",
			"pack: t\nversion: 1\nrules:\n  - id: A\n    description: d\n    type: llm_judge\n    severity: WARN\n    patterns:\n      - pattern: x\n",
			"unsupported type",
		},
		{
			"invalid severity",
			"pack: t\nversion: 1\nrules:\n  - id: A\n    description: d\n    type: static_regex\n    severity: INFO\n    patterns:\n      - pattern: x\n",
			"invalid severity",
		},
		{
			"no patterns",
			"pack: t\nversion: 1\nrules:\n  - id: A\n    description: d\n    type: static_regex\n    severity: WARN\n    patterns: []\n",
			"at least one pattern",
		},
		{
			"bad regex",
			"pack: t\nversion: 1\nrules:\n  - id: A\n    description: d\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: '('\n",
			"error parsing regexp",
		},
		{
			"duplicate id in pack",
			"pack: t\nversion: 1\nrules:\n  - id: A\n    description: d\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: x\n  - id: A\n    description: e\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: y\n",
			"duplicate rule id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rules.LoadFS(mapFS(tt.body))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestCheckUniqueIDsAcrossPacks(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte("pack: a\nversion: 1\nrules:\n  - id: X-1\n    description: d\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: x\n")},
		"b.yaml": {Data: []byte("pack: b\nversion: 1\nrules:\n  - id: X-1\n    description: d\n    type: static_regex\n    severity: WARN\n    patterns:\n      - pattern: y\n")},
	}
	packs, err := rules.LoadFS(fsys)
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if err := rules.CheckUniqueIDs(packs); err == nil || !strings.Contains(err.Error(), "X-1") {
		t.Fatalf("CheckUniqueIDs error = %v, want collision on X-1", err)
	}
}

func TestLoadDirMissingIsNoop(t *testing.T) {
	packs, err := rules.LoadDir("/nonexistent/path/here")
	if err != nil {
		t.Fatalf("LoadDir missing: %v", err)
	}
	if packs != nil {
		t.Errorf("LoadDir missing = %v, want nil", packs)
	}
	if packs, err := rules.LoadDir(""); err != nil || packs != nil {
		t.Errorf("LoadDir empty = (%v, %v), want (nil, nil)", packs, err)
	}
}

func TestLoadDirOnDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "overlay.yaml"), []byte(validPack), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, err := rules.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(packs) != 1 || packs[0].Name != "test" {
		t.Errorf("LoadDir = %+v, want one pack named test", packs)
	}
}

func TestLoadDirNotADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "notadir.yaml")
	if err := os.WriteFile(file, []byte(validPack), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := rules.LoadDir(file)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("LoadDir(file) err = %v, want not-a-directory error", err)
	}
}

func TestLoadAllWithOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "overlay.yaml"), []byte(validPack), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, err := rules.LoadAll(builtinpacks.FS, nil, dir)
	if err != nil {
		t.Fatalf("LoadAll with overlay: %v", err)
	}
	names := map[string]bool{}
	for _, p := range packs {
		names[p.Name] = true
	}
	if !names["test"] {
		t.Errorf("overlay pack 'test' not present in %v", packNamesOf(packs))
	}
	for _, want := range []string{"core", "mongodb"} {
		if !names[want] {
			t.Errorf("built-in pack %q dropped when overlay applied (got %v)", want, packNamesOf(packs))
		}
	}
}

func TestLoadAllOverlayCollision(t *testing.T) {
	// An overlay rule reusing a built-in id must fail the cross-pack check.
	collide := strings.Replace(validPack, "id: T-001", "id: CORE-001", 1)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "overlay.yaml"), []byte(collide), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := rules.LoadAll(builtinpacks.FS, nil, dir)
	if err == nil || !strings.Contains(err.Error(), "CORE-001") {
		t.Errorf("LoadAll err = %v, want collision on CORE-001", err)
	}
}

// TestShippedPacksLoad guards against a malformed built-in pack shipping.
func TestShippedPacksLoad(t *testing.T) {
	packs, err := rules.LoadAll(builtinpacks.FS, nil, "")
	if err != nil {
		t.Fatalf("shipped packs failed to load: %v", err)
	}
	names := map[string]bool{}
	for _, p := range packs {
		names[p.Name] = true
	}
	for _, want := range []string{"core", "mongodb"} {
		if !names[want] {
			t.Errorf("shipped packs missing %q (got %v)", want, names)
		}
	}
}

func TestLoadAllPackSelection(t *testing.T) {
	t.Run("nil enables all", func(t *testing.T) {
		packs, err := rules.LoadAll(builtinpacks.FS, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(packs) != 2 {
			t.Errorf("got %d packs, want 2", len(packs))
		}
	})
	t.Run("allowlist keeps only named", func(t *testing.T) {
		packs, err := rules.LoadAll(builtinpacks.FS, []string{"core"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(packs) != 1 || packs[0].Name != "core" {
			t.Errorf("got %+v, want only core", packNamesOf(packs))
		}
	})
	t.Run("empty disables all base packs", func(t *testing.T) {
		packs, err := rules.LoadAll(builtinpacks.FS, []string{}, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(packs) != 0 {
			t.Errorf("got %d packs, want 0", len(packs))
		}
	})
	t.Run("unknown name errors", func(t *testing.T) {
		_, err := rules.LoadAll(builtinpacks.FS, []string{"nope"}, "")
		if err == nil || !strings.Contains(err.Error(), "unknown built-in pack") {
			t.Errorf("err = %v, want unknown-pack error", err)
		}
	})
}

func packNamesOf(packs []rules.Pack) []string {
	out := make([]string, len(packs))
	for i, p := range packs {
		out[i] = p.Name
	}
	return out
}
