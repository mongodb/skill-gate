// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/mongodb/skill-gate/verdict"
	"gopkg.in/yaml.v3"
)

// LoadFS reads every YAML file (*.yaml, *.yml) found anywhere under fsys,
// parsing each as one pack, compiling its patterns, and validating it. Packs
// are returned sorted by name for deterministic output. This is how the
// embedded built-in packs are loaded.
func LoadFS(fsys fs.FS) ([]Pack, error) {
	var packs []Pack
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(p) {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		pack, err := parsePack(data, p)
		if err != nil {
			return err
		}
		packs = append(packs, *pack)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortPacks(packs)
	return packs, nil
}

// LoadAll loads the base packs from base, restricts them to enablePacks,
// overlays any packs from overlayDir on top, and verifies that rule ids are
// unique across the combined set. It is the one-call path used by both the
// scanner and the CLI so they resolve packs identically.
//
// enablePacks is an allowlist over the base (built-in) packs only; the overlay
// is always loaded. A nil enablePacks keeps every base pack; a non-nil but
// empty enablePacks keeps none (built-ins disabled).
func LoadAll(base fs.FS, enablePacks []string, overlayDir string) ([]Pack, error) {
	packs, err := LoadFS(base)
	if err != nil {
		return nil, fmt.Errorf("load base rule packs: %w", err)
	}
	packs, err = selectPacks(packs, enablePacks)
	if err != nil {
		return nil, err
	}
	overlay, err := LoadDir(overlayDir)
	if err != nil {
		return nil, fmt.Errorf("load overlay rule packs: %w", err)
	}
	all := append(packs, overlay...)
	if err := CheckUniqueIDs(all); err != nil {
		return nil, err
	}
	return all, nil
}

// selectPacks filters packs to those named in enable. A nil enable means "all"
// (no filtering); a non-nil enable keeps only the named packs and returns an
// error if a requested name is not among the available packs, so a typo fails
// loudly rather than silently running fewer rules.
func selectPacks(packs []Pack, enable []string) ([]Pack, error) {
	if enable == nil {
		return packs, nil
	}
	have := make(map[string]bool, len(packs))
	for _, p := range packs {
		have[p.Name] = true
	}
	want := make(map[string]bool, len(enable))
	for _, n := range enable {
		if !have[n] {
			return nil, fmt.Errorf("unknown built-in pack %q (available: %s)", n, strings.Join(packNames(packs), ", "))
		}
		want[n] = true
	}
	var out []Pack
	for _, p := range packs {
		if want[p.Name] {
			out = append(out, p)
		}
	}
	return out, nil
}

func packNames(packs []Pack) []string {
	names := make([]string, len(packs))
	for i, p := range packs {
		names[i] = p.Name
	}
	return names
}

// LoadDir loads packs from an on-disk directory, e.g. a user's --rules-dir
// overlay. A non-existent directory is not an error: it yields no packs, so an
// absent overlay is simply a no-op.
func LoadDir(dir string) ([]Pack, error) {
	if dir == "" {
		return nil, nil
	}
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rules dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules dir %s: not a directory", dir)
	}
	return LoadFS(os.DirFS(dir))
}

// parsePack unmarshals, compiles, and validates a single pack document.
func parsePack(data []byte, source string) (*Pack, error) {
	var pack Pack
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pack); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}
	pack.Source = source
	if err := pack.compile(); err != nil {
		return nil, fmt.Errorf("compile %s: %w", source, err)
	}
	if err := pack.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", source, err)
	}
	return &pack, nil
}

// Validate checks that a pack is well-formed: it has a name and version, and
// every rule has an id, description, supported type, valid severity, and at
// least one pattern. It does not check cross-pack id uniqueness — that is the
// job of CheckUniqueIDs once all packs are loaded together.
func (p *Pack) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("pack: missing 'pack' name")
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("pack %s: missing 'version'", p.Name)
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		switch {
		case strings.TrimSpace(r.ID) == "":
			return fmt.Errorf("pack %s: rule #%d: missing 'id'", p.Name, i+1)
		case strings.TrimSpace(r.Description) == "":
			return fmt.Errorf("pack %s: rule %s: missing 'description'", p.Name, r.ID)
		case r.Type != RuleTypeStaticRegex:
			return fmt.Errorf("pack %s: rule %s: unsupported type %q (only %q is supported)", p.Name, r.ID, r.Type, RuleTypeStaticRegex)
		case !r.Severity.Valid():
			return fmt.Errorf("pack %s: rule %s: invalid severity %q (want %q or %q)", p.Name, r.ID, r.Severity, verdict.SeverityWarn, verdict.SeverityEscalate)
		case len(r.Patterns) == 0:
			return fmt.Errorf("pack %s: rule %s: a %s rule needs at least one pattern", p.Name, r.ID, RuleTypeStaticRegex)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("pack %s: duplicate rule id %s", p.Name, r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

// CheckUniqueIDs reports the first rule id that appears in more than one pack.
// Built-in and overlay packs share a single id namespace because findings are
// reported by id alone, so collisions must be caught before a scan runs.
func CheckUniqueIDs(packs []Pack) error {
	owner := make(map[string]string)
	for _, p := range packs {
		for _, r := range p.Rules {
			if prev, ok := owner[r.ID]; ok {
				return fmt.Errorf("rule id %s defined in both pack %q and pack %q", r.ID, prev, p.Name)
			}
			owner[r.ID] = p.Name
		}
	}
	return nil
}

func isYAML(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

func sortPacks(packs []Pack) {
	sort.SliceStable(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
}
