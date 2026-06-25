// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package judge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mongodb/skill-gate/internal/rules"
	"github.com/mongodb/skill-gate/llm"
)

// Cache is an on-disk store of judge results, one JSON file per entry, modeled
// on skill-validator's judge cache. Its purpose is to avoid re-paying for LLM
// calls on PR pushes that don't change a skill.
//
// An entry is keyed by a stable identity — model, rule id, and file path — so a
// re-run of the same (model, rule, file) overwrites in place rather than
// accumulating orphans. Whether the entry is still valid is a separate check:
// it is a hit only when the stored content hash and rule hash both still match,
// so editing the file content or the rule's rubric/exclusions/schema
// invalidates it automatically. Switching models lands on a different key, so a
// model change never reads a stale judgment either.
type Cache struct {
	dir string
}

// NewCache returns a cache rooted at dir. The directory is created lazily on the
// first cache write (see save).
func NewCache(dir string) *Cache { return &Cache{dir: dir} }

// CacheEntry is one persisted judge result plus the metadata used to validate
// it on read.
type CacheEntry struct {
	Model       string            `json:"model"`
	RuleID      string            `json:"rule_id"`
	File        string            `json:"file"`
	ContentHash string            `json:"content_hash"`
	RuleHash    string            `json:"rule_hash"`
	JudgedAt    time.Time         `json:"judged_at"`
	Response    llm.JudgeResponse `json:"response"`
}

// cacheKey is the stable identity of a (model, rule, file) judgment. Editing the
// file or the rule does not change the key — it changes the validity hashes the
// entry carries — so a re-judge overwrites the same file.
func cacheKey(model, ruleID, file string) string {
	return shortHash(model + "\x00" + ruleID + "\x00" + file)
}

// contentHash identifies a file's content for cache invalidation.
func contentHash(content string) string { return shortHash(content) }

// ruleHash identifies the parts of an llm_judge rule that change its meaning, so
// editing the rubric, exclusions, or schema invalidates cached judgments.
func ruleHash(r *rules.Rule) string {
	var b strings.Builder
	b.WriteString(r.Rubric)
	b.WriteByte(0)
	for _, ex := range r.Exclusions {
		b.WriteString(ex)
		b.WriteByte(0)
	}
	b.Write(r.SchemaBytes())
	return shortHash(b.String())
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:32]
}

// get returns the cached entry for key if it exists and is readable. Validity
// (content/rule hash match) is the caller's check.
func (c *Cache) get(key string) (*CacheEntry, bool) {
	data, err := os.ReadFile(filepath.Join(c.dir, key+".json"))
	if err != nil {
		return nil, false
	}
	var e CacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, false
	}
	return &e, true
}

// save writes an entry for key, creating the cache directory if needed. A write
// error is returned so the caller can decide whether to treat caching as
// best-effort; the scanner does (a failed cache write never fails a scan).
func (c *Cache) save(key string, e *CacheEntry) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	// Write to a unique temp file then rename, so a concurrent or interrupted
	// write never leaves a truncated entry that a later run would read as valid.
	final := filepath.Join(c.dir, key+".json")
	tmp, err := os.CreateTemp(c.dir, key+".*.tmp")
	if err != nil {
		return fmt.Errorf("create cache temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close cache temp: %w", err)
	}
	return os.Rename(tmpName, final)
}
