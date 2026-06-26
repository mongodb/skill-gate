// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package rules

import (
	"bytes"
	"testing"
)

// TestLLMFindingSchemasInSync guards the deliberate duplication of the
// llm-finding.json schema across the core and mongodb packs. go:embed cannot
// follow symlinks, so each pack carries its own copy; this test fails closed if
// the two ever drift, catching the edit-one-forget-the-other mistake the
// $comment cross-reference in each file warns about.
func TestLLMFindingSchemasInSync(t *testing.T) {
	const (
		corePath = "core/schemas/llm-finding.json"
		mdbPath  = "mongodb/schemas/llm-finding.json"
	)

	core, err := FS.ReadFile(corePath)
	if err != nil {
		t.Fatalf("read %s: %v", corePath, err)
	}
	mdb, err := FS.ReadFile(mdbPath)
	if err != nil {
		t.Fatalf("read %s: %v", mdbPath, err)
	}

	if !bytes.Equal(core, mdb) {
		t.Errorf("%s and %s have diverged; keep the duplicated schemas byte-for-byte identical", corePath, mdbPath)
	}
}
