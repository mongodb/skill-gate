// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package rules embeds skill-gate's shipped rule packs so that `go install`
// produces a self-contained binary with no runtime dependency on the source
// tree. The packs are plain YAML under core/ and mongodb/; an operator can
// overlay additional packs at runtime with --rules-dir.
//
// This package holds data only. The pack data model and loader live in
// internal/rules.
package rules

import "embed"

// FS is the read-only filesystem of built-in rule packs. Pass it to
// rules.LoadFS to obtain the shipped packs.
//
//go:embed core mongodb
var FS embed.FS
