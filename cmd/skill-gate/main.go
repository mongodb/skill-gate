// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Command skill-gate gates skill-bundle PRs by evaluating the markdown content
// of a skill against YAML rule packs, producing AUTO-PASS / WARN / ESCALATE
// verdicts. This is the reference wiring: it hands the build version to the CLI
// and exits with the CLI's chosen process exit code.
package main

import (
	"os"

	"github.com/mongodb/skill-gate/internal/cli"
)

// version is overridable at build time with
// -ldflags "-X main.version=<v>".
var version = "dev"

func main() {
	os.Exit(cli.Execute(version))
}
