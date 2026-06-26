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
	"runtime/debug"

	"github.com/mongodb/skill-gate/internal/cli"
)

// version is the fallback build version, overridable at build time with
// -ldflags "-X main.version=<v>". It is used only when the binary carries no
// module version in its build info — e.g. built outside a VCS checkout. A
// `go install <module>@<tag>` binary reports the tag and a local `go build` in
// the repo reports a VCS pseudo-version instead (see resolveVersion).
var version = "dev"

func main() {
	os.Exit(cli.Execute(resolveVersion()))
}

// resolveVersion prefers the module version embedded in the binary's build info:
// `go install <module>@<tag>` sets it to the tag (e.g. v0.1.0) and a local
// `go build` in the repo sets a VCS pseudo-version — both with no ldflags. It
// falls back to the ldflags-injected version (or "dev") only when build info
// carries no version at all.
func resolveVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}
