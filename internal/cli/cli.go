// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package cli builds skill-gate's cobra command tree and owns the mapping from
// outcomes to process exit codes. main.go is a thin wrapper around Execute.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mongodb/skill-gate/verdict"
	"github.com/spf13/cobra"
)

// packsFlagUsage is the shared help text for the --packs flag.
const packsFlagUsage = `comma-separated built-in packs to run (default: all; "none" to disable built-ins)`

// enabledPacks turns the --packs flag into the allowlist scanner/rules expect.
// When the flag was not set it returns nil ("all built-in packs"). "none"
// (case-insensitive) returns a non-nil empty slice ("no built-in packs").
// Otherwise it returns the comma-separated names.
//
// A value that is set but names no packs (empty, whitespace, or only commas) is
// an error rather than a silent "none": disabling the built-ins must be spelled
// out so a malformed flag can never quietly run zero security rules.
func enabledPacks(changed bool, raw string) ([]string, error) {
	if !changed {
		return nil, nil
	}
	if strings.EqualFold(strings.TrimSpace(raw), "none") {
		return []string{}, nil
	}
	out := []string{}
	for name := range strings.SplitSeq(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--packs %q names no built-in packs; pass a comma-separated list (e.g. --packs core) or \"none\" to disable the built-ins", raw)
	}
	return out, nil
}

// exitCodeError carries a verdict-derived exit code up to Execute. Its message
// is empty because the scan output has already been rendered; Execute uses it
// only to choose the process exit code, not to print anything.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return "" }

// Execute builds the root command and runs it, returning the process exit code.
// A clean run returns the verdict's code (0/1/2); a tool error is printed to
// stderr and returns verdict.ExitError.
func Execute(version string) int {
	root := newRootCmd(version)
	// We render scan output and errors ourselves, so keep cobra from echoing
	// usage or the error on top of our output.
	root.SilenceErrors = true
	root.SilenceUsage = true

	err := root.Execute()
	if err == nil {
		return verdict.ExitAutoPass
	}
	var ece *exitCodeError
	if errors.As(err, &ece) {
		return ece.code
	}
	fmt.Fprintln(os.Stderr, "skill-gate: "+err.Error())
	return verdict.ExitError
}

func newRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "skill-gate",
		Short: "Gate Agent Skill PRs by evaluating skill prose for unsafe guidance",
		Long: "skill-gate evaluates the markdown content of a skill bundle against YAML rule\n" +
			"packs and produces a single verdict: AUTO-PASS, WARN, or ESCALATE.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newScanCmd(), newVersionCmd(version), newRulesCmd())
	return root
}
