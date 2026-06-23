// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/mongodb/skill-gate/internal/rules"
	builtinpacks "github.com/mongodb/skill-gate/rules"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect and validate rule packs",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newRulesListCmd(), newRulesLintCmd())
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var (
		rulesDir string
		packsSel string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the loaded rules",
		Long:  "List shows every rule in the selected built-in packs, plus any overlaid with --rules-dir.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			packs, err := loadSelectedPacks(cmd, packsSel, rulesDir)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), formatRules(packs))
			return err
		},
	}
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "directory of additional rule packs to include")
	cmd.Flags().StringVar(&packsSel, "packs", "", packsFlagUsage)
	return cmd
}

func newRulesLintCmd() *cobra.Command {
	var (
		rulesDir string
		packsSel string
	)
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Validate rule packs",
		Long: "Lint loads and validates the selected built-in packs (and any overlaid with\n" +
			"--rules-dir): every pattern must compile, every rule must be well-formed,\n" +
			"and rule ids must be unique across all packs. It exits non-zero on the first\n" +
			"problem it finds.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			packs, err := loadSelectedPacks(cmd, packsSel, rulesDir)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "ok: %d rule(s) across %d pack(s)\n", countRules(packs), len(packs))
			return err
		},
	}
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "directory of additional rule packs to validate")
	cmd.Flags().StringVar(&packsSel, "packs", "", packsFlagUsage)
	return cmd
}

// loadSelectedPacks resolves the --packs allowlist and --rules-dir overlay the
// same way for both rules subcommands: the built-ins filtered by --packs, with
// any overlay packs layered on top.
func loadSelectedPacks(cmd *cobra.Command, packsSel, rulesDir string) ([]rules.Pack, error) {
	enabled, err := enabledPacks(cmd.Flags().Changed("packs"), packsSel)
	if err != nil {
		return nil, err
	}
	return rules.LoadAll(builtinpacks.FS, enabled, rulesDir)
}

func formatRules(packs []rules.Pack) string {
	var b strings.Builder
	for _, p := range packs {
		fmt.Fprintf(&b, "%s (v%s) — %d rule(s)\n", p.Name, p.Version, len(p.Rules))
		for i := range p.Rules {
			r := &p.Rules[i]
			criterion := ""
			if r.Criterion > 0 {
				criterion = fmt.Sprintf(" [#%d]", r.Criterion)
			}
			fmt.Fprintf(&b, "  %-10s %-8s%s  %s\n", r.ID, r.Severity, criterion, r.Description)
		}
	}
	return b.String()
}

func countRules(packs []rules.Pack) int {
	n := 0
	for _, p := range packs {
		n += len(p.Rules)
	}
	return n
}
