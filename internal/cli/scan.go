// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mongodb/skill-gate/internal/report"
	"github.com/mongodb/skill-gate/scanner"
	"github.com/mongodb/skill-gate/verdict"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		output      string
		rulesDir    string
		packs       string
		strict      bool
		annotations bool
		minConf     float64
	)
	cmd := &cobra.Command{
		Use:   "scan <bundle>",
		Short: "Scan a skill bundle and print a verdict",
		Long: "Scan walks the markdown files in a skill bundle, applies the static rule\n" +
			"packs, and prints the findings and verdict. The exit code is 0 for AUTO-PASS,\n" +
			"1 for WARN, and 2 for ESCALATE.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !report.ValidFormat(output) {
				return fmt.Errorf("unknown output format %q (want one of: %s)", output, strings.Join(report.Formats, ", "))
			}
			if minConf < 0 || minConf > 1 {
				return fmt.Errorf("--min-confidence must be between 0 and 1, got %g", minConf)
			}
			enabled, err := enabledPacks(cmd.Flags().Changed("packs"), packs)
			if err != nil {
				return err
			}
			rep, err := scanner.Scan(cmd.Context(), args[0], scanner.Config{
				EnablePacks:   enabled,
				RulesDir:      rulesDir,
				MinConfidence: confidenceFloor(minConf),
			})
			if err != nil {
				return err
			}
			if err := report.Write(cmd.OutOrStdout(), output, rep); err != nil {
				return err
			}
			if annotations {
				workDir, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("resolve working directory for annotations: %w", err)
				}
				baseDir := args[0]
				if info, err := os.Stat(args[0]); err == nil && !info.IsDir() {
					baseDir = filepath.Dir(args[0])
				}
				if err := report.WriteAnnotations(cmd.OutOrStdout(), rep, baseDir, workDir); err != nil {
					return err
				}
			}
			return scanExit(rep.Verdict, strict)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", report.FormatText, "output format: text, json, or markdown")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "directory of additional rule packs to overlay")
	cmd.Flags().StringVar(&packs, "packs", "", packsFlagUsage)
	cmd.Flags().BoolVar(&strict, "strict", false, "treat WARN as a blocking (ESCALATE-level) exit code")
	cmd.Flags().BoolVar(&annotations, "emit-annotations", false, "also emit GitHub Actions workflow-command annotations to stdout")
	cmd.Flags().Float64Var(&minConf, "min-confidence", 0, "suppress static findings below this confidence floor (0-1): ESCALATE findings below it downgrade to WARN, WARN findings drop")
	return cmd
}

// confidenceFloor turns the single --min-confidence value into the per-tier map
// the scanner expects, applying the floor to both tiers. A zero floor returns a
// nil map so the default (report everything) costs no allocation.
func confidenceFloor(min float64) map[verdict.Severity]float64 {
	if min <= 0 {
		return nil
	}
	return map[verdict.Severity]float64{
		verdict.SeverityWarn:     min,
		verdict.SeverityEscalate: min,
	}
}

// scanExit converts a verdict into the exit signal Execute acts on. With
// --strict, a WARN is promoted to the ESCALATE exit code so a CI gate can fail
// the build on advisory findings.
func scanExit(v verdict.Verdict, strict bool) error {
	code := v.ExitCode()
	if strict && v == verdict.Warn {
		code = verdict.ExitEscalate
	}
	if code == verdict.ExitAutoPass {
		return nil
	}
	return &exitCodeError{code: code}
}
