// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mongodb/skill-gate/internal/report"
	"github.com/mongodb/skill-gate/llm"
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
		staticOnly  bool
		llmModel    string
		cacheDir    string
		llmConc     int
		llmTimeout  time.Duration
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
			client, err := judgeClient(staticOnly, llmModel)
			if err != nil {
				return err
			}
			rep, err := scanner.Scan(cmd.Context(), args[0], scanner.Config{
				EnablePacks:    enabled,
				RulesDir:       rulesDir,
				MinConfidence:  confidenceFloor(minConf),
				Client:         client,
				StaticOnly:     staticOnly,
				CacheDir:       cacheDir,
				LLMConcurrency: llmConc,
				LLMTimeout:     llmTimeout,
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
	cmd.Flags().Float64Var(&minConf, "min-confidence", 0, "suppress static findings below this confidence floor (0-1): ESCALATE downgrades to WARN, WARN drops (does not apply to llm_judge findings)")
	cmd.Flags().BoolVar(&staticOnly, "static-only", false, "skip the LLM-as-judge stage; run only static rules (no LLM client required)")
	cmd.Flags().StringVar(&llmModel, "llm-model", llm.DefaultModel, "model id for the LLM-as-judge stage")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "enable the judge result cache in this directory (off by default; in CI use an ephemeral path and never commit it)")
	cmd.Flags().IntVar(&llmConc, "llm-concurrency", 0, "max concurrent LLM calls (0 = default)")
	cmd.Flags().DurationVar(&llmTimeout, "llm-timeout", 0, "per-call timeout for LLM requests (0 = none)")
	return cmd
}

// judgeClient builds the default Anthropic client for stage 2 from the
// environment. With --static-only it returns nil (stage 2 is skipped). Missing
// credentials are not fatal here: a nil client lets the scanner fail closed with
// a clear message only if the selected packs actually contain llm_judge rules.
func judgeClient(staticOnly bool, model string) (llm.Client, error) {
	if staticOnly {
		return nil, nil
	}
	c, err := llm.NewAnthropicFromEnv(model)
	if errors.Is(err, llm.ErrNoCredentials) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
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
