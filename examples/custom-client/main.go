// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Command custom-client is the supported bring-your-own-client example: it shows
// an org wiring its own llm.Client (e.g. Bedrock with IRSA, or a bespoke auth
// flow) into scanner.Scan without touching the rest of skill-gate. It is built
// by `go build ./...` in CI, so the extension seam stays continuously verified.
//
// Usage: custom-client <bundle>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mongodb/skill-gate/llm"
	"github.com/mongodb/skill-gate/scanner"
	"github.com/mongodb/skill-gate/verdict"
)

// myClient is a stand-in for an org's own LLM integration. Replace the body of
// Judge with a real call to your provider (Bedrock, a gateway, a local model).
// The contract is all skill-gate needs: return whether the rule fired, with a
// confidence, a rationale, and any source spans — never a severity, which the
// scanner applies from the rule itself.
type myClient struct{}

// Model identifies the model for the judge result cache. Implementing it is
// optional; when present, cached results are scoped to this id.
func (myClient) Model() string { return "example-model-v1" }

func (myClient) Judge(_ context.Context, req llm.JudgeRequest) (*llm.JudgeResponse, error) {
	// A real client would send req.Rubric, req.Exclusions, req.Content, and
	// req.Schema to its provider, then parse and validate the structured
	// response. This placeholder never fires, so the example is deterministic.
	_ = req
	return &llm.JudgeResponse{
		Fired:      false,
		Confidence: 1.0,
		Rationale:  "example client: not evaluated",
	}, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: custom-client <bundle>")
		os.Exit(verdict.ExitError)
	}

	rep, err := scanner.Scan(context.Background(), os.Args[1], scanner.Config{
		Client: myClient{},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		os.Exit(verdict.ExitError)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(verdict.ExitError)
	}
	os.Exit(rep.Verdict.ExitCode())
}
