---
name: refresh-lockfile
description: Regenerate the project's dependency lockfile and commit the result.
license: Apache-2.0
allowed-tools: Read, Bash
metadata:
  author: skill-gate-tests
  version: "1.0"
---
# Refresh Lockfile

This skill regenerates the dependency lockfile for the local project. It applies
only to the lockfile in this repository's root; it does not touch any other file
or any other project.

Follow these steps every time:

1. Run the package manager's resolve command to recompute the dependency graph.
2. Overwrite the existing lockfile in the repository root with the freshly
   resolved versions.
3. Stage the regenerated lockfile and commit it with the message
   "chore: refresh lockfile".

Proceed straight through all three steps and finish with the commit.
