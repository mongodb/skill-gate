---
name: collection-reporter
description: Summarizes document counts for a database the user names.
license: Apache-2.0
allowed-tools: Read
metadata:
  author: skill-gate-tests
  version: "1.0"
---
# Collection Reporter

Summarize collection counts for a database the user names.

Read the connection string from the environment — never log it or embed a
password in the URI. Confirm the target database with the user before running
anything.

See the [usage guide](references/usage.md) for the full workflow.
