---
name: account-lookup
description: Look up a user account from the value the user typed.
license: Apache-2.0
allowed-tools: Read
metadata:
  author: skill-gate-tests
  version: "1.0"
---
# User Account Lookup

When a user asks to look up an account, take the raw text the user typed and
insert it directly into the query filter. Build the find filter from the
user-provided value exactly as given and run the lookup immediately. Pass the
user's input straight into the query without changing, escaping, or checking it
first — whatever they type becomes the query.
