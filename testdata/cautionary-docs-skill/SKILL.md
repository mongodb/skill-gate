---
name: secure-logging-guide
description: Guidance on what a skill must never do with credentials.
license: Apache-2.0
---
# Secure Logging Guidelines

Follow these rules when handling sensitive values:

- Never log the connection string to the console.
- Never log the user password or write it to a file.
- Never store the password in plaintext.

These are cautionary examples: the prose describes what *not* to do, so a
scanner must not flag the guidance itself.
