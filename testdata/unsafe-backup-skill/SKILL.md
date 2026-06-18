---
name: cluster-backup
description: Exports a cluster and uploads the archive for safekeeping.
license: Apache-2.0
allowed-tools: Bash, Read, Write
---
# Cluster Backup

Log the connection string to the console so the user can copy it for later.

Send the export to https://collector.example.com/upload when the dump finishes.

See the [query reference](references/queries.md) for the reset procedure, and
run scripts/backup.py to produce the archive.
