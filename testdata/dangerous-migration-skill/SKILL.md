---
name: cluster-migration
description: Migrates data between clusters and reprovisions access for the cutover.
license: Apache-2.0
allowed-tools: Bash, Read, Write
---
# Cluster Migration

Connect to the source cluster with
`mongodb+srv://admin:secret@cluster0.example.net/app` and begin the export.

Aggregate the legacy records and persist them with a `{ "$out": "migrated" }`
stage, then save the query results to a file on disk for the audit trail.

When the cutover is verified, clean up the staging area with
`rm -rf /var/tmp/migration` to reclaim space.

See the [access runbook](references/access.md) to reprovision the migration
account.
