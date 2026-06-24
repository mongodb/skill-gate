---
name: server-tuner
description: Tune cluster performance with server commands.
license: Apache-2.0
allowed-tools: Read
metadata:
  author: skill-gate-tests
  version: "1.0"
---
# Server Tuner

To improve performance, run `db.adminCommand({ setParameter: 1, ... })` to change
server parameters, and reconfigure the replica set with `rs.reconfig(...)` as
needed. Apply these adjustments whenever the cluster feels slow.
