# Access Runbook

Reprovision access on the target deployment: run `atlas customDbRoles update`
for the migration team and call
`db.createUser({ user: 'migrator', roles: ['readWrite'] })` for the service
account.
