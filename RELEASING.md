# Releasing

skill-gate is distributed as a Go module — consumers install a pinned version
with `go install`:

```sh
go install github.com/mongodb/skill-gate/cmd/skill-gate@vX.Y.Z
```

There is no build pipeline to run. `go install` compiles from source at the
tagged commit, and the binary reports its version from build info with no
ldflags (see `resolveVersion` in `cmd/skill-gate/main.go`). **Cutting a release
is just pushing a semver tag.**

## Versioning

- Tags are semver with a leading `v`: `vMAJOR.MINOR.PATCH` (e.g. `v0.1.0`).
- Pre-1.0 (`v0.x`): treat minor bumps as potentially breaking.
- `go install …@vX.Y.Z` resolves the tag via the Go module proxy. A GitHub
  *Release* object is **not** required — it's a separate, optional UI layer
  (release notes / attached binaries), and `go install` never looks at it.

## Cut a release

```sh
git checkout main && git pull --ff-only       # release from a green main
git tag -a v0.1.0 -m "skill-gate v0.1.0"      # use -s to sign if required (see below)
git push origin v0.1.0
```

Verify it resolves (the first fetch may take a few seconds while the module
proxy populates):

```sh
go install github.com/mongodb/skill-gate/cmd/skill-gate@v0.1.0
skill-gate --version            # prints v0.1.0
# …or without installing:
go list -m github.com/mongodb/skill-gate@v0.1.0
```

## Rules of thumb

- **Tags are immutable once published.** The Go module proxy caches a version's
  content permanently — never move or re-point a published tag. To ship a fix,
  cut the next patch (`v0.1.1`).
- **Tag a commit you're happy to pin.** Downstream CI pins an exact tag and
  bumps it deliberately, so a bad tag can't be silently overwritten — only
  superseded by a newer one.
- **Signing / protection.** If your org requires signed commits or protected /
  signed tags, sign the tag (`git tag -s`) and apply tag protection before
  pushing.

## Optional: a GitHub Release

Not needed for `go install`. Create one only if you want human-readable release
notes, visibility in the Releases tab, or attached prebuilt binaries.
