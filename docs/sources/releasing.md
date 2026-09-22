# Releasing

Each release needs **two tags on the same commit**. Both are required; one is
for people and one is for Go.

| tag | example | purpose |
|-----|---------|---------|
| `v1.x.y` | `v1.3.1` | the fork's release. Drives the GitHub release and matches the version string the daemon prints. |
| `v4.900.N` | `v4.900.1` | the Go module version. The only way a consumer can pin this fork without a commit SHA. |

## Why two

`go.mod` declares:

```
module github.com/osrg/gobgp/v4
```

The fork keeps the upstream module path deliberately. Renaming it to
`github.com/purelb/gobgp-netlink/v4` would mean rewriting every import in the
tree, and every upstream catch-up merge would then conflict on those imports
across thousands of files.

The cost is that Go's semantic import versioning applies: a module whose path
ends in `/v4` may only be versioned by tags of the form `v4.x.y`. The fork's own
release tags are rejected:

```
$ go get github.com/purelb/gobgp-netlink/v4@v1.3.1
invalid version: module path includes a major version suffix,
so major version must match
```

Before `v4.900.1` the only published `v4.x` tag was `v4.0.0`, so every consumer
was pinned to a pseudo-version derived from it:

```
v4.0.1-0.20260917191119-994cf2fcd580
```

That is why `go get -u` did nothing useful and why consumers carried commit
SHAs in `go.mod`.

## Why the 900 series

Upstream tags reach this repository. `v1.30` through `v1.33` are old
`osrg/gobgp` tags sitting on our remote today, inherited through catch-up
merges. Reusing upstream's own numbering - tagging `v4.9.1` on top of their
`v4.9.0` - would collide the day upstream releases that version.

Upstream is at `4.9.0`. They will not reach `4.900`, so the series is ours
alone and can never clash.

The patch component increments once per fork release:

| fork release | Go module tag |
|--------------|---------------|
| v1.3.1 | v4.900.1 (withdrawn, see below) |
| v1.3.2 | v4.900.2 |
| v1.3.3 | v4.900.3 |
| next | v4.900.4 |

Never reuse a number. `v4.900.1` was tagged, withdrawn, and is permanently
spent: `sum.golang.org` had already notarised it against the v1.3.1 commit, and
that log is append-only, so deleting the git tag did not un-publish the
version. Re-tagging it on different content gives consumers a checksum
mismatch, which Go reports as possible tampering. Check before choosing a
number:

```sh
curl -s https://sum.golang.org/lookup/github.com/purelb/gobgp-netlink/v4@v4.900.N
```

An `h1:` line means the number is taken. Note the `/v4` suffix - it is part of
the module path, and querying without it returns a confident 404 for a module
that has never existed.

## Which tag builds binaries

Only the `v1.x.y` tag. The `release` workflow excludes `v4.*` deliberately, so
the Go module tag produces no GitHub release and no artifacts - it exists purely
for the module proxy.

Both tags sit on the same commit, and GoReleaser does not use the tag that
triggered the run to decide the version. It resolves it with

```sh
git tag --points-at HEAD --sort=-version:refname | head -1
```

which ranks `v4.900.N` above `v1.x.y` and yields the module version. The
workflow therefore pins `GORELEASER_CURRENT_TAG` to the triggering tag. Both
guards are needed: the trigger exclusion alone still leaves a lone `v1.x.y` run
building `v4.900.N` artifacts.

This is not hypothetical. v1.3.2 was released by pushing both tags in one
command, which fired the workflow twice; both runs built `4.900.2`, one created
a `v4.900.2` release and the other failed uploading assets that already
existed, and the `v1.3.2` release shipped with no binaries at all.

## Steps

With the release commit on `main`:

```sh
# 1. the fork release tag, annotated, with the release notes
git tag -a v1.3.2 -F <notes-file> <commit>

# 2. the Go module tag, same commit
git tag -a v4.900.2 -F <explanation> <commit>

# 3. push the release tag first, on its own, and let the build finish.
#    This is the only tag that triggers GoReleaser.
git push origin v1.3.2
gh run watch "$(gh run list --workflow=release --limit 1 --json databaseId --jq '.[0].databaseId')"

# 4. then the module tag, which triggers nothing
git push origin v4.900.2

# 5. the GitHub release is cut from the v1.x.y tag
gh release create v1.3.2 --notes-file <notes-file> --verify-tag
```

If a release needs rebuilding - a failed run, or artifacts attached to the wrong
release - re-run the workflow by hand rather than retagging. It checks out the
tag you name and pins the version to it:

```sh
gh workflow run release.yml --ref main -f tag=v1.3.2
```

Confirm the artifacts are named for the fork release, not the module version:

```sh
gh release view v1.3.2 --json assets --jq '.assets[].name'
# gobgp-netlink_1.3.2_linux_amd64.tar.gz, not gobgp-netlink_4.900.2_...
```

Verify the Go tag resolves before telling anyone to use it:

```sh
cd "$(mktemp -d)"
printf 'module t\ngo 1.25.13\nrequire github.com/osrg/gobgp/v4 v4.0.0\n' > go.mod
echo 'replace github.com/osrg/gobgp/v4 => github.com/purelb/gobgp-netlink/v4 v4.900.2' >> go.mod
go mod tidy   # must not rewrite the replace into a pseudo-version
```

## What consumers write

```
require github.com/osrg/gobgp/v4 v4.0.0

replace github.com/osrg/gobgp/v4 => github.com/purelb/gobgp-netlink/v4 v4.900.2
```

The `replace` is not optional: the module declares itself as
`github.com/osrg/gobgp/v4`, so requiring it by the fork's own path fails with a
module path mismatch. That is inherent to keeping the upstream path and is not
something a tag can fix.
