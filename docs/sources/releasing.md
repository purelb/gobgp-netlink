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
| v1.3.1 | v4.900.1 |
| next | v4.900.2 |

## Steps

With the release commit on `main`:

```sh
# 1. the fork release tag, annotated, with the release notes
git tag -a v1.3.2 -F <notes-file> <commit>

# 2. the Go module tag, same commit
git tag -a v4.900.2 -F <explanation> <commit>

# 3. push both
git push origin v1.3.2 v4.900.2

# 4. the GitHub release is cut from the v1.x.y tag
gh release create v1.3.2 --notes-file <notes-file> --verify-tag
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

replace github.com/osrg/gobgp/v4 => github.com/purelb/gobgp-netlink/v4 v4.900.1
```

The `replace` is not optional: the module declares itself as
`github.com/osrg/gobgp/v4`, so requiring it by the fork's own path fails with a
module path mismatch. That is inherent to keeping the upstream path and is not
something a tag can fix.
