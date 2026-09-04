#!/usr/bin/env bash
#
# Report advisories against the upstream release this fork is based on.
#
# govulncheck cannot do this. It matches OSV advisories against a module's
# dependencies, and the inherited gobgp code is the *main* module here, so it is
# invisible to that tool - and would stay invisible under any other module name,
# because OSV keys its advisories to github.com/osrg/gobgp/v4. Renaming the
# module would match less, not more.
#
# So ask OSV directly: "what is known against the upstream release we are based
# on?" The base version is read from internal/pkg/version/version.go rather than
# hardcoded, so the next upstream catch-up moves one place and this follows.
#
# Anything OSV returns that is not justified in tools/vuln-allowlist.txt fails.

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}/.."

VERSION_FILE=internal/pkg/version/version.go
ALLOWLIST=tools/vuln-allowlist.txt
UPSTREAM_MODULE=github.com/osrg/gobgp/v4

# The base version lives in three constants. Anchor on the comment above them so
# the fork's own FORK_MAJOR/MINOR/PATCH cannot be picked up by mistake.
read_base_version() {
    python3 - "$VERSION_FILE" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
# Take the first MAJOR/MINOR/PATCH triple, which is the upstream base; the
# fork's own version uses the FORK_ prefix and is deliberately not matched.
def one(name):
    m = re.search(r'^\s*%s\s+uint\s*=\s*(\d+)' % name, src, re.M)
    if not m:
        sys.exit("could not read %s from %s" % (name, sys.argv[1]))
    return m.group(1)
print("%s.%s.%s" % (one("MAJOR"), one("MINOR"), one("PATCH")))
PY
}

BASE_VERSION=$(read_base_version)
echo "base upstream version: ${UPSTREAM_MODULE}@${BASE_VERSION}"

RESPONSE=$(curl -sS --fail --max-time 30 -X POST https://api.osv.dev/v1/query \
    -d "{\"package\":{\"name\":\"${UPSTREAM_MODULE}\",\"ecosystem\":\"Go\"},\"version\":\"${BASE_VERSION}\"}")

python3 - "$ALLOWLIST" <<PY
import json, re, sys

allow = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = re.split(r"\s+", line, maxsplit=1)
    allow[parts[0]] = parts[1] if len(parts) > 1 else ""

data = json.loads(r'''${RESPONSE}''')
vulns = data.get("vulns", [])

if not vulns:
    print("no advisories against the base version")
    sys.exit(0)

unlisted = []
for v in vulns:
    ident = v.get("id", "?")
    summary = (v.get("summary") or "").strip().replace("\n", " ")
    # OSV returns the same advisory under different identifiers depending on the
    # query - the NEXT_HOP DoS comes back as GO-2026-4736 for one base version
    # and GHSA-4p9m-8gc4-rw2h for another. Matching the id alone would fail the
    # build on an advisory that is already justified, so aliases count too.
    names = [ident] + list(v.get("aliases", []))
    hit = next((n for n in names if n in allow), None)
    if hit:
        print("  allowlisted %s - %s" % (hit, allow[hit][:90]))
    else:
        unlisted.append((ident, summary))

if unlisted:
    print()
    print("FAIL: %d advisory/advisories against %s@%s are not in %s:"
          % (len(unlisted), "${UPSTREAM_MODULE}", "${BASE_VERSION}", sys.argv[1]))
    for ident, summary in unlisted:
        print("  %s  %s" % (ident, summary[:100]))
        print("      https://pkg.go.dev/vuln/%s" % ident)
    print()
    print("Either fix it, or add an entry to %s saying why it does not apply" % sys.argv[1])
    print("and what proves that.")
    sys.exit(1)

print("all %d advisory/advisories are allowlisted with a justification" % len(vulns))
PY
