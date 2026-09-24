#!/usr/bin/env python3
"""Check that netlink export installed exactly what BGP selected.

Run on a host where gobgpd exports to the kernel. For every prefix in the
global RIB it requires:

  - exactly one kernel route for the prefix, across every table and protocol
  - that the route carries gobgpd's route protocol
  - that its gateways are exactly the nexthops of the paths BGP marked best,
    each once - one with multipath off or maximum-paths 1, the whole
    multipath set otherwise

and that no route with gobgpd's protocol exists for a prefix the RIB does not
hold. It reads the RIB with the gobgp CLI and the kernel with ip(8), so it
needs both, and the global RIB only: VRF export is not checked.

    check_fib.py --gobgp ./gobgp --protocol 201

Exits 0 when every prefix matches, 1 otherwise.
"""
import argparse
import collections
import json
import subprocess
import sys


def run(*cmd):
    return json.loads(subprocess.check_output(cmd, text=True) or "null")


def rib(gobgp, family):
    """Each prefix's received path count and the nexthops of its best paths."""
    out = {}
    for prefix, paths in (run(gobgp, "-j", "global", "rib", "-a", family) or {}).items():
        best = []
        for p in paths:
            if p.get("best"):
                # NEXT_HOP for IPv4, MP_REACH_NLRI for IPv6.
                best += [a["nexthop"] for a in p["attrs"] if a["type"] in (3, 14)]
        out[prefix] = (len(paths), best)
    return out


def kernel(version):
    """Every kernel route, in every table, by destination. -N keeps the
    protocol numeric rather than whatever name /etc/iproute2 gives it."""
    routes = collections.defaultdict(list)
    for r in run("ip", "-N", version, "-j", "route", "show", "table", "all"):
        routes[r["dst"]].append(r)
    return routes


def gateways(route):
    if "nexthops" in route:
        return [nh.get("gateway") for nh in route["nexthops"]]
    return [route.get("gateway")]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--gobgp", default="gobgp", help="gobgp CLI to read the RIB with (default: gobgp)")
    parser.add_argument("--protocol", default="186",
                        help="route protocol gobgpd exports with, netlink.export route-protocol (default: 186)")
    args = parser.parse_args()

    failures = 0
    for family, version in (("ipv4", "-4"), ("ipv6", "-6")):
        bgp, fib = rib(args.gobgp, family), kernel(version)
        best_counts, kernel_counts = collections.Counter(), collections.Counter()
        for prefix, (received, best) in sorted(bgp.items()):
            best_counts[len(best)] += 1
            entries = fib.get(prefix, [])
            problem = None
            if len(entries) != 1:
                problem = f"{len(entries)} kernel routes"
            else:
                r = entries[0]
                gws = gateways(r)
                kernel_counts[len(gws)] += 1
                if str(r.get("protocol")) != args.protocol:
                    problem = f"route protocol {r.get('protocol')}, expected {args.protocol}"
                elif len(gws) != len(set(gws)):
                    problem = f"duplicate gateway {gws}"
                elif set(gws) != set(best):
                    problem = f"kernel {sorted(gws)} != best {sorted(best)}"
            if problem:
                failures += 1
                print(f"FAIL {family} {prefix}: {problem} (received {received} paths)")
        stray = [d for d, rs in fib.items()
                 if d not in bgp and any(str(r.get("protocol")) == args.protocol for r in rs)]
        for d in stray:
            failures += 1
            print(f"FAIL {family} {d}: route protocol {args.protocol} route for a prefix not in the RIB")
        print(f"{family}: {len(bgp)} prefixes; best paths per prefix {dict(best_counts)}; "
              f"kernel gateways per route {dict(kernel_counts)}; stray routes {len(stray)}")

    print("RESULT:", "PASS" if failures == 0 else f"FAIL ({failures})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
