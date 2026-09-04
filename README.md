# GoBGP-Netlink: BGP implementation in Go with Redistribution Support via Netlink

[![Tests](https://github.com/purelb/gobgp-netlink/actions/workflows/ci.yml/badge.svg)](https://github.com/purelb/gobgp-netlink/actions/workflows/ci.yml)
[![Releases](https://img.shields.io/github/release/purelb/gobgp-netlink/all.svg?style=flat-square)](https://github.com/purelb/gobgp-netlink/releases)
[![LICENSE](https://img.shields.io/github/license/purelb/gobgp-netlink.svg?style=flat-square)](https://github.com/purelb/gobgp-netlink/blob/main/LICENSE)

GoBGP-Netlink is an open source Border Gateway Protocol (BGP) implementation designed from scratch for modern environment and implemented in a modern programming language,
[the Go Programming Language](http://golang.org/).

It is a fork of [gobgp](https://github.com/osrg/gobgp) updated to v4.9.0


The primary feature added is redistribution via Netlink to the Linux routing tables.

- Import: kernel connected routes → BGP RIB, per-interface, global or per-VRF, glob patterns (eth*), now event-driven on RTM_NEWADDR/RTM_DELADDR
- Export: BGP best-path → kernel FIB, with community/large-community matching rules, per-rule table ID and metric, nexthop validation, dampening, and a startup sweep for stale routes
- 14 gRPC RPCs: GetNetlink, {Enable,Disable}Netlink{Import,Export}, the four …VrfNetlink… variants, GetNetlinkImportStats, ListNetlinkExport, GetNetlinkExportStats, FlushNetlinkExport, ListNetlinkExportRules
- Config: [netlink.import], [netlink.export] with [[netlink.export.rules]], and [vrfs.netlink-import] / [vrfs.netlink-export] — 147 lines of YANG upstream doesn't have
- CLI: gobgp netlink


Further information on this can be found in the [Linux Netlink Integration](docs/sources/netlink.md) section.

Addition features & fixes are:

- RFC 2545 dual next-hop origination.  Originates both a global and link-local IPv6 next hop for kernel-learned routes on unnumbered sessions, which have no address of their own.  This is a fix to upstream facilitated by netlink support

- BFD.  BFD itself is upstream's. What the fork adds is everything around it: gobgp bfd, the neighbor BFD block, GetBfdServerState (upstream computes those counters and discards them), the 300 ms × 3 config floor, receive-side GTSM, and robustness fixes — RX queue depth, drain-before-expiry, TX jitter.

- Graceful Restart.  Two upstream defects fixed. Restarting gobgpd  no longer sends Cease/PEER_DECONFIGURED to GR peers, and mp-graceful-restart derives from the neighbour setting instead of advertising an empty AFI/SAFI list.

- Metrics.  Additional 27 metrics including netlink and bfd instrumentation.

*We update docs where we have added or modified the functionality however the rest of the documentation comes from upstream.  In some cases we have found the upstream documentation to be out of date* 

This fork is maintained by the PureLB Kubernetes Load Balancer team.

----

## Install

Try [a binary release](https://github.com/purelb/gobgp-netlink/releases/latest).

## Documentation

### Using GoBGP

- [Getting Started](docs/sources/getting-started.md)
- CLI
  - [Typical operation examples](docs/sources/cli-operations.md)
  - [Complete syntax](docs/sources/cli-command-syntax.md)
- [Route Server](docs/sources/route-server.md)
- [Route Reflector](docs/sources/route-reflector.md)
- [Policy](docs/sources/policy.md)
- Zebra Integration
  - [FIB manipulation](docs/sources/zebra.md)
  - [Equal Cost Multipath Routing](docs/sources/zebra-multipath.md)
- **Linux Netlink Integration** ⚠️ Linux-only
  - [Netlink Import/Export](docs/sources/netlink.md)
  - Import connected routes from Linux interfaces
  - Export BGP routes to Linux routing tables
  - Full VRF (Virtual Routing and Forwarding) support
  - IPv4 and IPv6 address families
- [MRT](docs/sources/mrt.md)
- [BMP](docs/sources/bmp.md)
- [EVPN](docs/sources/evpn.md)
- [Flowspec](docs/sources/flowspec.md)
- [RPKI](docs/sources/rpki.md)
- [Metrics](docs/sources/metrics.md)
- [Managing GoBGP with your favorite language with gRPC](docs/sources/grpc-client.md)
- Go Native BGP Library
  - [Basics](docs/sources/lib.md)
  - [BGP-LS](docs/sources/bgp-ls.md)
  - [SR Policy](docs/sources/lib-srpolicy.md)
- [Graceful Restart](docs/sources/graceful-restart.md)
- [Additional Paths](docs/sources/add-paths.md)
- [Peer Group](docs/sources/peer-group.md)
- [Dynamic Neighbor](docs/sources/dynamic-neighbor.md)
- [eBGP Multihop](docs/sources/ebgp-multihop.md)
- [TTL Security](docs/sources/ttl-security.md)
- [BFD](docs/sources/bfd.md)
- [Confederation](docs/sources/bgp-confederation.md)
- Data Center Networking
  - [Unnumbered BGP](docs/sources/unnumbered-bgp.md)
- [Sentry](docs/sources/sentry.md)

### Externals

- [Tutorial: Using GoBGP as an IXP connecting router](http://www.slideshare.net/shusugimoto1986/tutorial-using-gobgp-as-an-ixp-connecting-router)
- [GoBGP.nix: A NixOS module for GoBGP. Containing a working FRR implementation and a rich set of Options](https://github.com/wavelens/gobgp.nix)

## Community, discussion and support

The Purelb team have a slack channel [Kubernetes/PureLB](https://kubernetes.slack.com/archives/C01BCB7U031) where you can post regarding the gobgp-netlink project.

The original authors of GoBGP have a [Slack](https://join.slack.com/t/gobgp/shared_invite/zt-g9il5j8i-3gZwnXArK0O9Mnn4Yu~IrQ) for questions, discussion, suggestions, etc.

You have code or documentation for GoBGP-Netlink? Awesome! Send a pull
request. No CLA, board members, governance, or other mess. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for info on
code contributing.

## Licensing

GoBGP is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/purelb/gobgp-netlink/blob/main/LICENSE) for the full
license text.
