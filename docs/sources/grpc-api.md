# The gRPC API Contract

This page states what the gRPC API promises: which settings take effect and
when, what the daemon reports back, and what it refuses. It is for authors of
clients that drive gobgpd over the API, such as a Kubernetes controller that
reconciles desired state against `ListPeer`. For how to call the API from a
particular language, see [Managing GoBGP with Your Favorite Language](grpc-client.md).

## Contents

- [Every setting does something](#every-setting-does-something)
- [Presence: what "not set" means](#presence-what-not-set-means)
- [When a change takes effect](#when-a-change-takes-effect)
- [What is refused](#what-is-refused)
- [What is reported back](#what-is-reported-back)
- [Removed in 1.3.5](#removed-in-135)

## Every setting does something

A field the API accepts is acted on by the daemon. If gobgpd cannot act on a
setting, the field is not in the API, or the request is refused with an error
that says why. It is never accepted, stored, echoed back by a read, and
ignored.

That has not always been true, and 1.3.5 is the release that makes it so. The
conformance tests enforce it: every configuration setting must name the code
that acts on it, every value the daemon knows about a session must appear in
the reply, and every part of a peer must say whether changing it rebuilds the
session. A new field that does not meet this fails CI.

## Presence: what "not set" means

**Sub-messages are all-or-nothing.** `timers`, `transport`,
`graceful_restart`, `route_reflector`, `route_server`, `ebgp_multihop`,
`ttl_security`, `bfd` and `apply_policy` on `Peer` each count as set when the
message is present. Send one and you state every field in it, including the
ones left at zero. For a peer in a peer group this matters: a sub-message you
send replaces the group's, whole. Leave it out to inherit the group's.

**`PeerConf` is per field.** Every request carries `PeerConf` - it names the
peer and its group - so it cannot be all-or-nothing. These fields are
`optional` and inherit from the peer group when absent:
`auth_password`, `description`, `local_asn`, `remove_private`,
`send_community`, `send_software_version`, `allow_own_asn`,
`replace_peer_asn`, `allow_aspath_loop_local`. To state a zero value against a
group that sets one, set the field explicitly - `proto.Bool(false)`,
`proto.String("")`.

**`AfiSafiConfig.enabled` is ignored.** Every family in `afi_safis` is
negotiated. proto3 cannot tell `false` from absent, and absent is what most
clients send, so `false` is treated as enabled. To disable a family, leave it
out of the list.

## When a change takes effect

A change to a peer is either applied to the running session or rebuilds it.
Rebuilding tears the session down and brings it back up, which withdraws and
re-learns its routes. Through a peer group, one edit rebuilds every member.

| change | effect |
|---|---|
| `peer_asn`, `local_asn`, `auth_password`, `send_software_version`, `admin_down` | rebuilds |
| `allow_own_asn`, `replace_peer_asn`, `allow_aspath_loop_local` | rebuilds |
| `transport`, `ebgp_multihop`, `ttl_security`, `graceful_restart`, `afi_safis` | rebuilds |
| `route_server`, `route_reflector` | rebuilds |
| `timers.hold_time`, `timers.keepalive_interval` | rebuilds - they are negotiated in the OPEN |
| `timers.connect_retry`, `timers.idle_hold_time_after_reset` | applied in place |
| `send_community`, `remove_private` | applied in place; routes already advertised are re-sent |
| `description` | applied in place |
| `bfd` | applied in place |
| `apply_policy` | applied in place (route-server clients) |
| `afi_safis[].prefix_limits` | applied in place |

**Global settings take effect at `StartBgp` only.** There is no
`UpdateGlobal`: changing any field of `Global` means stopping and starting BGP.
A config-file reload that changes the `[global]` block logs an error naming
each setting it cannot apply, and applies the rest of the file.

## What is refused

Each of these is refused with an error rather than accepted and ignored.

| request | why |
|---|---|
| `StartBgp` with `use_multiple_paths` and neither `ebgp_maximum_paths` nor `ibgp_maximum_paths` | multipath with no limit selects nothing beyond the best path |
| `StartBgp` with `graceful_restart.longlived_enabled` | long-lived graceful restart is never inherited from the global block; set it per peer |
| `AddPeer` / `UpdatePeer` with `apply_policy` on a peer that is not a route-server client | per-peer policy is applied only to route-server clients; attach the policy to the global table instead |
| `AddDynamicNeighbor` through a peer group whose `apply_policy` is set and that is not a route-server client | the same, for every peer the group would create |

A peer group carrying a policy is accepted - it is a template, and may serve
route-server members. The refusal lands on a member that would ignore it.

## What is reported back

`ListPeer` reports each peer's resolved configuration - after peer-group
inheritance and defaults - and the session's state. A controller
comparing what it sent against what is reported will see the defaults gobgpd
fills in; [Settings gobgpd fills in for you](configuration.md#settings-gobgpd-fills-in-for-you)
lists them.

Deliberately not reported:

- **The MD5 password.** `PeerConf.auth_password` is redacted by `ListPeer`.
  `PeerState.auth_password_set` says whether one is configured.
- **A supplied `PeerConf.type`.** The peer type is derived from `peer_asn` and
  `local_asn`; the field reports the derived value, whatever was sent.

`PeerState.disconnect_reason` and `disconnect_message` say why the session
last went down, and are unset until it has. The netlink next hops -
`ipv4_nexthop`, `ipv6_nexthop`, `ipv6_link_local_nexthop` - are the addresses
a route imported from the kernel is advertised to this peer with, resolved when
the session came up.

## Removed in 1.3.5

These fields were accepted and acted on by nothing. They are removed and their
field numbers reserved. A client built against an older proto that still sets
one sends a field the daemon now drops as unknown - no error, and no change in
behaviour, because the field never did anything.

| field | why it did nothing |
|---|---|
| `PeerConf.route_flap_damping`, `PeerGroupConf.route_flap_damping`, and the two state copies | no route flap damping is implemented |
| `TimersConfig.minimum_advertisement_interval`, `TimersState.minimum_advertisement_interval` | nothing paces advertisements |
| `AfiSafi.route_selection_options`, `AfiSafi.use_multiple_paths` | route selection and multipath are global |
| `AfiSafi.apply_policy` | per-family policy was never applied |
| `RouteSelectionOptionsConfig.advertise_inactive_routes`, `enable_aigp`, `ignore_next_hop_igp_metric` | no route selection reads them |
| `Global.default_route_distance` | administrative distance is used by nothing |
| `Transport.mtu_discovery` | no socket option was set from it |
| `Queues.input` | there is no receive queue |
| `BfdAsyncCounters.last_packet_transmitted`, `last_packet_received` | no timestamp is recorded |
| `PeerState.auth_password`, `PeerGroupState.auth_password` | never written; `auth_password_set` is the flag |
| `Path.uuid` | never set on a read; `AddPathResponse` carries the uuid |

Added in 1.3.5:

- `Global.ebgp_maximum_paths` and `Global.ibgp_maximum_paths`, the multipath
  limits. See [Multipath](configuration.md#multipath).
- `ListNetlinkExportResponse.ExportedRoute.nexthops`, every nexthop of an
  exported route. An ECMP route has no single gateway, so its `nexthop` is
  empty.
