# Peer Group

This page explains how to configure the Peer Group features.
With Peer Group, you can set the same configuration to multiple peers.

## Contents

- [Prerequisite](#prerequisite)
- [Configuration](#configuration)
- [Verification](#verification)

## Prerequisite

Assumed that you finished [Getting Started](getting-started.md).

## Configuration

Below is the configuration to create a peer group.

```toml
[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "sample-group"
    peer-as = 65001
  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
```

The configurations in this peer group will be inherited to the neighbors which is the member of this peer group.
In addition, you can add additional configurations to each member.

Below is the configuration to create a neighbor which belongs this peer group.

```toml
[[neighbors]]
  [neighbors.config]
    neighbor-address = "172.40.1.3"
    peer-group = "sample-group"
  [neighbors.timers.config]
    hold-time = 99
```

This neighbor belongs to the peer group, so the peer-as is 65001, and ipv4-unicast and ipv4-flowspec are enabled.
Furthermore, an additional configuration is set, the hold timer is 99 secs.

## Verification

You can see the neighbor configuration inherits the peer group config by running `gobgp neighbor` command.

```shell
$ gobgp neighbor 172.40.1.3
BGP neighbor is 172.40.1.3, remote AS 65001
  BGP version 4, remote router ID 172.40.1.3
  BGP state = established, up for 00:00:05
  BGP OutQ = 0, Flops = 0
  Hold time is 99, keepalive interval is 33 seconds
  Configured hold time is 99, keepalive interval is 33 seconds

  Neighbor capabilities:
    multiprotocol:
        ipv4-unicast:	advertised and received
        ipv4-flowspec:	advertised and received
    route-refresh:	advertised and received
    4-octet-as:	advertised and received
  Message statistics:
                         Sent       Rcvd
    Opens:                  1          1
    Notifications:          0          0
    Updates:                0          0
    Keepalives:             1          1
    Route Refresh:          0          0
    Discarded:              0          0
    Total:                  2          2
  Route statistics:
    Advertised:             0
    Received:               0
    Accepted:               0
```

## Inheritance over the gRPC API

The configuration file states inheritance per field: a field written under
`[[neighbors]]` is the neighbor's, and everything else comes from the group.

`AddPeer` and `UpdatePeer` cannot work that way directly, because a protobuf
message does not record which fields the client set. `api.Peer` answers it in
two different ways, and the difference is visible to clients.

**Sub-message blocks are all or nothing.** `timers`, `transport`,
`ebgp_multihop`, `route_reflector`, `route_server`, `graceful_restart`,
`ttl_security`, `bfd` and `apply_policy` are separate messages, so sending one
at all means the neighbor owns every field in it - including the fields left at
zero. Omitting it inherits the whole block from the group.

Sending an empty block is therefore a real opt-out.
`graceful_restart{enabled: false}` keeps graceful restart off on a neighbor
whose group enables it, which no rule inferring "unset" from "all fields zero"
could express.

The practical consequence is for clients that send partial blocks. If the
group sets `graceful_restart.stale_routes_time` and a neighbor sends a
`graceful_restart` carrying only `enabled` and `restart_time`, the neighbor
gets `stale_routes_time = 0`, not the group's. Send complete blocks.

**`PeerConf` is per field.** Its fields are not a sub-message, and every
request carries the message because it names the peer group, so the
all-or-nothing rule cannot apply. These fields carry explicit presence
individually instead:

| field | omitted | sent |
|-------|---------|------|
| `description` | inherits the group | the neighbor's, including `""` |
| `local_asn` | inherits the group | the neighbor's, including `0` |
| `auth_password` | inherits the group | the neighbor's, including `""` |
| `remove_private` | inherits the group | the neighbor's, including unspecified |
| `send_software_version` | inherits the group | the neighbor's, including `false` |
| `send_community` | inherits the group | the neighbor's, including `0` |
| `allow_own_asn` | inherits the group | the neighbor's, including `0` |
| `replace_peer_asn` | inherits the group | the neighbor's, including `false` |
| `allow_aspath_loop_local` | inherits the group | the neighbor's, including `false` |

Because these are `optional` in the proto, "sent" means the field was set, not
that it was set to something non-zero. A Go client uses
`proto.String("")`, `proto.Bool(false)` or `proto.Uint32(0)` to state a zero
value and leaves the field `nil` to inherit.

**`peer_asn` is the exception.** The peer group owns a member's remote AS
whether or not the member states one, so sending it changes nothing. `type` is
likewise derived from `peer_asn` and `local_asn` after inheritance resolves.

On the read path every field is reported with a value, never `nil`. The
resolved configuration is a fact, and presence describes what a client sent,
not what a peer ended up with. To see where a value came from, use
`gobgp config running --provenance`.

## Changing a peer group later

Editing a peer group applies to the peers already in it, not only to peers
added afterwards. Each member is re-resolved against the new group, and
whatever the member stated for itself is kept:

| the member | the group changes | result |
|------------|-------------------|--------|
| stated nothing for a field | sets a new value | the member follows the group |
| stated its own value | sets a different one | the member keeps its own |

That is the same rule inheritance uses at `AddPeer` time, applied again. What
counts as "stated its own" is described above: for a sub-message block, sending
the block at all; for a `PeerConf` field, setting it.

### Which changes drop the session

A change that alters what this speaker puts in its OPEN message, or the socket
the session runs on, has to rebuild the session. A change that only alters what
is advertised does not, and is applied to the running session instead:

| change | session |
|--------|---------|
| `peer_asn`, `local_asn` | rebuilt |
| `auth_password` | rebuilt (TCP-MD5 is a socket option) |
| `send_software_version` | rebuilt (it is an OPEN capability) |
| `ttl_security`, `ebgp_multihop`, `transport`, `graceful_restart`, `afi_safis` | rebuilt |
| `route_server`, `route_reflector` | rebuilt (see below) |
| `description` | kept |
| `send_community`, `remove_private` | kept, and already-advertised routes are re-sent |
| `timers.hold_time`, `timers.keepalive_interval` | rebuilt (negotiated in the OPEN) |
| `timers.connect_retry`, `timers.idle_hold_time_after_reset` | kept (read live) |
| `bfd` | kept |
| `apply_policy` | kept - route-server clients only; refused on any other peer |

This matters most through a peer group, because one edit runs the same decision
for every member. Renaming a group - changing only its `description` - leaves
every session up.

`route_server` and `route_reflector` change neither the OPEN message nor the
socket, and are rebuilt anyway. `route_server` decides which RIB the peer's
routes live in, and flipping it in place would leave routes already installed
in the wrong one. `route_reflector` is read from a snapshot taken when the
session comes up, so an in-place change would keep deciding ORIGINATOR_ID and
CLUSTER_LIST by the old value until the session happened to flap. Before 1.3.5
a change to either was accepted and did nothing at all.
