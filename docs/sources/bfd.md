# BFD

BFD (Bidirectional Forwarding Detection) is a protocol for fast liveness
detection between two network systems. In BGP deployments, it is commonly used
to detect neighbor failures faster than regular BGP hold timers.

Both sides periodically exchange small BFD control packets. If one side stops
receiving packets for the configured detection time, the BFD session goes down
and the routing protocol can react immediately.

GoBGP implements BFD for BGP neighbors using the basic control packet model from
[RFC 5880](https://datatracker.ietf.org/doc/html/rfc5880) and single-hop UDP
transport from [RFC 5881](https://datatracker.ietf.org/doc/html/rfc5881).

## Supported Features

GoBGP has an native BFD implementation scoped to fast BGP peer failure
detection. It is intended to cover single-hop asynchronous BFD for BGP
neighbors, not to replace a full-featured standalone BFD daemon.

Supported behavior:

- asynchronous BFD control packets over UDP;
- per-neighbor BFD configuration;
- peer-group BFD configuration inherited by neighbors;
- default destination UDP port `3784`;
- source UDP port selected from the RFC 5881 dynamic range `49152..65535`;
- outgoing BFD packets sent with TTL/Hop Limit `255`;
- BFD states `DOWN`, `INIT`, `UP`, and `ADMIN_DOWN`;
- Poll/Final handling in control packets;
- hard BGP peer reset when the BFD session expires or the remote peer signals
  `DOWN`;
- BFD configuration through the GoBGP config file and gRPC API;
- BFD state in peer state returned by the API.

Current scope and limitations:

- BFD authentication, echo mode, demand mode, and other advanced BFD features
  are out of scope for this implementation;
- remote interval negotiation is limited: GoBGP sends the configured intervals,
  but currently does not adjust local timers from the peer's advertised
  `DesiredMinTxInterval` or `RequiredMinRxInterval`.

## Configuration

BFD is disabled by default. Enable it under `[neighbors.bfd.config]`.

Intervals are configured in microseconds.

```toml
[global.config]
  as = 65001
  router-id = "192.0.2.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65002

  [neighbors.bfd.config]
    enabled = true
    desired-minimum-tx-interval = 300000
    required-minimum-receive = 300000
    detection-multiplier = 3
```

With this example, GoBGP sends BFD control packets roughly every `300 ms`.
The local detection time is:

```text
required-minimum-receive * detection-multiplier
```

So `300000 * 3` gives about `900 ms`.

If BFD timer values are omitted, GoBGP uses these defaults:

| Option | Default | Unit |
| --- | ---: | --- |
| `enabled` | `false` | boolean |
| `port` | `3784` | UDP port |
| `desired-minimum-tx-interval` | `1000000` | microseconds |
| `required-minimum-receive` | `1000000` | microseconds |
| `detection-multiplier` | `3` | multiplier |

## Peer Groups

BFD can be configured once on a peer group and inherited by all neighbors in
that group.

```toml
[global.config]
  as = 65001
  router-id = "192.0.2.1"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "edge"
    peer-as = 65002

  [peer-groups.bfd.config]
    enabled = true
    desired-minimum-tx-interval = 300000
    required-minimum-receive = 300000
    detection-multiplier = 3

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-group = "edge"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.3"
    peer-group = "edge"
```

A neighbor can override BFD values inherited from its peer group by setting its
own fields under `[neighbors.bfd.config]`.

## Port Behavior

By default, BFD control packets are sent to UDP destination port `3784`.

```toml
[neighbors.bfd.config]
  enabled = true
  port = 3784
```

Use the default unless the remote system explicitly requires another destination
port. RFC 5881 specifies `3784` for single-hop BFD. In GoBGP, the local BFD
server still listens on UDP `3784`; changing `port` only changes the remote
destination port used by outgoing packets.

For firewalls and ACLs, allow:

- inbound UDP `3784` to the GoBGP host;
- outbound UDP from an ephemeral source port in `49152..65535` to the peer's
  BFD destination port, normally `3784`;
- the reverse direction on the peer.

The remote BGP speaker must also run BFD and must be configured with compatible
timers. Enabling BFD only on one side is not enough to bring the BFD session up.

## Runtime Behavior

When BFD is enabled for a neighbor, GoBGP creates a BFD peer for the neighbor
address. If the BFD session expires, or if the remote side signals `DOWN`,
GoBGP performs a hard reset of the corresponding BGP peer with the communication
string `BFD is down`.

Changing BFD configuration through `UpdatePeer` is applied at runtime:

- enabling BFD adds the BFD peer;
- disabling BFD removes the BFD peer;
- changing BFD timer or port settings recreates the BFD peer with the new
  configuration.

## Checking State

`gobgp neighbor <address>` prints a BFD section for every peer, including a
`not configured` line when BFD is off, so the absence of a session is always an
explicit answer rather than a missing section.

```bash
$ gobgp neighbor 192.0.2.2
...
  BFD: enabled, session UP
    Intervals: tx 300ms, rx 300ms, multiplier 3 (detect 900ms), port 3784
    Packets: tx 4133, rx 4722, failure transitions 0
```

`gobgp bfd` summarises every BFD-enabled peer and the server's receive-path
counters:

```bash
$ gobgp bfd
Peer                             State  Tx         Rx         Transitions
192.0.2.2                        UP     4133       4722       0

Server: rx 8859  drop 0  error 0  invalid 0  unknown-peer 0
```

Two of those server counters diagnose failures that are otherwise silent:

- `unknown-peer` counts control packets received from an address with no
  configured peer. It advances when a link-local neighbor is configured without
  its zone: packets arrive from `fe80::1%eth0`, the configured key is `fe80::1`,
  and the receive lookup cannot match. If the peer also sets a bind interface,
  transmission still succeeds, so BGP stays up and only the BFD session is dead.
- `drop` counts packets discarded because a peer's receive queue was full. That
  queue holds one packet, so any advance means an event loop stalled for longer
  than one transmit interval.

Intervals are printed as durations because they are configured in
**microseconds**: `300` means 300 microseconds, not 300 milliseconds.

All ten `BfdPeerState` fields are populated: the local and remote session
states, both diagnostic codes, both discriminators, the remote receive interval,
the last failure time, the failure count and the packet counters.
`failure_transitions` counts sessions going from up to down, so a session that
has never come up does not increment it, and `local_diagnostic_code` reports why
this end last declared the session down.

### JSON output

`-j` returns the raw `ListPeer` fields:

```bash
$ gobgp -j neighbor 192.0.2.2
```

Relevant fields:

- `bfd`: configured BFD values for the peer;
- `state.bfd_state.session_state`: current local BFD session state;
- `state.bfd_state.bfd_async.transmitted_packets`: sent BFD control packets;
- `state.bfd_state.bfd_async.received_packets`: received BFD control packets.

Note that `-j` uses Go's JSON encoder rather than protojson, so enums appear as
**numbers**, and this proto numbers `BFD_SESSION_STATE_UP` as `1`. RFC 5880
§6.8.1 numbers `Down` as 1 and `Up` as 3, so the raw value reads as the opposite
of its meaning to anyone familiar with the protocol. Prefer the text output,
which prints the state as a word.

```json
{
  "conf": {
    "neighbor_address": "192.0.2.2",
    "peer_asn": 65002
  },
  "bfd": {
    "enabled": true,
    "port": 3784,
    "desired_minimum_tx_interval": 300000,
    "required_minimum_receive": 300000,
    "detection_multiplier": 3
  },
  "state": {
    "bfd_state": {
      "session_state": 1,
      "bfd_async": {
        "transmitted_packets": 100,
        "received_packets": 99
      }
    }
  }
}
```

## Metrics

BFD exports the following Prometheus series:

| Metric | Description |
| --- | --- |
| `bgp_peer_bfd_enabled` | Whether BFD is configured for the peer. Emitted for every peer. |
| `bgp_peer_bfd_state` | Session state, as the `session_state` label. Always 1. |
| `bgp_peer_bfd_transmitted_packets_total` | Control packets sent to the peer. |
| `bgp_peer_bfd_received_packets_total` | Control packets received from the peer. |
| `bgp_peer_bfd_failure_transitions_total` | Times the session went up to down. |
| `bgp_bfd_received_packet_total` | Packets received and matched to a peer. |
| `bgp_bfd_received_drop_total` | Packets dropped because a peer queue was full. |
| `bgp_bfd_received_error_total` | Errors reading from the BFD server socket. |
| `bgp_bfd_invalid_packet_total` | Datagrams that would not decode. |
| `bgp_bfd_unknown_peer_total` | Packets from an address with no configured peer. |
| `bgp_bfd_wrong_hop_limit_total` | Packets discarded for a TTL/hop limit other than 255 (RFC 5881 §5). |
| `bgp_bfd_server_up` | Whether the BFD socket is bound. Zero while peers have BFD enabled means no detection is happening. |

A session that is configured but never comes up is expressible as:

```text
bgp_peer_bfd_enabled == 1
  unless on(peer) bgp_peer_bfd_state{session_state="BFD_SESSION_STATE_UP"}
```

`bgp_peer_bfd_enabled` is emitted for peers with BFD disabled as well, so this
alert compares two present series rather than depending on one being absent.

## gRPC API

The gRPC `Peer` and `PeerGroup` messages include `BfdPeerConfig bfd`.

```protobuf
message BfdPeerConfig {
  bool enabled = 1;
  uint32 port = 2;
  uint32 desired_minimum_tx_interval = 3;
  uint32 required_minimum_receive = 4;
  uint32 detection_multiplier = 5;
}
```

For example, when adding or updating a peer:

```go
peer := &api.Peer{
    Conf: &api.PeerConf{
        NeighborAddress: "192.0.2.2",
        PeerAsn:         65002,
    },
    Bfd: &api.BfdPeerConfig{
        Enabled:                  true,
        Port:                     3784,
        DesiredMinimumTxInterval: 300000,
        RequiredMinimumReceive:   300000,
        DetectionMultiplier:      3,
    },
}
```

`ListPeer` returns peer state with `state.bfd_state`.

`GetBfdServerState` returns the BFD server's receive-path counters, which are
server-wide rather than per-peer:

```protobuf
rpc GetBfdServerState(GetBfdServerStateRequest) returns (GetBfdServerStateResponse);

message GetBfdServerStateResponse {
  BfdState state = 1;
}

message BfdState {
  uint64 received_packet = 1;
  uint64 received_drop = 2;
  uint64 received_error = 3;
  uint64 invalid_packet = 4;
  uint64 unknown_peer = 5;
}
```

`unknown_peer` is the counter to reach for when a session will not come up: it
counts packets that arrived for an address with no configured peer, which no
other API reports and which the daemon logs only at DEBUG.

## Privileges

### CAP_NET_RAW

Binding a BFD session to an interface uses `SO_BINDTODEVICE`, which requires
`CAP_NET_RAW`. Interface binding is exactly the unnumbered link-local case, so a
deployment that drops that capability will find those sessions cannot bind.

Worth stating explicitly because the capability looks unused while BFD is
disabled, and is easy to drop on that basis.

### Hop limit validation

Control packets are sent with TTL / hop limit 255 as RFC 5881 §5 requires, and
received packets carrying any other value are discarded. The receive check needs
the kernel to report each datagram's TTL, via `IP_RECVTTL` and
`IPV6_RECVHOPLIMIT`. Where that cannot be enabled the server logs a warning and
continues **without** the check rather than dropping every packet; the
`bgp_bfd_wrong_hop_limit_total` metric counts what it does discard.

## Troubleshooting

If the BFD session does not come up:

- verify that both GoBGP and the remote peer have BFD enabled for the same
  neighbor address;
- verify that UDP `3784` is reachable in both directions;
- verify that the remote system accepts source ports from `49152..65535`;
- avoid setting a non-default `port` unless the remote peer is known to listen
  there;
- give a link-local neighbor address its zone (`fe80::1%eth0`). Without it the
  receive lookup cannot match the zoned address the kernel reports, so the
  session stays down. If the peer also sets a bind interface, transmit still
  works and BGP stays up, which makes this failure look like success;
- run `gobgp bfd` and compare the per-peer `Tx` and `Rx` columns. Tx advancing
  while Rx stays flat means the packets are leaving but the replies are not
  being matched to this peer; check `unknown-peer` in the same output;
- capture traffic and confirm that BFD control packets are being exchanged.

```bash
$ tcpdump -ni any udp port 3784
```

For production use, choose intervals conservatively. Very aggressive BFD timers
can cause unnecessary BGP resets during CPU pressure, packet loss, or control
plane congestion.
