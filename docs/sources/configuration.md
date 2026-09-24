# Configuration Example

```toml
[global.config]
    as = 1
    router-id = "1.1.1.1"
    # listen port (by default 179)
    port = 1790
    # to disable listening
    # port = -1

    # listen address list (by default "0.0.0.0" and "::")
    local-address-list = ["192.168.10.1", "2001:db8::1"]

    [global.apply-policy.config]
        import-policy-list = ["policy1"]
        default-import-policy = "reject-route"
        export-policy-list = ["policy2"]
        default-export-policy = "accept-route"

[[rpki-servers]]
    [rpki-servers.config]
        address = "210.173.170.254"
        port = 323

[[bmp-servers]]
    [bmp-servers.config]
        address = "127.0.0.1"
        port = 11019
        route-monitoring-policy = "pre-policy"
        statistics-timeout = 3600

[[vrfs]]
    [vrfs.config]
        name = "vrf1"
        # If id is omitted, automatically assigned.
        id = 1
        rd = "65000:100"
        # Each configuration for import and export RTs;
        # import-rt-list
        # export-rt-list
        # are preferred than both-rt-list.
        both-rt-list = ["65000:100"]

[[mrt-dump]]
    [mrt-dump.config]
        dump-type = "updates"
        file-name = "/tmp/log/2006/01/02.1504.dump"
        dump-interval = 180

[zebra]
    [zebra.config]
        enabled = true
        url = "unix:/var/run/quagga/zserv.api"
        redistribute-route-type-list = ["connect"]
        version = 2  # version used in Quagga on Ubuntu 16.04

[[neighbors]]
    [neighbors.config]
        peer-as = 2
        # To disable AS checking set to 0
        auth-password = "password"
        neighbor-address = "192.168.10.2"
        # override global.config.as value
        local-as = 1000
        remove-private-as = "all"
        # Which community attributes to send to this peer: "standard",
        # "extended", "both" or "none". Omit it to send whatever the path
        # carries, which is what gobgpd does when it is not set.
        #
        # "none" is not literal. Three things survive it, so treat this as a
        # description of configuration rather than a guarantee of effect:
        #
        #  1. Large communities. The OpenConfig enum has no value meaning
        #     "send large", so stripping them would make them unsendable.
        #  2. LLGR_STALE and NO_LLGR. gobgpd stamps LLGR_STALE itself when
        #     re-advertising a stale route, and removing it while still
        #     honouring the capability the peer negotiated would leave that
        #     peer treating stale routes as fresh.
        #  3. Every address family except ipv4/ipv6 unicast and labelled
        #     unicast. In VPN, EVPN, FlowSpec, MUP and VPLS, communities are
        #     protocol payload rather than decoration - the Route Target that
        #     selects a VRF, and every FlowSpec traffic action, are extended
        #     communities. Stripping them would not filter a route, it would
        #     destroy it, and a FlowSpec "discard" rule would arrive as a bare
        #     "accept". There is no per-family form of this setting, so it is
        #     simply ignored for those families; gobgpd logs a warning at
        #     startup when it is set on a peer that has one enabled.
        #
        # It is also ignored entirely for route-server clients, which get no
        # egress attribute transformation at all (RFC 7947).
        #
        # Two consequences worth stating plainly:
        #
        #  - "none" and "extended" strip NO_EXPORT, NO_ADVERTISE and
        #    NO_EXPORT_SUBCONFED, so the receiving AS loses the signal not to
        #    re-export the route. This is how the setting behaves on other
        #    vendors too, but it is a route-leak vector.
        #  - Within unicast, "color" and "encap" extended communities are
        #    stripped along with the rest.
        #
        # Only `gobgp neighbor <addr> adj-out` and the "Advertised" count in
        # `gobgp neighbor <addr>` reflect this filtering. BMP (pre-policy,
        # post-policy and Loc-RIB), MRT, and ListPath on ADJ_OUT with
        # enable_filtered all show the path before per-peer egress processing,
        # so a community can appear there and still not be sent.
        #
        # Changing this on a live peer does not reset the session; gobgpd
        # applies it and soft-resets outbound.
        #send-community = "both"
        # To enable peer group setting, uncomment the following
        #peer-group = "my-peer-group"
        # Force sending Software Version Capability, default: disabled.
        #send-software-version = true
    [neighbors.as-path-options.config]
        allow-own-as = 1
        replace-peer-as = true
    [neighbors.timers.config]
        connect-retry = 5 #unit of measurement is seconds
        hold-time = 9 #unit of measurement is seconds
        keepalive-interval = 3 #unit of measurement is seconds
    [neighbors.transport.config]
        passive-mode = true
        local-address = "192.168.10.1"
        remote-port = 2016
        ip-tos = 192 #DSCP class CS6
    [neighbors.ebgp-multihop.config]
        enabled = true #directly connection should be set false，if not ，peer will be deleted after hold-time
        multihop-ttl = 100
    # To make this neighbor a route-reflector client, uncomment the following.
    # Please note that this is mutually exclusive with
    # "neighbors.route-server.config" below.
    #[neighbors.route-reflector.config]
    #    route-reflector-client = true
    #    route-reflector-cluster-id = "192.168.0.1"
    [neighbors.add-paths.config]
        send-max = 8
        receive = true
    [neighbors.graceful-restart.config]
        enabled = true
        notification-enabled = true
        long-lived-enabled = true
        # graceful restart restart time
        restart-time = 20
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-unicast"
        [neighbors.afi-safis.prefix-limit.config]
           max-prefixes = 1000
           shutdown-threshold-pct = 80
        [neighbors.afi-safis.mp-graceful-restart.config]
           enabled = true
        [neighbors.afi-safis.long-lived-graceful-restart.config]
           enabled = true
           # long lived graceful restart restart time
           restart-time = 100000
        [neighbors.afi-safis.add-paths.config]
           # override neighbors.add-paths.config
           receive = true
           send-max = 8
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-labelled-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-labelled-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l3vpn-ipv4-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l3vpn-ipv6-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l2vpn-evpn"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l2vpn-vpls"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "rtc"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-encap"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-encap"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-flowspec"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-flowspec"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-mup"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-mup"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "opaque"
    [neighbors.apply-policy.config]
        import-policy-list = ["policy1"]
        default-import-policy = "reject-route"
        export-policy-list = ["policy2"]
        default-export-policy = "accept-route"
    [neighbors.route-server.config]
        route-server-client = true
    # To enable TTL Security, uncomment the following.
    # Please note that this feature is mutually exclusive with
    # "neighbors.ebgp-multihop.config".
    #[neighbors.ttl-security.config]
    #    enabled = true
    #    ttl-min = 255  # 255 means directly connected

[[neighbors]]
    [neighbors.config]
        peer-group = "my-peer-group"
        neighbor-address = "127.0.0.2"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "my-peer-group"
    peer-as = 65000
    send-software-version = true
  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix = "20.0.0.0/24"
    peer-group = "my-peer-group"

[[defined-sets.prefix-sets]]
    prefix-set-name = "ps0"
    [[defined-sets.prefix-sets.prefix-list]]
        ip-prefix = "10.0.0.0/8"
        masklength-range = "24..32"
[[defined-sets.neighbor-sets]]
   neighbor-set-name = "ns0"
   neighbor-info-list = ["192.168.10.2", "172.13.0.0/24"]
[[defined-sets.bgp-defined-sets.community-sets]]
    community-set-name = "cs0"
    community-list = ["100:100"]
[[defined-sets.bgp-defined-sets.ext-community-sets]]
    ext-community-set-name = "es0"
    ext-community-list = ["rt:100:100", "soo:200:200"]
[[defined-sets.bgp-defined-sets.as-path-sets]]
    as-path-set-name = "as0"
    as-path-list = ["^100", "200$"]
[[defined-sets.bgp-defined-sets.large-community-sets]]
    large-community-set-name = "ls0"
    large-community-list = ["100:100:100", "200:200:200"]

[[policy-definitions]]
    name = "policy1"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.match-prefix-set]
            prefix-set = "ps0"
            match-set-options = "any"
        [policy-definitions.statements.conditions.match-neighbor-set]
            neighbor-set = "ns0"
            match-set-options = "invert"
        [policy-definitions.statements.conditions.bgp-conditions.match-community-set]
            community-set = "cs0"
            match-set-options = "all"
        [policy-definitions.statements.conditions.bgp-conditions.match-large-community-set]
            large-community-set = "ls0"
            match-set-options = "all"
        [policy-definitions.statements.actions.bgp-actions.set-as-path-prepend]
            as = "last-as"
            repeat-n = 5
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions.match-ext-community-set]
            ext-community-set = "es0"
        [policy-definitions.statements.actions]
            route-disposition = "reject-route"

[[policy-definitions]]
    name = "policy2"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]
            as-path-set = "as0"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-community]
            options = "add"
            [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]
                communities-list = ["100:200"]

[[policy-definitions]]
    name = "policy3"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]
            as-path-set = "as0"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-community]
            options = "add"
            [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]
                communities-list = ["100:200"]
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.match-prefix-set]
            prefix-set = "ps0"
            match-set-options = "invert"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-ext-community]
            options = "replace"
            [policy-definitions.statements.actions.bgp-actions.set-ext-community.set-ext-community-method]
                communities-list = ["soo:100:200", "rt:300:400"]
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.match-neighbor-set]
            neighbor-set = "ns0"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-ext-community]
            options = "remove"
            [policy-definitions.statements.actions.bgp-actions.set-ext-community.set-ext-community-method]
                communities-list = ["soo:500:600", "rt:700:800"]
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions]
            next-hop-in-list = [
               "10.0.100.1"
            ]
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"

[[policy-definitions]]
    name = "route-type-policy"
    [[policy-definitions.statements]]
        # this statement matches with locally generated routes
        [policy-definitions.statements.conditions.bgp-conditions]
            route-type = "local"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
    [[policy-definitions.statements]]
        # this statement matches with routes from iBGP peers
        [policy-definitions.statements.conditions.bgp-conditions]
            route-type = "internal"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
    [[policy-definitions.statements]]
        # this statement matches with routes from eBGP peers
        [policy-definitions.statements.conditions.bgp-conditions]
            route-type = "external"
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"

[[policy-definitions]]
    name = "large-communty-policy"
    [[policy-definitions.statements]]
        # this statement adds specified large communities
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-large-community]
            options = "add"
            [policy-definitions.statements.actions.bgp-actions.set-large-community.set-large-community-method]
                communities-list = ["100:200:300"]
    [[policy-definitions.statements]]
        # this statement adds specified large communities
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-large-community]
            options = "replace"
            [policy-definitions.statements.actions.bgp-actions.set-large-community.set-large-community-method]
                communities-list = ["100:200:300"]
    [[policy-definitions.statements]]
        # this statement removes specified large communities
        # regular expression is also supported
        [policy-definitions.statements.actions]
            route-disposition = "accept-route"
        [policy-definitions.statements.actions.bgp-actions.set-large-community]
            options = "remove"
            [policy-definitions.statements.actions.bgp-actions.set-large-community.set-large-community-method]
                communities-list = ["100:200:300", "^200:"]

# Linux Netlink Integration (Linux-only)

# Import routes from Linux interfaces into GoBGP
[netlink]
  [netlink.import]
    enabled = true
    interface-list = ["eth0", "eth1"]

  # Export BGP routes to Linux routing tables
  [netlink.export]
    enabled = true
    route-protocol = 201
    dampening-interval = 1000

# Export to global routing table
[[netlink.export.rules]]
  name = "default-export"
  vrf = ""
  table-id = 0
  metric = 100
  skip-nexthop-validation = false
  community-list = []

# Per-VRF netlink import/export
[[vrfs]]
  [vrfs.config]
    name = "vrf-customer1"
    rd = "64512:100"
    import-rt-list = ["64512:100"]
    export-rt-list = ["64512:100"]

  # Import from Linux VRF interfaces
  [vrfs.netlink-import]
    enabled = true
    interface-list = ["eth2", "eth3"]

  # Export to Linux VRF routing table
  [vrfs.netlink-export]
    enabled = true
    linux-vrf = "vrf-customer1"
    linux-table-id = 100
    metric = 50
    skip-nexthop-validation = true
    community-list = []
```

See [Netlink Integration](netlink.md) for detailed documentation.

## Peer-group inheritance

A neighbor in a peer group keeps every setting it configures and takes the rest
from the group. That is per field, not per block: setting one field of
`[neighbors.bfd.config]` does not stop the other BFD fields coming from the
group.

What decides "configured" is whether the setting was *present* in the
configuration, not whether its value differs from zero. That distinction is the
whole point, because most of these blocks carry their enable flag as a boolean:

```toml
[[neighbors]]
  [neighbors.config]
    neighbor-address = "127.0.0.3"
    peer-group = "my-peer-group"   # suppose the group enables graceful restart
  [neighbors.graceful-restart.config]
    enabled = false                # this peer turns it off, and stays off
```

The same applies over the gRPC API, where presence is per *message*: a request
that includes a block owns all of it, including the fields left at their zero
values, and a request that omits a block inherits it. Sending an empty block is
therefore an explicit "none of this".

The practical consequence for an API client is that a partially populated block
no longer inherits its remaining fields from the group. If a client sends
`graceful_restart` with only `enabled` and `restart_time` set, the peer's
`stale_routes_time` is zero rather than the group's.

`gobgp config running --provenance` reports which blocks a peer inherited and
from where, since the running configuration otherwise shows a value that was
set and one that was inherited identically.

## Global graceful restart

`[global.graceful-restart]` does not reach peers unless you ask for it. Add to
the `[global.config]` block above:

```text
graceful-restart-inherit-to-neighbors = true
```

Without it the global block is accepted and reported and does nothing, which is
what it has always done. It is opt-in rather than simply fixed because turning
it on changes forwarding behaviour: once graceful restart is negotiated, the
upstream router keeps this speaker's routes for `restart-time` - defaulted from
the hold time, so 90 seconds - instead of withdrawing them when the session
drops. For a speaker announcing service addresses that delays failover by that
long, and it only becomes visible on the restart *after* the one that enables
it.

Precedence is the neighbor, then its peer group, then this.

`long-lived-enabled` is not propagated, because the per-family long-lived flag
is not derived from it and the capability would go out carrying no families.
Since it could never take effect, gobgpd refuses it on the global block - over
the API and in a config file - rather than accept it and do nothing. Set it per
neighbor or peer group.

## Multipath

Multipath is global. It selects every path that ties with the best one, up to a
limit per peer type, and both advertises the set and - with netlink export -
installs it into the kernel as one route with a nexthop per path.

```toml
[global.use-multiple-paths.config]
  enabled = true
[global.use-multiple-paths.ebgp.config]
  maximum-paths = 4
[global.use-multiple-paths.ibgp.config]
  maximum-paths = 2
```

The limit is chosen from the best path: a best path learned over eBGP selects
up to the eBGP limit, one learned over iBGP up to the iBGP limit. A type with no
limit gets the single best path. Locally originated best paths are not capped.

| configuration | eBGP | iBGP |
|---|---|---|
| `ebgp maximum-paths = 4` only | up to 4 paths | best path only |
| `ibgp maximum-paths = 2` only | best path only | up to 2 paths |
| both set | up to 4 | up to 2 |
| `enabled = true`, neither set | refused at startup | |

`enabled = true` with neither limit is refused, because it would select nothing
the daemon does not select already. A configuration that enabled multipath
before 1.3.5 had no limit and must add one.

The limits are read at startup; changing them, like any global setting, needs
a restart - a reload logs an error naming the setting and applies the rest.

Over the API they are `Global.ebgp_maximum_paths` and
`Global.ibgp_maximum_paths`. `use-multiple-paths` exists only here: the
per-neighbor, per-peer-group and per-address-family blocks were removed in
1.3.5, since the RIB never read them.

## Settings gobgpd fills in for you

gobgpd applies defaults to a peer and then reports the *resolved* values, so
`ListPeer` and `gobgp config running` show fields the configuration never set.
A controller that compares what it sent against what is reported will see a
difference on every poll for each of these unless it expects them.

| field | default |
|---|---|
| `timers.config.connect-retry` | 120 |
| `timers.config.hold-time` | 90 |
| `timers.config.keepalive-interval` | hold-time / 3 |
| `timers.config.idle-hold-time-after-reset` | 30 |
| `config.local-as` | the global AS, or the confederation member AS |
| `config.peer-type` | derived from peer-as against local-as |
| `graceful-restart.config.restart-time` | the hold time, when graceful restart is enabled |
| `graceful-restart.config.deferral-time` | 360, when graceful restart is enabled |
| `ebgp-multihop.config.multihop-ttl` | 255, when ebgp-multihop is enabled |
| `ttl-security.config.ttl-min` | 255, when ttl-security is enabled |
| `bfd.config.port` | 3784, when BFD is enabled |
| `bfd.config.detection-multiplier` | 3, when BFD is enabled |
| `bfd.config.desired-minimum-tx-interval` | 1000000 (1s, microseconds), when BFD is enabled |
| `bfd.config.required-minimum-receive` | 1000000 (1s, microseconds), when BFD is enabled |

The as-path options are reported slightly differently and belong in the same
list. `allow-own-as`, `replace-peer-as` and `allow-aspath-loop-local` carry
explicit presence on the API, so a client can leave them unstated and inherit
them from a peer group. The read path always reports all three, because a
running configuration is what is in force rather than what was typed - so a
client that stated none of them still gets three values back. There is no
information lost either way: for these three, "not stated" and "0 or false"
have the same effect.

Per-family settings are derived from the neighbor's too, which is what makes a
capability carry families rather than going out empty:

| field | derived from |
|---|---|
| `afi-safis.mp-graceful-restart.config.enabled` | `graceful-restart.config.enabled` |
| `afi-safis.long-lived-graceful-restart.config.enabled` | `graceful-restart.config.long-lived-enabled` |
| `afi-safis.add-paths.config.receive` / `send-max` | the neighbor's `add-paths` block |

Two ways to avoid the spurious diff: send these fields explicitly with the
values you want, so the report matches; or exclude them from the comparison.
`gobgp config running --provenance` distinguishes what was inherited from a
peer group or the global block, but not what came from a default - a field
absent from that report and present in the output is a default.
