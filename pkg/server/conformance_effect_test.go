// Copyright (C) 2026 Acnodal Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// API conformance: does the setting actually do anything?
//
// This is the layer the other two cannot reach. Round-trip proves the daemon
// remembers a value; boundary proves it remembers it accurately. Neither proves
// the value changes what goes on the wire.
//
// send_community is the cautionary case. For the whole of gobgp's history it
// was accepted by the TOML loader, stored in NeighborConfig, and read by
// nothing. Mid-way through fixing it, after the converters were wired but
// before the egress filter existed, it round-tripped perfectly through
// AddPeer/ListPeer and still did absolutely nothing. Both other layers would
// have passed it.
//
// So: two daemons, a real session, and an assertion about what the receiver
// sees in its adjacency RIB.
//
// wireEffectFields below is the registry. A per-peer setting that changes what
// is advertised belongs in it, and the meta-test requires each entry to name a
// test that exists. Adding an egress knob without an effect test fails the
// build - which is the specific hole send_community fell through.
package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// wireEffectFields maps a per-peer setting that changes what is advertised to
// the test that proves it does.
//
// The value is the test function itself, not its name: a registry that names a
// test cannot tell you the test was deleted, whereas this one does not compile.
var wireEffectFields = map[string]func(*testing.T){
	"PeerConf.send_community":   TestEffectSendCommunity,
	"PeerConf.remove_private":   TestEffectRemovePrivateAs,
	"PeerConf.replace_peer_asn": TestEffectReplacePeerAsn,
}

// noWireEffect is the other half: fields that legitimately do not change what
// is advertised, each with the reason. Between the two maps every PeerConf
// field is accounted for, and TestEveryPeerConfFieldIsClassified fails when a
// new one appears in neither.
//
// That is the check that would have caught send_community. It was a field
// nobody had classified, so nobody noticed it did nothing.
var noWireEffect = map[string]string{
	"PeerConf.auth_password":           "TCP-MD5 on the socket, not a path attribute",
	"PeerConf.description":             "operator annotation",
	"PeerConf.local_asn":               "session identity; covered by AS_PATH assertions in the transform tests",
	"PeerConf.neighbor_address":        "session identity",
	"PeerConf.peer_asn":                "session identity",
	"PeerConf.peer_group":              "inheritance mechanism; the inherited fields carry the effect",
	"PeerConf.type":                    "derived from the ASNs, not an input",
	"PeerConf.neighbor_interface":      "transport selection, not a path attribute",
	"PeerConf.vrf":                     "table selection; VRF import/export is covered by the RTC and VRF tests",
	"PeerConf.allow_own_asn":           "ingress acceptance, not egress: it decides what we take, not what we send",
	"PeerConf.admin_down":              "session administrative state",
	"PeerConf.send_software_version":   "OPEN message capability, not a path attribute",
	"PeerConf.allow_aspath_loop_local": "ingress acceptance, as with allow_own_asn",
}

// effectPeers brings up a real session between two in-process daemons and
// returns them. a advertises; b receives and is inspected.
func effectPeers(t *testing.T, port int, confA *api.PeerConf) (a, b *BgpServer) {
	t.Helper()

	a = NewBgpServer()
	go a.Serve()
	require.NoError(t, a.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: int32(port)},
	}))
	t.Cleanup(func() { a.StopBgp(context.Background(), &api.StopBgpRequest{}) }) //nolint:errcheck

	confA.NeighborAddress = "127.0.0.1"
	confA.PeerAsn = 65002
	require.NoError(t, a.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      confA,
		Transport: &api.Transport{PassiveMode: true},
	}}))

	b = NewBgpServer()
	go b.Serve()
	require.NoError(t, b.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65002, RouterId: "2.2.2.2", ListenPort: -1},
	}))
	t.Cleanup(func() { b.StopBgp(context.Background(), &api.StopBgpRequest{}) }) //nolint:errcheck

	waiter := newPeerStateWaiter(a, api.PeerState_SESSION_STATE_ESTABLISHED)
	require.NoError(t, b.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{RemotePort: uint32(port)},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
	}}))
	waiter.Wait(t, 30*time.Second)
	return a, b
}

// advertise originates a prefix carrying both community types, plus any extra
// attributes a particular transform needs to have something to act on.
func advertise(t *testing.T, a *BgpServer, prefix string, extra ...bgp.PathAttributeInterface) {
	t.Helper()
	rt, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	require.NoError(t, err)
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
	require.NoError(t, err)

	_, err = a.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: bgp.RF_IPv4_UC,
		Nlri:   nlri,
		Attrs: append([]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			nexthop,
			bgp.NewPathAttributeCommunities([]uint32{65000<<16 | 1}),
			bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
		}, extra...),
	}}})
	require.NoError(t, err)
	time.Sleep(1500 * time.Millisecond)
}

// received reports what arrived in b's adjacency RIB for a prefix.
type received struct {
	found  bool
	std    bool
	ext    bool
	asPath []uint32
}

func (r received) String() string {
	if !r.found {
		return "route ABSENT"
	}
	return fmt.Sprintf("std=%v ext=%v as_path=%v", r.std, r.ext, r.asPath)
}

func adjInOf(t *testing.T, b *BgpServer, prefix string) received {
	t.Helper()
	var out received
	require.NoError(t, b.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_ADJ_IN,
		Family:    bgp.RF_IPv4_UC,
		Name:      "127.0.0.1",
	}, func(p bgp.NLRI, paths []*apiutil.Path) {
		if p.String() != prefix {
			return
		}
		out.found = true
		for _, path := range paths {
			for _, attr := range path.Attrs {
				switch v := attr.(type) {
				case *bgp.PathAttributeCommunities:
					out.std = true
				case *bgp.PathAttributeExtendedCommunities:
					out.ext = true
				case *bgp.PathAttributeAsPath:
					for _, param := range v.Value {
						out.asPath = append(out.asPath, param.GetAS()...)
					}
				}
			}
		}
	}))
	return out
}

func TestEffectSendCommunity(t *testing.T) {
	const prefix = "10.60.0.0/24"
	none := uint32(3) // COMMUNITY_TYPE_NONE
	a, b := effectPeers(t, 10601, &api.PeerConf{SendCommunity: &none})
	advertise(t, a, prefix)

	got := adjInOf(t, b, prefix)
	require.True(t, got.found, "the route must reach the peer at all")
	assert.False(t, got.std, "send_community=none must strip standard communities: %s", got)
	assert.False(t, got.ext, "send_community=none must strip extended communities: %s", got)
}

func TestEffectSendCommunityUnsetSendsEverything(t *testing.T) {
	const prefix = "10.61.0.0/24"
	a, b := effectPeers(t, 10611, &api.PeerConf{})
	advertise(t, a, prefix)

	got := adjInOf(t, b, prefix)
	require.True(t, got.found)
	assert.True(t, got.std, "unset must not filter: %s", got)
	assert.True(t, got.ext, "unset must not filter: %s", got)
}

func TestEffectRemovePrivateAs(t *testing.T) {
	const prefix = "10.62.0.0/24"
	a, b := effectPeers(t, 10621, &api.PeerConf{
		RemovePrivate: api.RemovePrivate_REMOVE_PRIVATE_ALL.Enum(),
	})
	advertise(t, a, prefix)

	got := adjInOf(t, b, prefix)
	require.True(t, got.found, "the route must reach the peer at all")
	// 65001 is the sender's own public ASN and is prepended on egress; the point
	// is that no private ASN survives.
	for _, asn := range got.asPath {
		assert.False(t, asn >= 64512 && asn <= 65534 && asn != 65001,
			"remove_private=all left a private ASN in the AS_PATH: %s", got)
	}
}

func TestEffectReplacePeerAsn(t *testing.T) {
	const prefix = "10.63.0.0/24"
	a, b := effectPeers(t, 10631, &api.PeerConf{ReplacePeerAsn: proto.Bool(true)})

	// replace-peer-as is loop prevention: when advertising toward peer 65002,
	// any 65002 already in the AS_PATH is replaced with our own ASN so the peer
	// does not discard the route as a loop. A locally-originated route has an
	// empty AS_PATH and nothing to replace, so the peer's ASN has to be put
	// there deliberately for the transform to have any work to do.
	advertise(t, a, prefix, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65002, 65100}),
	}))

	got := adjInOf(t, b, prefix)
	require.True(t, got.found, "the route must reach the peer at all")
	assert.NotContains(t, got.asPath, uint32(65002),
		"replace_peer_asn must remove the peer's own ASN from the AS_PATH: %s", got)
	assert.Contains(t, got.asPath, uint32(65001),
		"replace_peer_asn must substitute our ASN in its place: %s", got)
	assert.Contains(t, got.asPath, uint32(65100),
		"other ASNs must be left alone: %s", got)
}

// The classification check. Every PeerConf field must be either proven to have
// a wire effect or recorded as having none, with a reason.
//
// send_community sat outside both categories for gobgp's entire history: a
// field nobody had classified, so nobody noticed it did nothing.
func TestEveryPeerConfFieldIsClassified(t *testing.T) {
	fields := (&api.PeerConf{}).ProtoReflect().Descriptor().Fields()
	for i := range fields.Len() {
		name := "PeerConf." + string(fields.Get(i).Name())
		_, proven := wireEffectFields[name]
		_, exempt := noWireEffect[name]
		assert.True(t, proven || exempt,
			"%s is classified neither as having a wire effect (with a test) nor as having none (with a reason). "+
				"Decide which, and if it affects what is advertised, write the effect test - "+
				"round-trip and boundary tests both pass a setting that does nothing.", name)
		assert.False(t, proven && exempt, "%s is in both maps", name)
	}
}

// PeerConf is only part of a peer. Everything else a peer carries lives in a
// sub-message of api.Peer - graceful_restart, transport, timers, ttl_security
// and the rest - and none of it was classified at all, so a setting there could
// be accepted, reported, and do nothing with no test objecting.
//
// That is not hypothetical. graceful_restart is a sub-message, and a peer in a
// peer group came up with it silently off for the whole life of the feature.
// The per-field classification above could never have caught it, twice over:
// the field is not in PeerConf, and the defect needs two objects to exist.
//
// This classifies the sub-messages themselves rather than their fields.
// Per-field would be better, but it would be a registry of several hundred
// entries written in one sitting, which is how a registry becomes a rubber
// stamp. Block-level makes the question "has anyone checked this part of a peer
// does anything, and at this scope" answerable, and a new sub-message cannot
// appear without someone answering it.
var peerBlockEffects = map[string]string{
	"conf":             "classified field by field above",
	"state":            "read-only operational state",
	"timers":           "hold time and keepalive reach the OPEN; covered by the scenario tests",
	"transport":        "local address, passive mode and TCP options reach the socket",
	"route_reflector":  "cluster id and client status change reflection; covered by the rr scenario test",
	"route_server":     "decides which RIB the peer's routes enter, and whether they reach the kernel FIB",
	"graceful_restart": "reaches the GR capability in the OPEN, per family; TestGracefulRestartSurvivesPeerGroupMembership and the oc inheritance matrix",
	"apply_policy":     "import and export policy; covered by the policy scenario tests",
	"ebgp_multihop":    "sets the TTL on the socket",
	"ttl_security":     "sets IP_MINTTL on the socket (GTSM)",
	"afi_safis":        "decides which families are negotiated at all",
	"bfd":              "drives the BFD session; covered by bfd_server_test.go",
}

func TestEveryPeerBlockIsClassified(t *testing.T) {
	fields := (&api.Peer{}).ProtoReflect().Descriptor().Fields()
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		_, ok := peerBlockEffects[name]
		assert.True(t, ok,
			"api.Peer.%s is not classified. Say what it changes on the wire and which test proves it, "+
				"or say it changes nothing and why. A setting that round-trips and does nothing passes "+
				"every other layer of this suite - that is how graceful_restart stayed broken.", name)
	}
}

// Scope is the other half. A setting can work at one level and be inert at
// another, which no per-field check sees because the field itself round-trips
// perfectly at the level where it works.
//
// stale_routes_time is the example: implemented and acted on per peer and per
// peer group, and for the whole of v1.3.2 accepted, echoed and inert at the
// global level. The conformance suite's own comment described it backwards.
var settingsWithScope = map[string][]string{
	"graceful_restart.enabled":            {"peer", "peer-group", "global-opt-in"},
	"graceful_restart.stale_routes_time":  {"peer", "peer-group"},
	"graceful_restart.long_lived_enabled": {"peer", "peer-group"},
}

func TestScopedSettingsAreRecorded(t *testing.T) {
	// A registry, not a behavioural check: the point is that the levels a
	// setting works at are written down where the next person will look,
	// because "it works" is not a property of a setting on its own.
	for name, scopes := range settingsWithScope {
		assert.NotEmpty(t, scopes, "%s must name the scopes it is implemented at", name)
	}
	assert.Contains(t, settingsWithScope["graceful_restart.stale_routes_time"], "peer",
		"stale_routes_time is implemented per peer; it is the global level that needs the opt-in")
	assert.NotContains(t, settingsWithScope["graceful_restart.stale_routes_time"], "global",
		"the global block only reaches peers via graceful-restart-inherit-to-neighbors")
}

// And the registered effect tests actually run here too, so the registry cannot
// drift into naming tests that are skipped or never invoked.
func TestRegisteredWireEffectsAllRun(t *testing.T) {
	for name, fn := range wireEffectFields {
		t.Run(name, func(t *testing.T) { fn(t) })
	}
}

// Changing an egress transform on a session that is already up.
//
// The tests above set the field before the session exists, so the transform is
// applied to every advertisement from the start. That leaves the harder half
// unproven: a change made to a live peer applies only to routes advertised
// after it unless the already-advertised ones are re-sent.
//
// This is the half that cannot be observed without a real session, which is why
// it went untested. NeedsResendOpenMessage excludes send-community and
// remove-private-as, so neither change rebuilds the session - and a rebuild is
// what would otherwise have re-advertised everything as a side effect. Deleting
// the softResetOut call in updateNeighbor breaks nothing in a test that has no
// peer attached.
func TestEffectRemovePrivateAsAppliesToAlreadyAdvertisedRoutes(t *testing.T) {
	const prefix = "10.64.0.0/24"
	// No remove-private to begin with: the private ASN must arrive first, or
	// there is nothing to prove was re-sent.
	a, b := effectPeers(t, 10641, &api.PeerConf{})

	// 64700 is private (64512-65534) and must go; 1000 is public and must stay,
	// so the assertion distinguishes "the transform ran" from "the AS_PATH was
	// mangled". 65100 would not do for the public one - it is private too.
	advertise(t, a, prefix, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{64700, 1000}),
	}))

	before := adjInOf(t, b, prefix)
	require.True(t, before.found, "the route must reach the peer at all")
	require.Contains(t, before.asPath, uint32(64700),
		"the private ASN has to be there before the change, or this proves nothing: %s", before)

	// Change it on the live peer. Everything else is identical, so this is the
	// only difference the daemon sees.
	_, err := a.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         65002,
			RemovePrivate:   api.RemovePrivate_REMOVE_PRIVATE_ALL.Enum(),
		},
		Transport: &api.Transport{PassiveMode: true},
	}})
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	after := adjInOf(t, b, prefix)
	require.True(t, after.found, "the route must still be there after the change")
	assert.NotContains(t, after.asPath, uint32(64700),
		"the route advertised before the change was never re-sent under it: %s", after)
	assert.Contains(t, after.asPath, uint32(1000),
		"only the private ASNs should have gone: %s", after)
}

// Sent withdrawal counters were two bugs stacked.
//
// counterStats.Sent.Withdraw{Update,Prefix} was declared, zeroed on reset,
// copied into oc by toConfig and exported as bgp_sent_withdraw_update_total —
// and incremented by nothing. Only the received side was, via bmpStatsUpdate.
// The api literal for Sent then dropped both fields anyway, while the Received
// literal beside it carried them.
//
// So the sent metrics read zero for the whole life of the fork, and would have
// continued to read zero if only one of the two halves had been fixed.
func TestEffectSentWithdrawCountersAreCounted(t *testing.T) {
	const prefix = "10.67.0.0/24"
	a, b := effectPeers(t, 10671, &api.PeerConf{})

	advertise(t, a, prefix)
	require.True(t, adjInOf(t, b, prefix).found, "the route must reach the peer first")

	sentWithdraws := func(t *testing.T) (updates, prefixes uint64) {
		t.Helper()
		var p *api.Peer
		require.NoError(t, a.ListPeer(context.Background(), &api.ListPeerRequest{},
			func(x *api.Peer) { p = x }))
		require.NotNil(t, p)
		require.NotNil(t, p.State)
		require.NotNil(t, p.State.Messages)
		require.NotNil(t, p.State.Messages.Sent)
		return p.State.Messages.Sent.WithdrawUpdate, p.State.Messages.Sent.WithdrawPrefix
	}

	u0, p0 := sentWithdraws(t)

	// Delete the exact path that was advertised - DeletePath matches on the
	// full path, so a bare NLRI is rejected with "nexthop not found".
	var toDelete []*apiutil.Path
	require.NoError(t, a.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_IPv4_UC,
	}, func(n bgp.NLRI, paths []*apiutil.Path) {
		if n.String() == prefix {
			toDelete = append(toDelete, paths...)
		}
	}))
	require.NotEmpty(t, toDelete, "the advertised path must be in the global RIB")
	require.NoError(t, a.DeletePath(apiutil.DeletePathRequest{Paths: toDelete}))
	time.Sleep(2 * time.Second)

	u1, p1 := sentWithdraws(t)
	assert.Greater(t, u1, u0, "withdrawing a route must count a sent withdraw UPDATE")
	assert.Greater(t, p1, p0, "and the prefix it withdrew")
}

// The output queue depth is reported rather than hardcoded to zero.
//
// oc NeighborState.Queues was declared and written by nothing, so `gobgp
// neighbor` printed "BGP OutQ = 0" for every peer forever, and PeerState.out_q
// was likewise always zero.
func TestEffectOutputQueueIsReported(t *testing.T) {
	a, _ := effectPeers(t, 10681, &api.PeerConf{})

	var p *api.Peer
	require.NoError(t, a.ListPeer(context.Background(), &api.ListPeerRequest{},
		func(x *api.Peer) { p = x }))
	require.NotNil(t, p)
	require.NotNil(t, p.State)

	// An idle established session has an empty queue; what is asserted is that
	// both fields are populated from the same source and agree, not that the
	// depth is non-zero - a non-zero depth cannot be produced deterministically.
	require.NotNil(t, p.State.Queues)
	assert.Equal(t, p.State.Queues.Output, p.State.OutQ,
		"out_q and queues.output are the same datum and must agree")
}

// PeerState's three netlink next-hop fields are reported.
//
// They have been declared since the netlink work landed and written by nothing,
// because nothing populated table.PeerInfo either - which is the same reason
// the RFC 2545 dual next hop this fork exists for was never emitted.
func TestEffectNetlinkNexthopsAreReported(t *testing.T) {
	a, _ := effectPeers(t, 10691, &api.PeerConf{})

	var p *api.Peer
	require.NoError(t, a.ListPeer(context.Background(), &api.ListPeerRequest{},
		func(x *api.Peer) { p = x }))
	require.NotNil(t, p)
	require.NotNil(t, p.State)

	// The session is over loopback, so the local address is 127.0.0.1 and the
	// IPv4 next hop is that same address - which is exactly the invariant the
	// preference for the local address is there to hold: a numbered session
	// advertises the address it is sourced from, as it always did.
	assert.Equal(t, "127.0.0.1", p.State.Ipv4Nexthop,
		"the IPv4 next hop must be the session local address")

	// lo carries no global or link-local IPv6, so these stay empty rather than
	// reporting netip.Addr's zero value as the string "invalid IP".
	assert.Empty(t, p.State.Ipv6Nexthop)
	assert.Empty(t, p.State.Ipv6LinkLocalNexthop)
}

// And they survive a configuration change that rebuilds PeerInfo without
// tearing the session down.
//
// updateNeighbor replaces the peer's PeerInfo snapshot wholesale when
// remove-private-as changes on a live peer, and table.NewPeerInfo does not
// carry the netlink next hops. Without carrying them over, an unrelated
// configuration change silently reverts netlink-imported routes to the
// fallback next hop and empties these three fields until the session flaps -
// which is the same class of defect as never populating them at all, only
// harder to notice.
func TestEffectNetlinkNexthopsSurviveAConfigChange(t *testing.T) {
	a, _ := effectPeers(t, 10711, &api.PeerConf{})

	nexthop := func(t *testing.T) string {
		t.Helper()
		var p *api.Peer
		require.NoError(t, a.ListPeer(context.Background(), &api.ListPeerRequest{},
			func(x *api.Peer) { p = x }))
		require.NotNil(t, p)
		require.NotNil(t, p.State)
		return p.State.Ipv4Nexthop
	}

	before := nexthop(t)
	require.Equal(t, "127.0.0.1", before, "the next hop must be set before the change, or this proves nothing")

	// remove-private-as is the one in-place change that rebuilds PeerInfo.
	_, err := a.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         65002,
			RemovePrivate:   api.RemovePrivate_REMOVE_PRIVATE_ALL.Enum(),
		},
		Transport: &api.Transport{PassiveMode: true},
	}})
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	assert.Equal(t, before, nexthop(t), "the next hop must survive an in-place configuration change")
}

// disconnect_reason and disconnect_message are reported by ListPeer.
//
// convertFSMStateReasonToAPI has existed since the fields were added, but its
// only caller was the WatchEvent stream. A caller that polls ListPeer - which
// is what k8gobgp does - got UNSPECIFIED and "" for every peer, up or down.
func TestEffectDisconnectReasonIsReported(t *testing.T) {
	a, _ := effectPeers(t, 10701, &api.PeerConf{})

	peerState := func(t *testing.T) *api.PeerState {
		t.Helper()
		var p *api.Peer
		require.NoError(t, a.ListPeer(context.Background(), &api.ListPeerRequest{},
			func(x *api.Peer) { p = x }))
		require.NotNil(t, p)
		require.NotNil(t, p.State)
		return p.State
	}

	// An established session has no disconnect to report. Asserting this is
	// what stops the test passing on a constant.
	st := peerState(t)
	assert.Equal(t, api.PeerState_DISCONNECT_REASON_UNSPECIFIED, st.DisconnectReason,
		"an established session reports no disconnect reason")
	assert.Empty(t, st.DisconnectMessage)

	require.NoError(t, a.ShutdownPeer(context.Background(),
		&api.ShutdownPeerRequest{Address: "127.0.0.1", Communication: "test"}))

	require.Eventually(t, func() bool {
		return peerState(t).DisconnectReason != api.PeerState_DISCONNECT_REASON_UNSPECIFIED
	}, 30*time.Second, 200*time.Millisecond, "the disconnect must be reported")

	st = peerState(t)
	assert.Equal(t, api.PeerState_DISCONNECT_REASON_NOTIFICATION_SENT, st.DisconnectReason)
	assert.Contains(t, st.DisconnectMessage, "notification-sent",
		"the message names the reason, not just the enum")
}

// A peer shut down for exceeding its prefix limit reports that as the reason.
//
// The adminStatePfxCt arm sent the CEASE and returned no state. sendNotification
// closes the connection, so the session went down through whichever goroutine
// noticed first - usually the reader, as read-failed - and the reason reported
// was neither right nor stable. BMP saw the same wrong reason, so the
// maximum-prefixes notification it should have carried to the station was
// never attached.
func TestEffectPrefixLimitShutdownIsReportedAsSuch(t *testing.T) {
	const port = 10721

	a := NewBgpServer()
	go a.Serve()
	require.NoError(t, a.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: port},
	}))
	t.Cleanup(func() { a.StopBgp(context.Background(), &api.StopBgpRequest{}) }) //nolint:errcheck

	// One prefix allowed; the second one trips it.
	require.NoError(t, a.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis: []*api.AfiSafi{{
			Config: &api.AfiSafiConfig{
				Family:  &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
				Enabled: true,
			},
			PrefixLimits: &api.PrefixLimit{MaxPrefixes: 1},
		}},
	}}))

	b := NewBgpServer()
	go b.Serve()
	require.NoError(t, b.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65002, RouterId: "2.2.2.2", ListenPort: -1},
	}))
	t.Cleanup(func() { b.StopBgp(context.Background(), &api.StopBgpRequest{}) }) //nolint:errcheck

	waiter := newPeerStateWaiter(a, api.PeerState_SESSION_STATE_ESTABLISHED)
	require.NoError(t, b.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{RemotePort: uint32(port)},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
	}}))
	waiter.Wait(t, 30*time.Second)

	advertise(t, b, "10.72.1.0/24")
	advertise(t, b, "10.72.2.0/24")

	var st *api.PeerState
	require.Eventually(t, func() bool {
		var p *api.Peer
		if err := a.ListPeer(context.Background(), &api.ListPeerRequest{},
			func(x *api.Peer) { p = x }); err != nil || p == nil || p.State == nil {
			return false
		}
		st = p.State
		return st.AdminState == api.PeerState_ADMIN_STATE_PFX_CT &&
			st.DisconnectReason != api.PeerState_DISCONNECT_REASON_UNSPECIFIED
	}, 30*time.Second, 200*time.Millisecond, "the prefix limit must shut the session down and say why")

	assert.Equal(t, api.PeerState_DISCONNECT_REASON_NOTIFICATION_SENT, st.DisconnectReason,
		"the session went down because this speaker sent a CEASE, not because a read or write failed")
	assert.Contains(t, st.DisconnectMessage, "maximum number of prefixes reached",
		"the message must name the CEASE subcode")
}

// Everything ListPeer reports about a live session is reported.
//
// The other half of the configuration-consumer registry. That one catches a
// setting nothing acts on; this catches a value the daemon has and never
// writes into the reply - the defect behind most of this release: description,
// peer group, remove-private, both hold timers, the queue depth, the sent
// withdrawal counters, the disconnect reason, the netlink next hops. Each was
// in scope at the conversion and left out of the literal.
//
// The session is built to use as much as it can - a peer group, a
// description, remove-private and send-community, routes and a withdrawal in
// each direction - and then every scalar under PeerState and
// TimersState must be non-zero. What legitimately stays zero on a healthy
// session is listed with the reason and, where it matters, the test that does
// assert it non-zero. A new field added to either message arrives here as a
// failure until someone reports it or says why not.
var reportedStateZeroOnAHealthySession = map[string]string{
	"PeerState.auth_password_set":              "no MD5 on this session; server_authpassword_test.go asserts the flag",
	"PeerState.bfd_state":                      "BFD is not run on this session; Test_BfdPeerStateSnapshotPopulatesEveryField asserts the snapshot",
	"PeerState.disconnect_reason":              "the session has never gone down; TestEffectDisconnectReasonIsReported",
	"PeerState.disconnect_message":             "the session has never gone down; TestEffectDisconnectReasonIsReported",
	"PeerState.flops":                          "the session has never gone down",
	"PeerState.ipv6_nexthop":                   "the session is over IPv4 loopback, which has no global IPv6 address; TestSetNetlinkNexthops",
	"PeerState.ipv6_link_local_nexthop":        "as ipv6_nexthop; TestSetNetlinkNexthops",
	"PeerState.out_q":                          "the output queue is empty on an idle session; TestEffectOutputQueueIsReported",
	"PeerState.queues.output":                  "as out_q; TestEffectOutputQueueIsReported",
	"PeerState.messages.received.notification": "a NOTIFICATION ends the session",
	"PeerState.messages.sent.notification":     "a NOTIFICATION ends the session",
	"PeerState.messages.received.discarded":    "nothing malformed was sent",
	"PeerState.messages.sent.discarded":        "nothing was discarded",
	"PeerState.messages.sent.refresh": "gobgpd never sends ROUTE-REFRESH: a soft reset in replays the stored " +
		"Adj-RIB-In instead of asking the peer",
	"PeerState.messages.received.refresh": "the peer here is gobgpd, which never sends one",
	"TimersState.downtime":                "the session has never gone down",
	"TimersState.uptime.nanos":            "uptime is recorded to the second",
}

func TestConformanceReportedStateIsComplete(t *testing.T) {
	const port = 10801
	ctx := context.Background()

	a := NewBgpServer()
	go a.Serve()
	require.NoError(t, a.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: port},
	}))
	t.Cleanup(func() { a.StopBgp(ctx, &api.StopBgpRequest{}) }) //nolint:errcheck

	require.NoError(t, a.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65002},
	}}))
	require.NoError(t, a.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerGroup:       "edge",
			Description:     proto.String("state completeness"),
			RemovePrivate:   api.RemovePrivate_REMOVE_PRIVATE_ALL.Enum(),
			SendCommunity:   proto.Uint32(2),
		},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	b := NewBgpServer()
	go b.Serve()
	require.NoError(t, b.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{Asn: 65002, RouterId: "2.2.2.2", ListenPort: -1},
	}))
	t.Cleanup(func() { b.StopBgp(ctx, &api.StopBgpRequest{}) }) //nolint:errcheck

	waiter := newPeerStateWaiter(a, api.PeerState_SESSION_STATE_ESTABLISHED)
	require.NoError(t, b.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{RemotePort: port},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
	}}))
	waiter.Wait(t, 30*time.Second)

	// Traffic in both directions, and a withdrawal each way.
	advertise(t, a, "10.80.1.0/24")
	advertise(t, a, "10.80.2.0/24")
	advertise(t, b, "10.80.3.0/24")
	advertise(t, b, "10.80.4.0/24")
	time.Sleep(2 * time.Second)
	withdraw := func(s *BgpServer, prefix string) {
		t.Helper()
		var paths []*apiutil.Path
		require.NoError(t, s.ListPath(apiutil.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_IPv4_UC,
		}, func(n bgp.NLRI, ps []*apiutil.Path) {
			if n.String() == prefix {
				for _, p := range ps {
					if p.PeerASN == 0 { // locally originated
						paths = append(paths, p)
					}
				}
			}
		}))
		require.NotEmpty(t, paths, "%s must be in the RIB to withdraw", prefix)
		require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: paths}))
	}
	withdraw(a, "10.80.2.0/24")
	withdraw(b, "10.80.4.0/24")
	time.Sleep(3 * time.Second)

	var p *api.Peer
	require.NoError(t, a.ListPeer(ctx, &api.ListPeerRequest{EnableAdvertised: true},
		func(x *api.Peer) { p = x }))
	require.NotNil(t, p)
	require.NotNil(t, p.State)
	require.NotNil(t, p.Timers)
	require.NotNil(t, p.Timers.State)

	seen := map[string]bool{}
	var walk func(m protoreflect.Message, path string)
	walk = func(m protoreflect.Message, path string) {
		fields := m.Descriptor().Fields()
		for i := range fields.Len() {
			fd := fields.Get(i)
			name := path + "." + string(fd.Name())
			seen[name] = true
			if _, ok := reportedStateZeroOnAHealthySession[name]; ok {
				continue
			}
			if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() {
				if assert.True(t, m.Has(fd), "%s is not reported", name) {
					walk(m.Get(fd).Message(), name)
				}
				continue
			}
			assert.True(t, m.Has(fd),
				"%s is zero on a live session that exercises it. Either the daemon knows it and does not "+
					"write it into the reply, or it is legitimately zero here - then say why in "+
					"reportedStateZeroOnAHealthySession.", name)
		}
	}
	walk(p.State.ProtoReflect(), "PeerState")
	walk(p.Timers.State.ProtoReflect(), "TimersState")

	for name := range reportedStateZeroOnAHealthySession {
		assert.True(t, seen[name], "reportedStateZeroOnAHealthySession names %s, which is not a reported field", name)
	}
}

// A hold-time change on a live peer reaches the running session.
//
// It used to be stored and reported at once while the session kept negotiating
// from the old value until it happened to restart: hold time is carried in the
// OPEN and read only when the session establishes. It now rebuilds the
// session, so the new value is negotiated immediately.
func TestEffectHoldTimeChangeReachesTheSession(t *testing.T) {
	a, _ := effectPeers(t, 10811, &api.PeerConf{})

	negotiated := func(t *testing.T) uint64 {
		t.Helper()
		var p *api.Peer
		require.NoError(t, a.ListPeer(context.Background(), &api.ListPeerRequest{},
			func(x *api.Peer) { p = x }))
		require.NotNil(t, p)
		if p.State.SessionState != api.PeerState_SESSION_STATE_ESTABLISHED || p.Timers == nil || p.Timers.State == nil {
			return 0
		}
		return p.Timers.State.NegotiatedHoldTime
	}
	require.EqualValues(t, 90, negotiated(t), "both sides start on the default")

	_, err := a.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &api.Transport{PassiveMode: true},
		// Hold time alone: keepalive stays at its default of 30, so the
		// change to hold time is the only thing that can rebuild the session.
		Timers: &api.Timers{Config: &api.TimersConfig{HoldTime: 60, KeepaliveInterval: 30}},
	}})
	require.NoError(t, err)

	// The lower of the two offers is negotiated, so 60 is only reachable by a
	// new OPEN from this side.
	require.Eventually(t, func() bool { return negotiated(t) == 60 }, 60*time.Second, 250*time.Millisecond,
		"the running session must renegotiate with the new hold time")
}
