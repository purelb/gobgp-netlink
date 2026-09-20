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
	"PeerConf.route_flap_damping":      "not implemented in this daemon",
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
		RemovePrivate: api.RemovePrivate_REMOVE_PRIVATE_ALL,
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
	a, b := effectPeers(t, 10631, &api.PeerConf{ReplacePeerAsn: true})

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

// And the registered effect tests actually run here too, so the registry cannot
// drift into naming tests that are skipped or never invoked.
func TestRegisteredWireEffectsAllRun(t *testing.T) {
	for name, fn := range wireEffectFields {
		t.Run(name, func(t *testing.T) { fn(t) })
	}
}
