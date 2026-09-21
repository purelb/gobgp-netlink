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

package oc

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OverwriteNeighborConfigWithPeerGroup had no test of any kind before the BFD
// inheritance change, which alters what it does for every grouped neighbor on
// both config paths. These were written against the old behaviour first so
// that the assertions which flipped could be seen to be the intended ones and
// no others; two did, and they now state the new contract.
//
// Every case uses its own neighbor address. configuredFields is a package
// global that RegisterConfiguredFields only ever adds to - nothing prunes it,
// and other packages' tests register into it too - so sharing an address
// between cases makes the result depend on test ordering and -run filtering.

func neighborWithBfd(addr string, group string, bfd BfdConfig) *Neighbor {
	n := &Neighbor{}
	n.Config.NeighborAddress = netip.MustParseAddr(addr)
	n.Config.PeerGroup = group
	n.Bfd.Config = bfd
	return n
}

func peerGroupWithBfd(name string, bfd BfdConfig) *PeerGroup {
	pg := &PeerGroup{}
	pg.Config.PeerGroupName = name
	pg.Bfd.Config = bfd
	return pg
}

// grpcPresence registers the blocks a gRPC client sent, the way
// recordNeighborPresence does in the converter. Presence is per block: sending
// one means owning all of it.
func grpcPresence(addr string, blocks ...string) {
	p := map[string]any{}
	for _, b := range blocks {
		switch b {
		case "bfd":
			p[b] = MarkBlockConfigured(BfdConfig{})
		case "graceful-restart":
			p[b] = MarkBlockConfigured(GracefulRestartConfig{})
		case "ttl-security":
			p[b] = MarkBlockConfigured(TtlSecurityConfig{})
		case "route-server":
			p[b] = MarkBlockConfigured(RouteServerConfig{})
		case "route-reflector":
			p[b] = MarkBlockConfigured(RouteReflectorConfig{})
		}
	}
	RegisterConfiguredFields(addr, p)
}

// tomlNeighbor mirrors what the TOML loader hands RegisterConfiguredFields:
// the raw parsed neighbor entry, which is what v.IsSet is asked about.
func tomlNeighbor(addr string, bfd map[string]any) map[string]any {
	n := map[string]any{
		"config": map[string]any{"neighbor-address": addr},
	}
	if bfd != nil {
		n["bfd"] = map[string]any{"config": bfd}
	}
	return n
}

// A neighbor configured over gRPC keeps its own BFD settings. Nothing recorded
// presence on that path, so the per-field IsSet check was false for every field
// and the group won them all - a group with no BFD block erased the neighbor's
// settings with its zero values. The converter records presence now.
func Test_OverwriteNeighborConfigWithPeerGroup_GrpcPathKeepsNeighborBfd(t *testing.T) {
	assert := assert.New(t)

	own := BfdConfig{
		Enabled:                  true,
		Port:                     9999,
		DetectionMultiplier:      7,
		DesiredMinimumTxInterval: 50000,
		RequiredMinimumReceive:   50000,
	}
	n := neighborWithBfd("198.51.100.1", "edge", own)
	pg := peerGroupWithBfd("edge", BfdConfig{})
	grpcPresence("198.51.100.1", "bfd")

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(own, n.Bfd.Config, "a group with no BFD block must not erase the neighbor's")
}

// The opt-out, and the reason the zero-value gate had to go. A neighbor in a
// BFD-enabled group sends "enabled = false" and nothing else - an all-zero
// block, indistinguishable from "unset" to any test of the value, so the old
// gate inherited the group's settings and turned BFD back on. Its own comment
// claimed otherwise; the documented example only worked because it also set the
// port and the intervals, which is what made the block non-empty.
//
// Recorded presence says the block was sent, so the opt-out holds with nothing
// else in it.
func Test_OverwriteNeighborConfigWithPeerGroup_NeighborCanOptOutOfGroupBfd(t *testing.T) {
	assert := assert.New(t)

	optOut := BfdConfig{Enabled: false}
	n := neighborWithBfd("198.51.100.6", "edge", optOut)
	grpcPresence("198.51.100.6", "bfd")
	pg := peerGroupWithBfd("edge", BfdConfig{
		Enabled:                  true,
		Port:                     3784,
		DetectionMultiplier:      3,
		DesiredMinimumTxInterval: 300000,
		RequiredMinimumReceive:   300000,
	})

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.False(n.Bfd.Config.Enabled, "the neighbor opted out and the group must not turn BFD back on")
	assert.Equal(optOut, n.Bfd.Config, "an explicitly sent block is owned entirely by the sender")
}

// The inverse, and the behaviour that must survive the fix: a neighbor that
// configured no BFD inherits the group's.
func Test_OverwriteNeighborConfigWithPeerGroup_GrpcPathInheritsGroupBfd(t *testing.T) {
	assert := assert.New(t)

	groupBfd := BfdConfig{
		Enabled:                  true,
		Port:                     3784,
		DetectionMultiplier:      3,
		DesiredMinimumTxInterval: 300000,
		RequiredMinimumReceive:   300000,
	}
	n := neighborWithBfd("198.51.100.2", "edge", BfdConfig{})
	pg := peerGroupWithBfd("edge", groupBfd)

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(groupBfd, n.Bfd.Config, "a neighbor with no BFD block inherits the group's")
}

// BFD inherits as a whole block on the TOML path too. This used to be
// per-field - a neighbor setting only `enabled` inherited the group's port
// and intervals - and narrowing it is the deliberate cost of making
// `enabled = false` a working opt-out. The fields the neighbor left out stay
// zero here and pick up the global defaults later in
// The TOML path keeps per-field inheritance, which is what it always had and
// what the whole-block gate took away. A neighbor that sets one field of a
// block keeps that field and still inherits the rest from its group.
//
// This used to assert the opposite - that the neighbor's block was kept whole
// and nothing came from the group. That was the gate's behaviour, and it cost
// config-file users the ability to override one field without restating the
// block. Restoring it is the point of moving presence onto the API path
// instead.
func Test_OverwriteNeighborConfigWithPeerGroup_TomlPathInheritsUnsetFields(t *testing.T) {
	assert := assert.New(t)

	const addr = "198.51.100.3"
	RegisterConfiguredFields(addr, tomlNeighbor(addr, map[string]any{"detection-multiplier": 9}))

	n := neighborWithBfd(addr, "edge", BfdConfig{DetectionMultiplier: 9})
	pg := peerGroupWithBfd("edge", BfdConfig{
		Enabled:                  true,
		Port:                     4784,
		DetectionMultiplier:      3,
		DesiredMinimumTxInterval: 700000,
		RequiredMinimumReceive:   700000,
	})

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.EqualValues(9, n.Bfd.Config.DetectionMultiplier, "the field the neighbor set wins")
	assert.True(n.Bfd.Config.Enabled, "and the fields it did not set come from the group")
	assert.EqualValues(4784, n.Bfd.Config.Port)
	assert.EqualValues(700000, n.Bfd.Config.DesiredMinimumTxInterval)
}

// A TOML neighbor that set no BFD fields inherits the whole block, the same
// as the gRPC path.
func Test_OverwriteNeighborConfigWithPeerGroup_TomlPathWithoutBfdInherits(t *testing.T) {
	assert := assert.New(t)

	const addr = "198.51.100.4"
	RegisterConfiguredFields(addr, tomlNeighbor(addr, nil))

	groupBfd := BfdConfig{Enabled: true, Port: 3784, DetectionMultiplier: 3}
	n := neighborWithBfd(addr, "edge", BfdConfig{})
	pg := peerGroupWithBfd("edge", groupBfd)

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(groupBfd, n.Bfd.Config)
}

// newDynamicPeer calls this directly and then calls
// SetDefaultNeighborConfigValues, which calls it again, because State.LocalAs
// is still zero at that point and the idempotence guard does not fire. Running
// it twice must not produce a different answer from running it once - the
// property the BFD fix has to preserve, since after the first call the
// neighbor's block is no longer empty.
func Test_OverwriteNeighborConfigWithPeerGroup_IsIdempotent(t *testing.T) {
	assert := assert.New(t)

	groupBfd := BfdConfig{Enabled: true, Port: 3784, DetectionMultiplier: 3}
	pg := peerGroupWithBfd("edge", groupBfd)

	n := neighborWithBfd("198.51.100.5", "edge", BfdConfig{})
	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))
	once := n.Bfd.Config

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))
	assert.Equal(once, n.Bfd.Config, "a second overwrite must not change the result")
}

func TestSetDefaultNeighborConfigValuesSendCommunity(t *testing.T) {
	newNeighbor := func(sc CommunityType) *Neighbor {
		n := &Neighbor{}
		n.Config.NeighborAddress = netip.MustParseAddr("10.0.0.1")
		n.Config.PeerAs = 65001
		n.Config.SendCommunity = sc
		return n
	}
	g := &Global{}
	g.Config.As = 65000
	g.Config.RouterId = netip.MustParseAddr("10.0.0.254")

	t.Run("copied to state for iBGP", func(t *testing.T) {
		n := newNeighbor(COMMUNITY_TYPE_BOTH)
		n.Config.PeerAs = 65000 // iBGP: unlike remove-private-as, this must still copy
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))
		assert.Equal(t, COMMUNITY_TYPE_BOTH, n.State.SendCommunity)
	})

	t.Run("copied to state for eBGP", func(t *testing.T) {
		n := newNeighbor(COMMUNITY_TYPE_NONE)
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))
		assert.Equal(t, COMMUNITY_TYPE_NONE, n.State.SendCommunity)
	})

	t.Run("unset stays unset", func(t *testing.T) {
		n := newNeighbor("")
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))
		assert.Equal(t, CommunityType(""), n.State.SendCommunity)
	})

	t.Run("typo is rejected, not silently ignored", func(t *testing.T) {
		n := newNeighbor(CommunityType("all"))
		err := SetDefaultNeighborConfigValues(n, nil, g)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid send-community")
	})
}

// N3: a neighbor that lists no afi-safis at all - the ordinary shape over the
// API - used to advertise a Graceful Restart capability with an empty AFI/SAFI
// list, because the per-family derivation lived only in the branch that handles
// an explicit list. fsm.go emits a tuple only for families whose
// mp-graceful-restart is enabled, so the peer negotiated GR and retained
// nothing: indistinguishable from working until a restart actually happens.
func Test_SetDefaultNeighborConfigValues_DerivesMpGracefulRestartWithoutExplicitFamilies(t *testing.T) {
	g := &Global{Config: GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}

	n := &Neighbor{}
	n.Config.NeighborAddress = netip.MustParseAddr("198.51.100.20")
	n.Config.PeerAs = 65001
	n.GracefulRestart.Config.Enabled = true

	require.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))

	require.NotEmpty(t, n.AfiSafis, "a neighbor with no explicit families should get a default one")
	for _, af := range n.AfiSafis {
		assert.True(t, af.MpGracefulRestart.Config.Enabled,
			"%s must carry mp-graceful-restart, or the GR capability goes out with no families",
			af.Config.AfiSafiName)
		assert.True(t, af.MpGracefulRestart.State.Enabled, "%s state must match config", af.Config.AfiSafiName)
	}
}

// The converse: GR off must not switch the families on.
func Test_SetDefaultNeighborConfigValues_NoMpGracefulRestartWhenGrDisabled(t *testing.T) {
	g := &Global{Config: GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}

	n := &Neighbor{}
	n.Config.NeighborAddress = netip.MustParseAddr("198.51.100.21")
	n.Config.PeerAs = 65001

	require.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))

	require.NotEmpty(t, n.AfiSafis)
	for _, af := range n.AfiSafis {
		assert.False(t, af.MpGracefulRestart.Config.Enabled, "%s", af.Config.AfiSafiName)
	}
}

// N6: an interface peer is registered under its interface name, so it has to be
// looked up under the same key. It used to be looked up by address - which is
// "invalid IP" for an interface peer - so the lookup always missed and the peer
// group won every field, which is D1's failure mode across every block.
func Test_NeighborPresenceKey_MatchesForAddressAndInterfacePeers(t *testing.T) {
	addrPeer := &Neighbor{}
	addrPeer.Config.NeighborAddress = netip.MustParseAddr("198.51.100.22")
	assert.Equal(t, "198.51.100.22", NeighborPresenceKey(addrPeer))

	intfPeer := &Neighbor{}
	intfPeer.Config.NeighborInterface = "eth0"
	assert.Equal(t, "eth0", NeighborPresenceKey(intfPeer),
		"an interface peer must key on the interface, since it has no address")

	// A dynamic peer is created from an accepted connection, so it has only a
	// state address. Keying it on nothing meant the peer group erased the
	// passive mode it had just been given.
	dynPeer := &Neighbor{}
	dynPeer.State.NeighborAddress = netip.MustParseAddr("198.51.100.23")
	assert.Equal(t, "198.51.100.23", NeighborPresenceKey(dynPeer),
		"a dynamic peer has no configured address, only a state one")

	neither := &Neighbor{}
	assert.Equal(t, "", NeighborPresenceKey(neither),
		"a neighbor with no identity is not registrable; the caller must skip it rather than panic")
}

// N5: the map is written from the SIGHUP reload path and read on the Serve
// goroutine. Run under -race, this fails on a plain map.
func Test_ConfiguredFields_ConcurrentRegisterAndLookup(t *testing.T) {
	const n = 200
	done := make(chan struct{}, 2)

	go func() {
		for i := range n {
			RegisterConfiguredFields("203.0.113.1", map[string]any{"i": i})
		}
		done <- struct{}{}
	}()
	go func() {
		for range n {
			_, _ = lookupConfiguredFields("203.0.113.1")
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	UnregisterConfiguredFields("203.0.113.1")
	_, ok := lookupConfiguredFields("203.0.113.1")
	assert.False(t, ok, "unregister must remove the entry, or a re-added peer inherits stale presence")
}
