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
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Peer-group inheritance is tested here, on the function that implements it,
// rather than through a server. It is a pure function over two structs, so a
// table runs in microseconds where the equivalent end-to-end matrix would start
// a BgpServer per case - and the server package is already close to its CI
// timeout.
//
// Three cases per block, because getting any one of them wrong is a real
// outage:
//
//   - the neighbor sent the block   -> the neighbor's values win entirely
//   - the neighbor sent nothing     -> the group's values are inherited
//   - the neighbor sent it disabled -> it stays disabled
//
// The third is the one that was impossible before. Every one of these blocks
// carries its enable flag as a bool, so "off" is the zero value: any rule that
// infers "unset" from "all fields zero" reads an explicit opt-out as silence
// and turns the feature back on. For ttl-security that silently removes GTSM;
// for route-server it moves the peer's routes into the global RIB and, in this
// fork, into the host FIB.
func TestPeerGroupInheritancePerBlock(t *testing.T) {
	// Each case sets one identifying field so "whose value won" is visible.
	cases := []struct {
		block string
		// apply the neighbor's own settings
		setNeighbor func(*Neighbor)
		// apply the group's settings
		setGroup func(*PeerGroup)
		// what the neighbor should look like when it sent the block
		wantOwn func(*testing.T, *Neighbor)
		// what it should look like when it sent nothing
		wantInherited func(*testing.T, *Neighbor)
		// an explicit "off" that must survive a group that has it on
		setOptOut  func(*Neighbor)
		wantOptOut func(*testing.T, *Neighbor)
	}{
		{
			block:       "graceful-restart",
			setNeighbor: func(n *Neighbor) { n.GracefulRestart.Config = GracefulRestartConfig{Enabled: true, RestartTime: 120} },
			setGroup:    func(g *PeerGroup) { g.GracefulRestart.Config = GracefulRestartConfig{Enabled: true, RestartTime: 30} },
			wantOwn: func(t *testing.T, n *Neighbor) {
				assert.True(t, n.GracefulRestart.Config.Enabled)
				assert.EqualValues(t, 120, n.GracefulRestart.Config.RestartTime)
			},
			wantInherited: func(t *testing.T, n *Neighbor) {
				assert.EqualValues(t, 30, n.GracefulRestart.Config.RestartTime)
			},
			setOptOut:  func(n *Neighbor) { n.GracefulRestart.Config = GracefulRestartConfig{Enabled: false} },
			wantOptOut: func(t *testing.T, n *Neighbor) { assert.False(t, n.GracefulRestart.Config.Enabled) },
		},
		{
			block:       "ttl-security",
			setNeighbor: func(n *Neighbor) { n.TtlSecurity.Config = TtlSecurityConfig{Enabled: true, TtlMin: 250} },
			setGroup:    func(g *PeerGroup) { g.TtlSecurity.Config = TtlSecurityConfig{Enabled: true, TtlMin: 254} },
			wantOwn: func(t *testing.T, n *Neighbor) {
				assert.True(t, n.TtlSecurity.Config.Enabled)
				assert.EqualValues(t, 250, n.TtlSecurity.Config.TtlMin)
			},
			wantInherited: func(t *testing.T, n *Neighbor) {
				assert.EqualValues(t, 254, n.TtlSecurity.Config.TtlMin)
			},
			setOptOut: func(n *Neighbor) { n.TtlSecurity.Config = TtlSecurityConfig{Enabled: false} },
			wantOptOut: func(t *testing.T, n *Neighbor) {
				assert.False(t, n.TtlSecurity.Config.Enabled,
					"GTSM must not be re-enabled by a group when the neighbor turned it off")
			},
		},
		{
			block:       "route-server",
			setNeighbor: func(n *Neighbor) { n.RouteServer.Config = RouteServerConfig{RouteServerClient: true} },
			setGroup: func(g *PeerGroup) {
				g.RouteServer.Config = RouteServerConfig{RouteServerClient: true, SecondaryRoute: true}
			},
			wantOwn: func(t *testing.T, n *Neighbor) {
				assert.True(t, n.RouteServer.Config.RouteServerClient)
				assert.False(t, n.RouteServer.Config.SecondaryRoute, "a sent block is owned entirely by the sender")
			},
			wantInherited: func(t *testing.T, n *Neighbor) {
				assert.True(t, n.RouteServer.Config.SecondaryRoute)
			},
			setOptOut: func(n *Neighbor) { n.RouteServer.Config = RouteServerConfig{RouteServerClient: false} },
			wantOptOut: func(t *testing.T, n *Neighbor) {
				assert.False(t, n.RouteServer.Config.RouteServerClient,
					"route-server status decides which RIB the peer's routes land in, and in this fork whether they reach the kernel")
			},
		},
		{
			block:       "route-reflector",
			setNeighbor: func(n *Neighbor) { n.RouteReflector.Config = RouteReflectorConfig{RouteReflectorClient: true} },
			setGroup: func(g *PeerGroup) {
				g.RouteReflector.Config = RouteReflectorConfig{
					RouteReflectorClient:    true,
					RouteReflectorClusterId: netip.MustParseAddr("10.9.9.9"),
				}
			},
			wantOwn: func(t *testing.T, n *Neighbor) {
				assert.True(t, n.RouteReflector.Config.RouteReflectorClient)
				assert.False(t, n.RouteReflector.Config.RouteReflectorClusterId.IsValid())
			},
			wantInherited: func(t *testing.T, n *Neighbor) {
				assert.Equal(t, "10.9.9.9", n.RouteReflector.Config.RouteReflectorClusterId.String())
			},
			setOptOut:  func(n *Neighbor) { n.RouteReflector.Config = RouteReflectorConfig{RouteReflectorClient: false} },
			wantOptOut: func(t *testing.T, n *Neighbor) { assert.False(t, n.RouteReflector.Config.RouteReflectorClient) },
		},
		{
			block:       "bfd",
			setNeighbor: func(n *Neighbor) { n.Bfd.Config = BfdConfig{Enabled: true, Port: 9999} },
			setGroup:    func(g *PeerGroup) { g.Bfd.Config = BfdConfig{Enabled: true, Port: 3784} },
			wantOwn: func(t *testing.T, n *Neighbor) {
				assert.EqualValues(t, 9999, n.Bfd.Config.Port)
			},
			wantInherited: func(t *testing.T, n *Neighbor) {
				assert.EqualValues(t, 3784, n.Bfd.Config.Port)
			},
			setOptOut:  func(n *Neighbor) { n.Bfd.Config = BfdConfig{Enabled: false} },
			wantOptOut: func(t *testing.T, n *Neighbor) { assert.False(t, n.Bfd.Config.Enabled) },
		},
	}

	// Addresses must be unique per case: configuredFields is a package global
	// that nothing prunes between tests, so sharing one makes the result depend
	// on test ordering.
	next := 100
	addr := func() string {
		next++
		return fmt.Sprintf("198.51.100.%d", next)
	}

	for _, tc := range cases {
		t.Run(tc.block+"/neighbor's own settings win", func(t *testing.T) {
			a := addr()
			n := &Neighbor{}
			n.Config.NeighborAddress = netip.MustParseAddr(a)
			n.Config.PeerGroup = "edge"
			tc.setNeighbor(n)
			pg := &PeerGroup{}
			pg.Config.PeerGroupName = "edge"
			tc.setGroup(pg)
			grpcPresence(a, tc.block)

			require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))
			tc.wantOwn(t, n)
		})

		t.Run(tc.block+"/nothing sent inherits the group", func(t *testing.T) {
			a := addr()
			n := &Neighbor{}
			n.Config.NeighborAddress = netip.MustParseAddr(a)
			n.Config.PeerGroup = "edge"
			pg := &PeerGroup{}
			pg.Config.PeerGroupName = "edge"
			tc.setGroup(pg)
			// No presence registered: the client sent no such block.

			require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))
			tc.wantInherited(t, n)
		})

		t.Run(tc.block+"/explicit off survives an enabled group", func(t *testing.T) {
			a := addr()
			n := &Neighbor{}
			n.Config.NeighborAddress = netip.MustParseAddr(a)
			n.Config.PeerGroup = "edge"
			tc.setOptOut(n)
			pg := &PeerGroup{}
			pg.Config.PeerGroupName = "edge"
			tc.setGroup(pg)
			grpcPresence(a, tc.block)

			require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))
			tc.wantOptOut(t, n)
		})
	}
}

// The global graceful-restart block was accepted, echoed back by GetBgp, and
// acted on by nothing: only per-peer and per-peer-group settings ever reached a
// session. Making it inherit unconditionally would have changed the data plane
// of every deployment that had set it, so it is opt-in.
//
// Precedence is neighbor, then peer group, then global.
func TestGlobalGracefulRestartInheritance(t *testing.T) {
	globalGR := func(inherit bool) *Global {
		g := &Global{Config: GlobalConfig{
			As:                                65000,
			RouterId:                          netip.MustParseAddr("10.0.0.1"),
			GracefulRestartInheritToNeighbors: inherit,
		}}
		g.GracefulRestart.Config = GracefulRestartConfig{Enabled: true, RestartTime: 300}
		return g
	}
	neighbor := func(addr string) *Neighbor {
		n := &Neighbor{}
		n.Config.NeighborAddress = netip.MustParseAddr(addr)
		n.Config.PeerAs = 65001
		return n
	}

	t.Run("off by default: nothing changes for an existing deployment", func(t *testing.T) {
		n := neighbor("198.51.100.200")
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, globalGR(false)))
		assert.False(t, n.GracefulRestart.Config.Enabled,
			"a global block must not reach peers unless the operator opted in")
	})

	t.Run("opted in: an ungrouped peer inherits it", func(t *testing.T) {
		n := neighbor("198.51.100.201")
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, globalGR(true)))
		assert.True(t, n.GracefulRestart.Config.Enabled)
		assert.EqualValues(t, 300, n.GracefulRestart.Config.RestartTime,
			"ungrouped peers are the majority; this must not be scoped to grouped ones")
	})

	t.Run("the peer's own settings beat the global", func(t *testing.T) {
		n := neighbor("198.51.100.202")
		n.GracefulRestart.Config = GracefulRestartConfig{Enabled: true, RestartTime: 60}
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, globalGR(true)))
		assert.EqualValues(t, 60, n.GracefulRestart.Config.RestartTime)
	})

	t.Run("the peer group beats the global", func(t *testing.T) {
		const addr = "198.51.100.203"
		n := neighbor(addr)
		n.Config.PeerGroup = "edge"
		pg := &PeerGroup{}
		pg.Config.PeerGroupName = "edge"
		pg.Config.PeerAs = 65001
		pg.GracefulRestart.Config = GracefulRestartConfig{Enabled: true, RestartTime: 90}

		require.NoError(t, SetDefaultNeighborConfigValues(n, pg, globalGR(true)))
		assert.EqualValues(t, 90, n.GracefulRestart.Config.RestartTime,
			"precedence is neighbor, then peer group, then global")
	})

	t.Run("long-lived is not propagated", func(t *testing.T) {
		g := globalGR(true)
		g.GracefulRestart.Config.LongLivedEnabled = true
		n := neighbor("198.51.100.204")
		require.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))
		assert.True(t, n.GracefulRestart.Config.Enabled)
		assert.False(t, n.GracefulRestart.Config.LongLivedEnabled,
			"the per-family long-lived flag is never derived from this one, so propagating it "+
				"would advertise a long-lived capability carrying no families")
	})
}

// A dynamic peer exists because a connection arrived from a prefix its group
// accepts, so it must stay passive - it never dials out. It sets passive mode
// and then runs peer-group inheritance, and because it has no configured
// address at all (only a state one) nothing recorded that it had set anything,
// so the group's empty transport block turned passive mode straight back off.
//
// Same defect as the graceful-restart one, reached by a different route: the
// presence key could not identify this peer.
func TestDynamicPeerKeepsPassiveMode(t *testing.T) {
	n := &Neighbor{}
	n.Config.PeerGroup = "edge"
	n.State.NeighborAddress = netip.MustParseAddr("198.51.100.210")
	n.Transport.Config.PassiveMode = true

	// Registered under the literal address, not under NeighborPresenceKey(n).
	// Using the key function on both sides would make this pass even if the
	// function returned the wrong thing - including "", which would silently
	// collide every dynamic peer onto one entry.
	RegisterConfiguredFields("198.51.100.210", map[string]any{
		"transport": MarkBlockConfigured(TransportConfig{}),
	})
	require.Equal(t, "198.51.100.210", NeighborPresenceKey(n),
		"the lookup key must be the peer's state address")

	pg := &PeerGroup{}
	pg.Config.PeerGroupName = "edge"
	// A group that says nothing about transport - the case that used to erase it.

	require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))
	assert.True(t, n.Transport.Config.PassiveMode,
		"a group with no transport block must not take passive mode off a dynamic peer")
}
