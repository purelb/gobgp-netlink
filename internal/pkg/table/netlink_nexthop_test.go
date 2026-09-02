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

package table

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

// newNetlinkIPv6Path builds the shape ipNetsToPaths produces for a netlink
// imported IPv6 route: an unspecified "::" nexthop that UpdatePathAttrs is
// expected to replace with the peer's addresses.
func newNetlinkIPv6Path(t *testing.T, iface string) *Path {
	t.Helper()

	prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))
	assert.NoError(t, err)

	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
		[]bgp.PathNLRI{{NLRI: prefix}}, netip.MustParseAddr("::"))
	assert.NoError(t, err)

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		mpreach,
	}

	p := NewPath(bgp.RF_IPv6_UC, NewNetlinkPeerInfo(iface), bgp.PathNLRI{NLRI: prefix},
		false, attrs, time.Now(), false)
	assert.NotNil(t, p)
	p.SetIsFromExternal(true)
	return p
}

// nexthopsOf returns the MP_REACH nexthops in wire order: the global next hop
// first and, when present, the RFC 2545 section 3 link-local next hop second.
func nexthopsOf(t *testing.T, p *Path) []net.IP {
	t.Helper()
	attr := p.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr == nil {
		return nil
	}
	mp := attr.(*bgp.PathAttributeMpReachNLRI)
	out := make([]net.IP, 0, 2)
	if mp.Nexthop.IsValid() {
		out = append(out, net.IP(mp.Nexthop.AsSlice()))
	}
	if mp.LinkLocalNexthop.IsValid() {
		out = append(out, net.IP(mp.LinkLocalNexthop.AsSlice()))
	}
	return out
}

// TestNetlinkPeerInfoCarriesOnlyIdentity pins the contract that
// NewNetlinkPeerInfo populates identity fields only.
//
// The three nexthop fields are deliberately left zero: UpdatePathAttrs reads
// them from the *peer's* PeerInfo, never from a path source, and populating them
// here cost four full netlink dumps per route per import tick. If someone
// repopulates them, this test says why not to.
func TestNetlinkPeerInfoCarriesOnlyIdentity(t *testing.T) {
	pi := NewNetlinkPeerInfo("eth0")

	assert.True(t, pi.IsNetlink)
	assert.Equal(t, "eth0", pi.NetlinkIfName)
	assert.Equal(t, "eth0", pi.GetNeighborInterface())

	assert.Nil(t, pi.IPv4Nexthop)
	assert.Nil(t, pi.IPv6Nexthop)
	assert.Nil(t, pi.IPv6LinkLocalNexthop)
}

// TestUpdatePathAttrsNetlinkIPv6DualNexthop is the RFC 2545 section 3 regression
// gate: a netlink-originated IPv6 route advertised to an unnumbered peer must
// carry BOTH the global and the link-local nexthop.
//
// This is the reason the fork exists, and it had no unit coverage. Both nexthops
// must come from the peer's PeerInfo, not from the path's source.
func TestUpdatePathAttrsNetlinkIPv6DualNexthop(t *testing.T) {
	logger := slog.Default()
	global := &oc.Global{Config: oc.GlobalConfig{As: 65001, RouterId: netip.MustParseAddr("1.1.1.1")}}

	for _, tt := range []struct {
		name     string
		peerType oc.PeerType
	}{
		{"eBGP", oc.PEER_TYPE_EXTERNAL},
		{"iBGP", oc.PEER_TYPE_INTERNAL},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// UpdatePathAttrs is now driven entirely from PeerInfo - upstream
			// c2462941 dropped its *oc.Neighbor parameter - so the peer type
			// lives here too. The dual nexthop still comes only from the peer's
			// PeerInfo, populated when the session comes up.
			info := &PeerInfo{
				PeerType:             tt.peerType,
				AS:                   65002,
				LocalAS:              65001,
				Address:              netip.MustParseAddr("fe80::2"),
				LocalAddress:         netip.MustParseAddr("2001:db8::1"),
				IPv6Nexthop:          net.ParseIP("2001:db8::1"),
				IPv6LinkLocalNexthop: net.ParseIP("fe80::1"),
			}

			out := UpdatePathAttrs(logger, global, info, newNetlinkIPv6Path(t, "eth0"))
			assert.NotNil(t, out)

			nh := nexthopsOf(t, out)
			if assert.Len(t, nh, 2, "expected global + link-local, got %v", nh) {
				assert.True(t, nh[0].Equal(net.ParseIP("2001:db8::1")), "global nexthop first, got %v", nh[0])
				assert.True(t, nh[1].Equal(net.ParseIP("fe80::1")), "link-local nexthop second, got %v", nh[1])
			}
		})
	}
}

// TestUpdatePathAttrsNetlinkIPv6GlobalOnly covers a peer with no link-local
// address: a single nexthop, never a duplicated global.
func TestUpdatePathAttrsNetlinkIPv6GlobalOnly(t *testing.T) {
	logger := slog.Default()
	global := &oc.Global{Config: oc.GlobalConfig{As: 65001, RouterId: netip.MustParseAddr("1.1.1.1")}}
	info := &PeerInfo{
		PeerType:     oc.PEER_TYPE_EXTERNAL,
		AS:           65002,
		LocalAS:      65001,
		Address:      netip.MustParseAddr("2001:db8::2"),
		LocalAddress: netip.MustParseAddr("2001:db8::1"),
		IPv6Nexthop:  net.ParseIP("2001:db8::1"),
	}

	out := UpdatePathAttrs(logger, global, info, newNetlinkIPv6Path(t, "eth0"))
	assert.NotNil(t, out)

	nh := nexthopsOf(t, out)
	if assert.Len(t, nh, 1, "expected a single nexthop, got %v", nh) {
		assert.True(t, nh[0].Equal(net.ParseIP("2001:db8::1")))
	}
}
