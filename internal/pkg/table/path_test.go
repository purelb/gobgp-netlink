// path_test.go
package table

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/dgryski/go-farm"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathNewIPv4(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv4p := NewPath(bgp.RF_IPv4_UC, pathP[0].GetSource(), bgp.PathNLRI{NLRI: pathP[0].GetNlri()}, true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv4p)
}

func TestPathNewIPv6(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv6p := NewPath(bgp.RF_IPv4_UC, pathP[0].GetSource(), bgp.PathNLRI{NLRI: pathP[0].GetNlri()}, true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv6p)
}

func TestPathGetNlri(t *testing.T) {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("13.2.3.2/24"))
	pd := &Path{
		info: &originInfo{
			nlri: nlri,
		},
	}
	r_nlri := pd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestPathCreatePath(t *testing.T) {
	peerP := PathCreatePeer()
	msg := updateMsgP1()
	updateMsgP := msg.Body.(*bgp.BGPUpdate)
	nlriList := updateMsgP.NLRI
	pathAttributes := updateMsgP.PathAttributes
	nlri_info := nlriList[0]
	path := NewPath(bgp.RF_IPv4_UC, peerP[0], bgp.PathNLRI{NLRI: nlri_info.NLRI}, false, pathAttributes, time.Now(), false)
	assert.NotNil(t, path)
}

func TestPathGetPrefix(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	prefix := "10.10.10.0/24"
	r_prefix := pathP[0].GetPrefix()
	assert.Equal(t, r_prefix, prefix)
}

func TestPathGetAttribute(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	nh := "192.168.50.1"
	pa := pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	r_nh := pa.(*bgp.PathAttributeNextHop).Value.String()
	assert.Equal(t, r_nh, nh)
}

func TestASPathLen(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65004, 65004, 65004, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)
	assert.Equal(10, p.GetAsPathLen())
}

func TestPathPrependAsnToExistingSeqAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	p.PrependAsn(65000, 1, false)
	assert.Equal([]uint32{65000, 65001, 65002, 65003, 65004, 65005, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathSeq(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToEmptyAsPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToFullPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)

	asns := make([]uint16, 255)
	for i := range asns {
		asns[i] = 65000 + uint16(i)
	}

	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	expected := []uint32{65000, 65000}
	for _, v := range asns {
		expected = append(expected, uint32(v))
	}
	p.PrependAsn(65000, 2, false)
	assert.Equal(append(expected, []uint32{0, 0, 0}...), p.GetAsSeqList())
}

func TestGetPathAttrs(t *testing.T) {
	paths := PathCreatePath(PathCreatePeer())
	path0 := paths[0]
	path1 := path0.Clone(false)
	path1.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	path2 := path1.Clone(false)
	nexthopAttr, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	path2.setPathAttr(nexthopAttr)
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP))
}

/*
func TestGetTransversalPathAttrs(t *testing.T) {
	checkTransversalPathAttrs := func(t *testing.T, path *Path, expectedAttr bgp.BGPAttrType, checkIsNotExist ...bool) {
		for _, attr := range path.GetTransversalPathAttrs() {
			assert.NotNil(t, attr)
		}
		if len(checkIsNotExist) > 0 && checkIsNotExist[0] {
			assert.Nil(t, path.GetTransversalPathAttrs()[expectedAttr])
		} else {
			assert.NotNil(t, path.GetTransversalPathAttrs()[expectedAttr])
		}
	}
	paths := PathCreatePath(PathCreatePeer())
	path0 := paths[0]
	checkTransversalPathAttrs(t, path0, bgp.BGP_ATTR_TYPE_ORIGIN)
	nextHop := path0.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, nextHop)
	assert.Equal(t, nextHop.(*bgp.PathAttributeNextHop).Value.String(), "192.168.50.1")

	path1 := path0.Clone(false)
	path1.setPathAttr(bgp.NewPathAttributeNextHop("192.168.98.1"))
	nextHop = path1.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, nextHop)
	assert.Equal(t, nextHop.(*bgp.PathAttributeNextHop).Value.String(), "192.168.98.1")
	path1.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, path1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN))
	checkTransversalPathAttrs(t, path1, bgp.BGP_ATTR_TYPE_ORIGIN)
	checkTransversalPathAttrs(t, path1, bgp.BGP_ATTR_TYPE_NEXT_HOP, true)

	path2 := path1.Clone(false)
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN))
	path2.delPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	// adding an attribute that has been deleted previously by underlayer, is not allowed
	path2.setPathAttr(bgp.NewPathAttributeNextHop("192.168.99.1"))
	checkTransversalPathAttrs(t, path2, bgp.BGP_ATTR_TYPE_ORIGIN, true)
	checkTransversalPathAttrs(t, path2, bgp.BGP_ATTR_TYPE_NEXT_HOP, true)

	nextHop = path2.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, nextHop)
	assert.Equal(t, nextHop.(*bgp.PathAttributeNextHop).Value.String(), "192.168.99.1")
}
*/

func PathCreatePeer() []*PeerInfo {
	peerP1 := &PeerInfo{AS: 65000}
	peerP2 := &PeerInfo{AS: 65001}
	peerP3 := &PeerInfo{AS: 65002}
	peerP := []*PeerInfo{peerP1, peerP2, peerP3}
	return peerP
}

func PathCreatePath(peerP []*PeerInfo) []*Path {
	bgpMsgP1 := updateMsgP1()
	bgpMsgP2 := updateMsgP2()
	bgpMsgP3 := updateMsgP3()
	pathP := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgP1, bgpMsgP2, bgpMsgP3} {
		updateMsgP := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgP.NLRI
		pathAttributes := updateMsgP.PathAttributes
		nlri_info := nlriList[0]
		pathP[i] = NewPath(bgp.RF_IPv4_UC, peerP[i], bgp.PathNLRI{NLRI: nlri_info.NLRI}, false, pathAttributes, time.Now(), false)
	}
	return pathP
}

func updateMsgP1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func updateMsgP2() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func updateMsgP3() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.150.1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	w1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("40.40.40.0/23"))
	withdrawnRoutes := []bgp.PathNLRI{{NLRI: w1}}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func TestRemovePrivateAS(t *testing.T) {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, oc.REMOVE_PRIVATE_AS_OPTION_ALL)
	list := path.GetAsList()
	assert.Equal(t, len(list), 2)
	assert.Equal(t, list[0], uint32(1))
	assert.Equal(t, list[1], uint32(2))

	path = NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, oc.REMOVE_PRIVATE_AS_OPTION_REPLACE)
	list = path.GetAsList()
	assert.Equal(t, len(list), 4)
	assert.Equal(t, list[0], uint32(10))
	assert.Equal(t, list[1], uint32(10))
	assert.Equal(t, list[2], uint32(1))
	assert.Equal(t, list[3], uint32(2))
}

func TestReplaceAS(t *testing.T) {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path = path.ReplaceAS(10, 1)
	list := path.GetAsList()
	assert.Equal(t, len(list), 4)
	assert.Equal(t, list[0], uint32(64512))
	assert.Equal(t, list[1], uint32(64513))
	assert.Equal(t, list[2], uint32(10))
	assert.Equal(t, list[3], uint32(2))
}

func TestUpdatePathAttrsRTCOriginatorIDWithLocalID(t *testing.T) {
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}
	clusterID := netip.MustParseAddr("10.0.0.100")
	info := &PeerInfo{
		AS:                      65000,
		LocalAS:                 65000,
		LocalAddress:            netip.MustParseAddr("192.168.0.1"),
		RouteReflectorClient:    true,
		RouteReflectorClusterID: clusterID,
		PeerType:                oc.PEER_TYPE_INTERNAL,
	}

	// Case 1: Source with Address (not local) set - should use LocalID as Originator ID
	sourceWithLocalID := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
		LocalID: netip.MustParseAddr("10.0.0.100"), // Different from global RouterId
		Address: netip.MustParseAddr("10.0.0.2"),   // Not local path (IsLocal() == false)
	}
	nlri := bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(0, nil)}
	nlriAttr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_RTC_UC, []bgp.PathNLRI{nlri})
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		nlriAttr,
	}
	pathWithLocalID := NewPath(bgp.RF_RTC_UC, sourceWithLocalID, nlri, false, attrs, time.Now(), false)
	updatedPath1 := UpdatePathAttrs(logger, global, info, pathWithLocalID)

	attr1 := updatedPath1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID)
	originatorID1 := attr1.(*bgp.PathAttributeOriginatorId).Value
	assert.True(t, originatorID1.IsValid(), "Originator ID attribute should be set for RTC route")
	assert.Equal(t, "10.0.0.100", originatorID1.String(),
		"Originator ID should be src.LocalID when path is not local")

	// Case 2: Source with LocalID nil - should fall back to global.Config.RouterId
	sourceWithoutLocalID := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
	}
	pathWithoutLocalID := NewPath(bgp.RF_RTC_UC, sourceWithoutLocalID, nlri, false, attrs, time.Now(), false)
	updatedPath2 := UpdatePathAttrs(logger, global, info, pathWithoutLocalID)

	attr2 := updatedPath2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID)
	originatorID2 := attr2.(*bgp.PathAttributeOriginatorId).Value
	assert.True(t, originatorID2.IsValid(), "Originator ID attribute should be set for RTC route")
	assert.Equal(t, "10.0.0.1", originatorID2.String(),
		"Originator ID should be global.Config.RouterId when path is local")
}

func TestNLRIToIPNet(t *testing.T) {
	_, n1, _ := net.ParseCIDR("30.30.30.0/24")
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	ipNet := nlriToIPNet(nlri)
	assert.Equal(t, n1, ipNet)

	_, n2, _ := net.ParseCIDR("2806:106e:19::/48")
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2806:106e:19::/48"))
	ipNet = nlriToIPNet(nlri)
	assert.Equal(t, n2, ipNet)

	labels := bgp.NewMPLSLabelStack(100, 200)
	_, n3, _ := net.ParseCIDR("30.30.30.0/24")
	mpls, _ := bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"), *labels)
	ipNet = nlriToIPNet(mpls)
	assert.Equal(t, n3, ipNet)

	_, n4, _ := net.ParseCIDR("2806:106e:19::/48")
	mpls, _ = bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix("2806:106e:19::/48"), *labels)
	ipNet = nlriToIPNet(mpls)
	assert.Equal(t, n4, ipNet)

	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	_, n5, _ := net.ParseCIDR("40.40.40.0/24")
	vpnv4, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("40.40.40.0/24"), *labels, rd)
	ipNet = nlriToIPNet(vpnv4)
	assert.Equal(t, n5, ipNet)

	_, n6, _ := net.ParseCIDR("2001:db8:53::/64")
	vpnv6, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("2001:db8:53::/64"), *labels, rd)
	ipNet = nlriToIPNet(vpnv6)
	assert.Equal(t, n6, ipNet)
}

func TestUnknownPathAttributes(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)

	type255 := bgp.BGPAttrType(255)
	unknownAttr := bgp.NewPathAttributeUnknown(bgp.BGPAttrFlag(0), type255, []byte{0x01, 0x02, 0x03})
	pathP[0].setPathAttr(unknownAttr)

	// Check if the unknown attribute is present
	assert.NotNil(t, pathP[0].getPathAttr(type255))

	found255 := false
	var last bgp.BGPAttrType
	for _, attr := range pathP[0].GetPathAttrs() {
		assert.NotNil(t, attr)
		if last >= attr.GetType() {
			t.Errorf("Path attributes are not sorted: %v >= %v", last, attr.GetType())
		}
		last = attr.GetType()
		if attr.GetType() == type255 {
			found255 = true
		}
	}
	assert.True(t, found255, "Unknown attribute of type 255 should be present in the path attributes list")
}

// attrsHashLikeEagerSites mirrors the eager hash computation used for
// paths originating from ProcessMessage: farm.Hash64 over the serialized
// path attributes excluding MP_REACH_NLRI.
func attrsHashLikeEagerSites(p *Path) uint64 {
	total := bytes.NewBuffer(make([]byte, 0))
	for _, a := range p.GetPathAttrs() {
		if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
			continue
		}
		b, _ := a.Serialize()
		total.Write(b)
	}
	return farm.Hash64(total.Bytes())
}

func mupT1stPath(t *testing.T, teid netip.Addr, nexthop netip.Addr) *Path {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := bgp.NewMUPType1SessionTransformedRoute(rd, netip.MustParsePrefix("10.10.10.1/32"), teid, 9, netip.MustParseAddr("10.10.10.1"), nil)
	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_MUP_IPv4, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		mpreach,
	}
	return NewPath(bgp.RF_MUP_IPv4, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func ipv4Path(t *testing.T, nexthop netip.Addr) *Path {
	t.Helper()
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.20.30.0/24"))
	nh, err := bgp.NewPathAttributeNextHop(nexthop)
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func TestPathEqual(t *testing.T) {
	teid1 := netip.MustParseAddr("0.0.0.100")
	teid2 := netip.MustParseAddr("0.0.0.200")
	nh1 := netip.MustParseAddr("10.0.0.1")
	nh2 := netip.MustParseAddr("10.0.0.2")

	t.Run("same pointer", func(t *testing.T) {
		p := ipv4Path(t, nh1)
		assert.True(t, p.Equal(p))
	})

	t.Run("clone", func(t *testing.T) {
		p := ipv4Path(t, nh1)
		assert.True(t, p.Equal(p.Clone(false)))
	})

	t.Run("identical, independently built", func(t *testing.T) {
		assert.True(t, ipv4Path(t, nh1).Equal(ipv4Path(t, nh1)))
		assert.True(t, mupT1stPath(t, teid1, nh1).Equal(mupT1stPath(t, teid1, nh1)))
	})

	t.Run("NEXT_HOP attribute differs", func(t *testing.T) {
		assert.False(t, ipv4Path(t, nh1).Equal(ipv4Path(t, nh2)))
	})

	t.Run("MP_REACH nexthop differs", func(t *testing.T) {
		lhs := mupT1stPath(t, teid1, nh1)
		rhs := mupT1stPath(t, teid1, nh2)
		// eager hashes collide because MP_REACH_NLRI is excluded from them
		lhs.SetHash(attrsHashLikeEagerSites(lhs))
		rhs.SetHash(attrsHashLikeEagerSites(rhs))
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.False(t, lhs.Equal(rhs))
	})

	t.Run("MP_REACH nexthop differs with NEXT_HOP present", func(t *testing.T) {
		// an UPDATE carrying both IPv4 NLRI and MP_REACH_NLRI is valid; the MP
		// paths built from it then hold a NEXT_HOP attribute alongside MP_REACH
		newMixedPath := func(mpNexthop string) *Path {
			nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:10::/64"))
			panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
			mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}},
				netip.MustParseAddr(mpNexthop))
			assert.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
				panh,
				mpreach,
			}
			p := NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			p.SetHash(attrsHashLikeEagerSites(p))
			return p
		}
		lhs := newMixedPath("2001:db8::1")
		rhs := newMixedPath("2001:db8::2")
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.False(t, lhs.Equal(rhs))
	})

	t.Run("MP_REACH link-local nexthop differs", func(t *testing.T) {
		newV6Path := func(ll string) *Path {
			nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:10::/64"))
			mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}},
				netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr(ll))
			assert.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
				mpreach,
			}
			p := NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			p.SetHash(attrsHashLikeEagerSites(p))
			return p
		}
		lhs := newV6Path("fe80::1")
		rhs := newV6Path("fe80::2")
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.Equal(t, lhs.GetNexthop(), rhs.GetNexthop())
		assert.False(t, lhs.Equal(rhs))
	})

	t.Run("NLRI payload outside the route key differs", func(t *testing.T) {
		lhs := mupT1stPath(t, teid1, nh1)
		rhs := mupT1stPath(t, teid2, nh1)
		// same route key (TEID is not part of it), same eager hash
		assert.Equal(t, lhs.GetNlri().String(), rhs.GetNlri().String())
		lhs.SetHash(attrsHashLikeEagerSites(lhs))
		rhs.SetHash(attrsHashLikeEagerSites(rhs))
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.False(t, lhs.Equal(rhs))
	})
}

// A path hashed eagerly in ProcessMessage and an identical one hashed
// lazily via updateHash must produce the same value, or Equal reports a
// spurious difference and packerV4 batching splits buckets.
func TestPathAttrsHashConsistency(t *testing.T) {
	teid := netip.MustParseAddr("0.0.0.100")
	nh := netip.MustParseAddr("10.0.0.1")

	eager := mupT1stPath(t, teid, nh)
	eager.SetHash(attrsHashLikeEagerSites(eager))
	lazy := mupT1stPath(t, teid, nh)

	assert.Equal(t, eager.GetHash(), lazy.GetHash())
	assert.True(t, eager.Equal(lazy))
}

func TestFilterCommunities(t *testing.T) {
	// The large community is in every case to pin the documented decision that
	// send-community never touches it: the OpenConfig enum cannot express
	// "send large", so "none" stripping it would make it unsendable.
	newPath := func() *Path {
		nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
		nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
		rt, _ := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
		ip6rt, _ := bgp.NewIPv6AddressSpecificExtended(
			bgp.EC_SUBTYPE_ROUTE_TARGET, netip.MustParseAddr("2001:db8::1"), 100, true)
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			nexthop,
			bgp.NewPathAttributeCommunities([]uint32{65000<<16 | 1}),
			bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
			bgp.NewPathAttributeIP6ExtendedCommunities([]bgp.ExtendedCommunityInterface{ip6rt}),
			bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{{ASN: 65000, LocalData1: 1, LocalData2: 2}}),
		}
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	}

	for _, tt := range []struct {
		name    string
		typ     oc.CommunityType
		wantStd bool
		wantExt bool
	}{
		// Unset is the upgrade-safety case: a peer that never configured this
		// must keep receiving everything, extended communities included.
		{"unset", "", true, true},
		{"standard", oc.COMMUNITY_TYPE_STANDARD, true, false},
		{"extended", oc.COMMUNITY_TYPE_EXTENDED, false, true},
		{"both", oc.COMMUNITY_TYPE_BOTH, true, true},
		{"none", oc.COMMUNITY_TYPE_NONE, false, false},
		// Unrecognised values reach here only from the gRPC path, which maps
		// them to "" - but assert the no-op rather than trusting that.
		{"unrecognised", oc.CommunityType("all"), true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := newPath()
			p.FilterCommunities(tt.typ)
			assert.Equal(t, tt.wantStd, p.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES) != nil, "standard")
			assert.Equal(t, tt.wantExt, p.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES) != nil, "extended")
			// Attr 25 tracks attr 16 in every row. That it tracks rather than
			// being asserted independently is the point: RFC 5701's IPv6 form is
			// a wider encoding of the same concept, not a separate one.
			assert.Equal(t, tt.wantExt, p.getPathAttr(bgp.BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES) != nil, "ipv6 extended")
			assert.NotNil(t, p.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY), "large is never stripped")
		})
	}
}

func TestFilterCommunitiesLeavesHashCleanWhenNothingToStrip(t *testing.T) {
	// delPathAttr unconditionally invalidates attrsHash and grows path.dels, so
	// an unguarded delete would cost a rehash on every advertised path.
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	p := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nexthop}, time.Now(), false)

	p.FilterCommunities(oc.COMMUNITY_TYPE_NONE)
	assert.Empty(t, p.dels)
}

// The allowlist is pinned exhaustively rather than by example, and that is
// deliberate. In most families communities are protocol payload: VPN and EVPN
// carry the Route Target that CanImportToVrf gates on, and every FlowSpec
// traffic action is an extended community - strip those and a discard rule
// arrives as a bare accept, which fails open.
//
// This test is EXPECTED TO FAIL on an upstream catch-up that adds an address
// family. The correct response is to classify the new family and add it to one
// side of this table with a reason. Loosening the assertion removes the only
// guard against the fail-open case above.
func TestFilterCommunitiesOnlyFiltersAllowlistedFamilies(t *testing.T) {
	filtered := map[bgp.Family]bool{
		bgp.RF_IPv4_UC:   true,
		bgp.RF_IPv6_UC:   true,
		bgp.RF_IPv4_MPLS: true,
		bgp.RF_IPv6_MPLS: true,
	}

	for f, name := range bgp.AddressFamilyNameMap {
		want := filtered[f]
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, want, SendCommunityFilterApplies(f),
				"family %s: if this is a new family, classify it - do not loosen the assertion", name)
		})
	}

	// And prove the predicate is actually load-bearing, not just consulted: a
	// VPN path carrying a Route Target must come through "none" untouched.
	rt, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	require.NoError(t, err)
	rd, err := bgp.ParseRouteDistinguisher("65000:100")
	require.NoError(t, err)
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(
		netip.MustParsePrefix("10.0.0.0/24"), *bgp.NewMPLSLabelStack(100), rd)
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeCommunities([]uint32{65000<<16 | 1}),
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
	}
	p := NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	p.FilterCommunities(oc.COMMUNITY_TYPE_NONE)
	assert.NotEmpty(t, p.GetRouteTargets(), "stripping the RT would make this route unimportable")
	assert.NotNil(t, p.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES), "VPN is exempt entirely")
}

// LLGR_STALE is stamped by AdjRib.MarkLLGRStaleOrDrop and re-advertised onward.
// Stripping it while still honouring the capability the peer negotiated would
// leave that peer treating stale routes as fresh.
func TestFilterCommunitiesPreservesLLGR(t *testing.T) {
	const ordinary = uint32(65000<<16 | 1)
	newPath := func(comms ...uint32) *Path {
		nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeCommunities(comms),
		}
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	}

	for _, typ := range []oc.CommunityType{
		"", oc.COMMUNITY_TYPE_STANDARD, oc.COMMUNITY_TYPE_EXTENDED,
		oc.COMMUNITY_TYPE_BOTH, oc.COMMUNITY_TYPE_NONE,
	} {
		t.Run("survives_"+string(typ), func(t *testing.T) {
			p := newPath(ordinary, uint32(bgp.COMMUNITY_LLGR_STALE), uint32(bgp.COMMUNITY_NO_LLGR))
			p.FilterCommunities(typ)
			assert.Contains(t, p.GetCommunities(), uint32(bgp.COMMUNITY_LLGR_STALE), "llgr-stale")
			assert.Contains(t, p.GetCommunities(), uint32(bgp.COMMUNITY_NO_LLGR), "no-llgr")

			stripsStandard := typ == oc.COMMUNITY_TYPE_EXTENDED || typ == oc.COMMUNITY_TYPE_NONE
			assert.Equal(t, !stripsStandard, slices.Contains(p.GetCommunities(), ordinary),
				"the ordinary community is the one that should go")
		})
	}

	// With nothing worth keeping the attribute is removed outright, not left as
	// an empty list.
	p := newPath(ordinary)
	p.FilterCommunities(oc.COMMUNITY_TYPE_NONE)
	assert.Nil(t, p.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES))

	// And with only LLGR present there is nothing to strip, so the attribute
	// must not be rewritten at all - see the hash-churn test below.
	p = newPath(uint32(bgp.COMMUNITY_LLGR_STALE))
	p.FilterCommunities(oc.COMMUNITY_TYPE_NONE)
	assert.Empty(t, p.dels)
}
