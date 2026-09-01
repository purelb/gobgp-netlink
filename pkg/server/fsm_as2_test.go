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

package server

import (
	"net"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

// TestRecvUpdateFromTwoByteAsPeer pins the MarshallingOption the receive path
// must pass.
//
// The merge-base decoder guessed the AS width with a
// try-4-byte-then-try-2-byte heuristic and needed no option. v4.9.0 replaces
// that with an explicit one - validate.go does `if opt != nil &&
// opt.Use2ByteAS` - so a receive path that omits it mis-parses every AS_PATH
// from a peer that did not negotiate 4-byte AS. The symptom is a NOTIFICATION
// and a session that will not stay up, against exactly the peers least likely
// to be modern.
//
// CI's `as2` job covers this end to end with exabgp's `asn4 disable`, but it
// needs Docker; this keeps the contract checkable in a unit run.
func TestRecvUpdateFromTwoByteAsPeer(t *testing.T) {
	prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.0.0/24"))
	assert.NoError(t, err)
	nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	assert.NoError(t, err)

	update := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		// 2-byte ASNs, as a peer without the 4-byte AS capability sends them.
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002}),
		}),
		nexthop,
	}, []bgp.PathNLRI{{NLRI: prefix}})

	wire, err := update.Serialize(&bgp.MarshallingOption{Use2ByteAS: true})
	assert.NoError(t, err)

	local, remote := net.Pipe()
	p, h := makePeerAndHandler(local)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	// What open2Cap sets when the peer did not advertise 4-byte AS support.
	h.fsm.twoByteAsTrans = true

	go func() {
		_, _ = remote.Write(wire)
	}()

	fmsg, err := h.recvMessageWithError(local, make(chan fsmStateReason, 1))
	assert.NoError(t, err, "a 2-byte AS_PATH from a 2-byte-AS peer must parse")
	if assert.NotNil(t, fmsg) {
		assert.NotEqual(t, bgp.ERROR_HANDLING_SESSION_RESET, fmsg.handling,
			"mis-parsing the AS_PATH resets the session against legacy peers")
	}
}
