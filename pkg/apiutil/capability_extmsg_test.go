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

package apiutil

import (
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

// TestMarshalEveryCapabilityType is a daemon-crash gate found on hardware.
//
// MarshalCapabilities returns an error for any capability it has no case for,
// NewPeerFromConfigStruct turns that into a nil *api.Peer, and ListPeer used to
// dereference it. So one unmarshalable capability advertised by one peer killed
// gobgpd on any ListPeer - which k8gobgp issues on every reconcile.
//
// That is not hypothetical: taking pkg/packet from v4.9.0 taught the parser to
// recognise RFC 8654, so what previously arrived as CapUnknown became a real
// *bgp.CapExtendedMessage with no case here. FRR 10.4 advertises it, so the
// daemon paniced against a live peer within a minute of starting.
//
// The table is deliberately exhaustive rather than testing only RFC 8654: the
// failure mode is "pkg/packet learned a type apiutil has not", and it will
// recur on the next catch-up unless every type is covered.
func TestMarshalEveryCapabilityType(t *testing.T) {
	f := bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST)

	for _, cap := range []bgp.ParameterCapabilityInterface{
		bgp.NewCapExtendedMessage(),
		bgp.NewCapMultiProtocol(f),
		bgp.NewCapRouteRefresh(),
		bgp.NewCapCarryingLabelInfo(),
		bgp.NewCapFourOctetASNumber(65001),
		bgp.NewCapEnhancedRouteRefresh(),
		bgp.NewCapRouteRefreshCisco(),
		bgp.NewCapFQDN("host", "example.com"),
		bgp.NewCapSoftwareVersion("gobgp"),
	} {
		got, err := MarshalCapability(cap)
		if assert.NoErrorf(t, err, "%T must marshal; an error here becomes a nil peer and a panic in ListPeer", cap) {
			assert.NotNilf(t, got, "%T marshalled to nil", cap)
		}
	}
}
