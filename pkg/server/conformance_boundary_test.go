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

// API conformance: boundary values.
//
// The round-trip suite fills fields with a small value, which proves the read
// path exists. It does not prove the value survives intact, because the
// internal config model is narrower than the wire in several places - the API
// takes uint32 where oc takes uint8 - and a bare conversion truncates.
//
// allow_own_asn was exactly that: the API accepted 256, stored uint8(256) = 0,
// and reported 0. Since 0 means "do not allow our own ASN at all", asking for
// the loosest setting silently produced the strictest. It fails closed, so
// nothing leaks; the peer just rejects paths it was meant to accept.
//
// The property asserted here is simple and holds for every numeric field:
//
//	an accepted value must come back unchanged.
//
// Rejecting a value is fine. Preserving it is fine. Accepting it and silently
// storing something else is always a bug, and is the shape truncation takes.
package server

import (
	"context"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/osrg/gobgp/v4/api"
)

// boundarySkip lists numeric fields that cannot be probed this way, with the
// reason. These are fields where a maximal value changes what the request
// means rather than testing a conversion.
var boundarySkip = map[string]string{
	"PeerConf.peer_asn":       "identifies the peer; a different value is a different peer",
	"PeerConf.local_asn":      "changes peer_type between eBGP and iBGP, so the peer is not comparable",
	"PeerConf.type":           "derived from the ASNs rather than accepted as input",
	"PeerConf.remove_private": "enum, not a numeric range",

	// A deliberate, documented divergence rather than a narrowing bug, and the
	// one place this suite's property is knowingly broken.
	//
	// send_community coerces an out-of-range value to unset instead of
	// rejecting it, because the field was ignored entirely before v1.3.1 and a
	// client that had been pushing junk into it keeps working exactly as it
	// did. The TOML path rejects the equivalent typo, because that is a human
	// editing a file rather than an existing client.
	//
	// Worth revisiting once the v1.3.0 compatibility window has passed: the
	// argument is about clients written before the field did anything, and it
	// weakens over time.
	"PeerConf.send_community": "out-of-range coerced to unset by design for pre-v1.3.1 clients; see SendCommunityFromAPI",
}

func TestConformancePeerConfBoundaryValues(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	fields := (&api.PeerConf{}).ProtoReflect().Descriptor().Fields()
	octet := 0
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.Uint32Kind || fd.IsList() {
			continue
		}
		name := "PeerConf." + string(fd.Name())
		if reason, skipped := boundarySkip[name]; skipped {
			t.Logf("skipping %s: %s", name, reason)
			continue
		}

		octet++
		addr := fmt.Sprintf("10.80.%d.1", octet)
		t.Run(string(fd.Name()), func(t *testing.T) {
			conf := &api.PeerConf{NeighborAddress: addr, PeerAsn: 65001}
			conf.ProtoReflect().Set(fd, protoreflect.ValueOfUint32(math.MaxUint32))

			err := s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
				Conf:      conf,
				Transport: &api.Transport{PassiveMode: true},
			}})
			if err != nil {
				// Rejecting an out-of-range value is the correct outcome.
				t.Logf("%s rejected at the boundary: %v", name, err)
				return
			}

			var got *api.PeerConf
			require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: addr},
				func(p *api.Peer) { got = p.Conf }))
			require.NotNil(t, got, "peer accepted but not returned")

			assert.Equal(t, uint32(math.MaxUint32), got.ProtoReflect().Get(fd).Uint(),
				"%s was accepted but stored as something else - a silent narrowing", name)
		})
	}
}
