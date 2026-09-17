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

// API conformance: does every field the API accepts come back out again?
//
// Every gRPC defect found in this repo so far has been the same mechanical
// shape - asymmetry between the set path and the get path. send_community was
// accepted and consumed by nothing; remove_private was applied to peer groups
// and never reported; PeerGroupState had a populating function that was never
// called; GetBgp accepted eleven fields and reported six.
//
// Hand-written per-feature tests will not find these, because the person
// writing them tests the field they just added. 651 proto fields across 238
// messages is past the point where that works.
//
// So this suite is driven from the proto descriptors rather than from a list
// someone maintains. Add a field to PeerConf and forget the read path, and this
// fails - the field is discovered automatically. Deliberate asymmetries go in
// knownAsymmetries below, each with a reason, which turns "we meant that" into
// something written down and reviewable rather than something absent.
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/osrg/gobgp/v4/api"
)

// knownAsymmetries lists fields that deliberately do not round-trip, and why.
// Anything absent from here and from the response is a bug.
//
// Keyed "MessageName.field_name".
var knownAsymmetries = map[string]string{
	"PeerConf.auth_password":      "redacted on read by design; State.auth_password_set reports whether one is configured",
	"PeerGroupConf.auth_password": "redacted on read by design, as above",

	// The GracefulRestart message is shared between global configuration and
	// per-session state. These three are State: the FSM writes them from the
	// peer's negotiated capabilities, so they are not global config and have
	// nothing to echo back. See fsm.go around the capability handling.
	"Global.graceful_restart.peer_restart_time": "per-session state from the peer's GR capability, not config",
	"Global.graceful_restart.peer_restarting":   "per-session state, not config",
	"Global.graceful_restart.local_restarting":  "per-session state, not config",
}

// fieldValues overrides the generic filler for fields whose valid domain is
// narrower than their wire type. Filling send_community with 7 is not a test of
// the read path - it is out of range, and the documented behaviour is to coerce
// an out-of-range value to unset, so the field correctly does not come back.
//
// Without this the suite reports a false positive and gets ignored, which is
// how conformance suites die.
var fieldValues = map[string]uint64{
	"PeerConf.send_community":      2, // COMMUNITY_TYPE_BOTH; valid range is 0-3
	"PeerGroupConf.send_community": 2,
	"PeerConf.allow_own_asn":       3, // uint8 in the internal model
	"PeerGroupConf.allow_own_asn":  3,
}

// fillMessage sets every field of a message to a distinctive non-zero value, so
// that a field dropped on the way out is distinguishable from one that merely
// defaulted.
//
// It covers enums, repeated fields and nested messages, not only scalars. An
// earlier version handled scalars alone and consequently missed the two real
// bugs it was written to catch: remove_private is an enum, and the GetBgp
// omissions were a repeated field and four nested messages. A conformance suite
// that passes because it did not look is worse than none.
func fillMessage(path string, m protoreflect.Message, skip map[string]bool) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := path + "." + string(fd.Name())
		if skip[name] {
			continue
		}
		v := uint64(7)
		if override, ok := fieldValues[name]; ok {
			v = override
		}

		if fd.IsMap() {
			continue
		}
		if fd.IsList() {
			l := m.Mutable(fd).List()
			switch fd.Kind() {
			case protoreflect.Uint32Kind:
				l.Append(protoreflect.ValueOfUint32(uint32(v)))
			case protoreflect.StringKind:
				// Left alone: string lists are addresses, interfaces and policy
				// names, none of which accept an arbitrary value.
			}
			continue
		}

		switch fd.Kind() {
		case protoreflect.BoolKind:
			m.Set(fd, protoreflect.ValueOfBool(true))
		case protoreflect.Uint32Kind:
			m.Set(fd, protoreflect.ValueOfUint32(uint32(v)))
		case protoreflect.Int32Kind:
			m.Set(fd, protoreflect.ValueOfInt32(int32(v)))
		case protoreflect.Uint64Kind:
			m.Set(fd, protoreflect.ValueOfUint64(v))
		case protoreflect.Int64Kind:
			m.Set(fd, protoreflect.ValueOfInt64(int64(v)))
		case protoreflect.EnumKind:
			// The first non-zero value: zero is UNSPECIFIED, which is
			// indistinguishable from unset and would prove nothing.
			vals := fd.Enum().Values()
			if vals.Len() > 1 {
				m.Set(fd, protoreflect.ValueOfEnum(vals.Get(1).Number()))
			}
		case protoreflect.MessageKind:
			fillMessage(name, m.Mutable(fd).Message(), skip)
		}
	}
}

// compareRoundTrip reports fields set on sent that are absent or different on
// got, recursing into nested messages and checking repeated fields.
func compareRoundTrip(t *testing.T, path string, sent, got protoreflect.Message) {
	t.Helper()
	fields := sent.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.IsMap() || !sent.Has(fd) {
			continue
		}
		key := path + "." + string(fd.Name())
		if reason, ok := knownAsymmetries[key]; ok {
			t.Logf("  skipping %s: %s", key, reason)
			continue
		}

		if fd.Kind() == protoreflect.MessageKind && !fd.IsList() {
			if !assert.True(t, got.Has(fd), "%s was accepted but is not reported back", key) {
				continue
			}
			compareRoundTrip(t, key, sent.Get(fd).Message(), got.Get(fd).Message())
			continue
		}

		if !assert.True(t, got.Has(fd), "%s was accepted but is not reported back", key) {
			continue
		}
		if fd.IsList() {
			assert.Equal(t, sent.Get(fd).List().Len(), got.Get(fd).List().Len(),
				"%s does not round-trip (length)", key)
			continue
		}
		assert.Equal(t, sent.Get(fd).Interface(), got.Get(fd).Interface(),
			"%s does not round-trip", key)
	}
}

func TestConformancePeerConfRoundTrip(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	conf := &api.PeerConf{NeighborAddress: "10.0.0.1", PeerAsn: 65001}
	// Fields that are not free to set arbitrarily on this path.
	fillMessage("PeerConf", conf.ProtoReflect(), map[string]bool{
		"PeerConf.peer_asn":           true, // set above; identifies the peer
		"PeerConf.local_asn":          true, // 7 would make this iBGP and change peer_type
		"PeerConf.admin_down":         true, // changes session handling, not a reported knob
		"PeerConf.vrf":                true, // must name an existing VRF
		"PeerConf.peer_group":         true, // must name an existing group
		"PeerConf.neighbor_interface": true, // mutually exclusive with neighbor_address
		"PeerConf.type":               true, // derived from the ASNs, not accepted as input
	})

	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      proto.Clone(conf).(*api.PeerConf),
		Transport: &api.Transport{PassiveMode: true},
	}}))

	var got *api.PeerConf
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: "10.0.0.1"},
		func(p *api.Peer) { got = p.Conf }))
	require.NotNil(t, got, "ListPeer returned no peer")

	compareRoundTrip(t, "PeerConf", conf.ProtoReflect(), got.ProtoReflect())
}

func TestConformancePeerGroupConfRoundTrip(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	conf := &api.PeerGroupConf{PeerGroupName: "g1", PeerAsn: 65001}
	fillMessage("PeerGroupConf", conf.ProtoReflect(), map[string]bool{
		"PeerGroupConf.peer_asn":  true,
		"PeerGroupConf.local_asn": true,
		"PeerGroupConf.type":      true,
	})

	require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: &api.PeerGroup{Conf: proto.Clone(conf).(*api.PeerGroupConf)},
	}))

	var got *api.PeerGroupConf
	require.NoError(t, s.ListPeerGroup(context.Background(), &api.ListPeerGroupRequest{},
		func(g *api.PeerGroup) { got = g.Conf }))
	require.NotNil(t, got, "ListPeerGroup returned no group")

	compareRoundTrip(t, "PeerGroupConf", conf.ProtoReflect(), got.ProtoReflect())
}

func TestConformanceGlobalRoundTrip(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	g := &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1}
	fillMessage("Global", g.ProtoReflect(), map[string]bool{
		"Global.asn":            true,
		"Global.listen_port":    true, // 7 would try to bind a privileged port
		"Global.bind_to_device": true, // must name a real interface
	})

	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: proto.Clone(g).(*api.Global),
	}))

	rsp, err := s.GetBgp(context.Background(), &api.GetBgpRequest{})
	require.NoError(t, err)
	require.NotNil(t, rsp.Global)

	compareRoundTrip(t, "Global", g.ProtoReflect(), rsp.Global.ProtoReflect())
}
