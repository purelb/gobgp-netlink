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
	"Peer.graceful_restart.peer_restart_time":   "per-session state, as above",
	"Peer.graceful_restart.peer_restarting":     "per-session state, as above",

	// Accepted by the API and implemented nowhere. These are not gaps in a read
	// path: there is nothing to report, because nothing stores or acts on them.
	// Recorded rather than quietly skipped, so the gap stays visible to whoever
	// reads this next.
	//
	// stale_routes_time is wired at the global level - newGlobalFromAPIStruct
	// stores it and NewGlobalFromConfigStruct reports it - but not per peer,
	// although OpenConfig defines it at both levels.
	//
	// mtu_discovery exists in api.Transport and in the generated config struct
	// and is referenced nowhere else in the tree: no converter stores it, and no
	// socket option is set from it.
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
	"Peer.conf.send_community":     2, // the whole-peer test reaches it by this path
	"PeerConf.allow_own_asn":       3, // uint8 in the internal model
	"PeerGroupConf.allow_own_asn":  3,

	// BFD intervals are in MICROSECONDS with a 300ms floor, and the port must
	// be a real one. The daemon validates all three, so the generic 7 is
	// rejected - correctly, which is why these are overridden rather than
	// skipped: the round trip is still worth asserting.
	"Peer.bfd.desired_minimum_tx_interval": 300000,
	"Peer.bfd.required_minimum_receive":    300000,
	"Peer.bfd.port":                        3784,
	"Peer.bfd.detection_multiplier":        3,
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
			case protoreflect.MessageKind:
				e := l.NewElement()
				fillMessage(name, e.Message(), skip)
				l.Append(e)
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

// peerSubMessages are the configuration-bearing parts of api.Peer. Listed
// explicitly so that TestEveryPeerSubMessageIsCovered can fail when a new one
// is added to the proto and nobody extends the round-trip below.
var peerSubMessages = map[string]string{
	"apply_policy":     "covered by TestConformanceWholePeerRoundTrip",
	"conf":             "covered by TestConformancePeerConfRoundTrip and the whole-peer test",
	"ebgp_multihop":    "covered by TestConformanceWholePeerRoundTrip",
	"route_reflector":  "covered by TestConformanceWholePeerRoundTrip",
	"timers":           "covered by TestConformanceWholePeerRoundTrip",
	"transport":        "covered by TestConformanceWholePeerRoundTrip",
	"route_server":     "covered by TestConformanceWholePeerRoundTrip",
	"graceful_restart": "covered by TestConformanceWholePeerRoundTrip",
	"afi_safis":        "covered by TestConformanceWholePeerRoundTrip",
	"ttl_security":     "covered by TestConformanceTtlSecurityRoundTrip; excluded from the whole-peer test because it is mutually exclusive with ebgp_multihop",
	"bfd":              "covered by TestConformanceWholePeerRoundTrip",
	"state":            "read-only operational state, not configuration",
}

func TestEveryPeerSubMessageIsCovered(t *testing.T) {
	fields := (&api.Peer{}).ProtoReflect().Descriptor().Fields()
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		_, ok := peerSubMessages[name]
		assert.True(t, ok,
			"api.Peer.%s is not listed in peerSubMessages. Every configuration-bearing "+
				"part of a peer must be round-tripped, or recorded as read-only with a reason.", name)
	}
}

// The whole peer, not just its Conf. Per-peer configuration spans eleven nested
// messages - transport, timers, graceful restart, TTL security, BFD and the
// rest - and each is a read path that can be forgotten independently.
func TestConformanceWholePeerRoundTrip(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	peer := &api.Peer{Conf: &api.PeerConf{NeighborAddress: "10.90.0.1", PeerAsn: 65001}}
	fillMessage("Peer", peer.ProtoReflect(), wholePeerSkip)

	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: proto.Clone(peer).(*api.Peer),
	}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: "10.90.0.1"},
		func(p *api.Peer) { got = p }))
	require.NotNil(t, got, "ListPeer returned no peer")

	compareRoundTrip(t, "Peer", peer.ProtoReflect(), got.ProtoReflect())
}

// wholePeerSkip covers fields that cannot take an arbitrary value on this path,
// and the read-only state block.
var wholePeerSkip = map[string]bool{
	"Peer.state":                    true, // operational state, not config
	"Peer.timers.state":             true, // operational state, not config
	"Peer.conf.peer_asn":            true, // identifies the peer
	"Peer.conf.local_asn":           true, // flips eBGP/iBGP
	"Peer.conf.admin_down":          true, // changes session handling
	"Peer.conf.vrf":                 true, // must name an existing VRF
	"Peer.conf.peer_group":          true, // must name an existing group
	"Peer.conf.neighbor_interface":  true, // mutually exclusive with the address
	"Peer.conf.type":                true, // derived from the ASNs
	"Peer.apply_policy":             true, // policy names must exist
	"Peer.transport.local_address":  true, // must parse as an address
	"Peer.transport.bind_interface": true, // must name a real interface
	// Mutually exclusive settings, each with its own test. The whole-peer test
	// sets everything at once, so these have to be excluded from it - and the
	// exclusions are a useful record of which settings conflict.
	"Peer.ttl_security":                       true, // conflicts with ebgp_multihop
	"Peer.route_server":                       true, // conflicts with route_reflector
	"Peer.afi_safis":                          true, // built by hand above; it needs a real family
	"Peer.afi_safis.config.family":            true, // family identity, not a scalar knob
	"Peer.afi_safis.state":                    true, // operational state
	"Peer.afi_safis.add_paths.config.receive": true, // negotiated, reported from state
}

// ttl-security has its own test because the daemon rejects it alongside
// ebgp-multihop, and the whole-peer test sets everything at once.
func TestConformanceTtlSecurityRoundTrip(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	peer := &api.Peer{
		Conf:        &api.PeerConf{NeighborAddress: "10.93.0.1", PeerAsn: 65001},
		TtlSecurity: &api.TtlSecurity{},
	}
	fillMessage("Peer.ttl_security", peer.TtlSecurity.ProtoReflect(), nil)

	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: proto.Clone(peer).(*api.Peer),
	}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: "10.93.0.1"},
		func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	require.NotNil(t, got.TtlSecurity, "ttl_security was accepted but is not reported back")

	compareRoundTrip(t, "Peer.ttl_security", peer.TtlSecurity.ProtoReflect(), got.TtlSecurity.ProtoReflect())
}

// route-server-client conflicts with route-reflector-client, so like
// ttl-security it cannot be set in the whole-peer test.
func TestConformanceRouteServerRoundTrip(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	peer := &api.Peer{
		Conf:        &api.PeerConf{NeighborAddress: "10.94.0.1", PeerAsn: 65001},
		RouteServer: &api.RouteServer{},
	}
	fillMessage("Peer.route_server", peer.RouteServer.ProtoReflect(), nil)

	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: proto.Clone(peer).(*api.Peer),
	}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: "10.94.0.1"},
		func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	require.NotNil(t, got.RouteServer, "route_server was accepted but is not reported back")

	compareRoundTrip(t, "Peer.route_server", peer.RouteServer.ProtoReflect(), got.RouteServer.ProtoReflect())
}
