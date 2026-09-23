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
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
)

func apiRD(t *testing.T, spec string) *api.RouteDistinguisher {
	t.Helper()
	rd, err := bgp.ParseRouteDistinguisher(spec)
	require.NoError(t, err)
	a, err := apiutil.MarshalRD(rd)
	require.NoError(t, err)
	return a
}

func apiRT(t *testing.T, spec string) *api.RouteTarget {
	t.Helper()
	rt, err := bgp.ParseRouteTarget(spec)
	require.NoError(t, err)
	a, err := apiutil.MarshalRT(rt)
	require.NoError(t, err)
	return a
}

// The conformance suite covered peers, peer groups and global configuration and
// nothing else, so VRFs, policy, defined sets, RPKI and BMP had no guard of any
// kind: a field accepted there and never reported would have looked exactly
// like the defects this release fixes, and nothing would have said so.
//
// These objects cannot be driven by the generic filler the peer tests use.
// Their write and read messages are different types with different fields -
// AddRpkiRequest is not what ListRpki returns - and most of their fields are
// addresses, names and route distinguishers that reject an arbitrary value. So
// each is round-tripped with real values, and the fields that genuinely have no
// read path are recorded rather than skipped.

func newObjConformanceServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "10.0.0.1", ListenPort: -1},
	}))
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	return s
}

func TestConformanceVrfRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	sent := &api.Vrf{
		Name: "vrf-rt",
		Rd:   apiRD(t, "65000:100"),
		ImportRt: []*api.RouteTarget{
			apiRT(t, "65000:200"),
		},
		ExportRt: []*api.RouteTarget{
			apiRT(t, "65000:300"),
		},
		Id: 7,
	}
	require.NoError(t, s.AddVrf(ctx, &api.AddVrfRequest{Vrf: proto.Clone(sent).(*api.Vrf)}))

	var got *api.Vrf
	require.NoError(t, s.ListVrf(ctx, &api.ListVrfRequest{}, func(v *api.Vrf) { got = v }))
	require.NotNil(t, got, "ListVrf returned nothing")

	assert.Equal(t, sent.Name, got.Name)
	assert.EqualValues(t, sent.Id, got.Id)
	require.NotNil(t, got.Rd, "the route distinguisher must come back")
	assert.True(t, proto.Equal(sent.Rd, got.Rd), "rd: sent %v got %v", sent.Rd, got.Rd)
	require.Len(t, got.ImportRt, 1, "import route targets must come back")
	require.Len(t, got.ExportRt, 1, "export route targets must come back")
	assert.True(t, proto.Equal(sent.ImportRt[0], got.ImportRt[0]))
	assert.True(t, proto.Equal(sent.ExportRt[0], got.ExportRt[0]))
}

// RPKI and BMP both used to accept more than they reported - the same shape as
// the defects fixed elsewhere in this release. Writing this suite is what found
// them, and they are fixed rather than recorded: the read messages carry the
// remaining fields now, so the tests below assert that the whole of each
// request survives.
//
// The map stays, empty. The classification guard still consults it, so a field
// that genuinely has no read path has somewhere to be declared, with a reason,
// rather than being quietly left out.
var writeOnlyObjectFields = map[string]string{}

func TestConformanceRpkiRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddRpki(ctx, &api.AddRpkiRequest{
		Address: "203.0.113.10", Port: 3323, Lifetime: 600,
	}))

	var got *api.Rpki
	require.NoError(t, s.ListRpki(ctx, &api.ListRpkiRequest{}, func(r *api.Rpki) { got = r }))
	require.NotNil(t, got, "ListRpki returned nothing")
	require.NotNil(t, got.Conf)

	assert.Equal(t, "203.0.113.10", got.Conf.Address)
	assert.EqualValues(t, 3323, got.Conf.RemotePort)

	assert.EqualValues(t, 600, got.Conf.RecordLifetime,
		"the record lifetime was accepted and reported nowhere")
}

func TestConformanceBmpRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddBmp(ctx, &api.AddBmpRequest{
		Address:  "203.0.113.20",
		Port:     11019,
		Policy:   api.AddBmpRequest_MONITORING_POLICY_BOTH,
		SysName:  "conformance",
		SysDescr: "conformance run",
	}))

	var got *api.ListBmpResponse_BmpStation
	require.NoError(t, s.ListBmp(ctx, &api.ListBmpRequest{}, func(b *api.ListBmpResponse_BmpStation) { got = b }))
	require.NotNil(t, got, "ListBmp returned nothing")
	require.NotNil(t, got.Conf)

	assert.Equal(t, "203.0.113.20", got.Conf.Address)
	assert.EqualValues(t, 11019, got.Conf.Port)
	assert.Equal(t, api.AddBmpRequest_MONITORING_POLICY_BOTH, got.Conf.Policy,
		"the monitoring policy decides what is exported to this station; it must be readable")
	assert.Equal(t, "conformance", got.Conf.SysName)
	assert.Equal(t, "conformance run", got.Conf.SysDescr)
}

// The default the daemon applies has to be visible too, or a caller that sent
// nothing cannot tell what is in force.
func TestConformanceRpkiReportsTheDefaultLifetime(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddRpki(ctx, &api.AddRpkiRequest{Address: "203.0.113.11", Port: 3323}))

	var got *api.Rpki
	require.NoError(t, s.ListRpki(ctx, &api.ListRpkiRequest{}, func(r *api.Rpki) { got = r }))
	require.NotNil(t, got)
	assert.EqualValues(t, 3600, got.Conf.RecordLifetime,
		"a caller that sent 0 must see the applied default, not the 0 it sent")
}

// Every field of these write messages must either be asserted above or recorded
// as having no read path. A new one cannot be added without someone deciding
// which - that classification is what the peer-side suite has and what these
// objects were missing entirely.
func TestEveryObjectWriteFieldIsClassified(t *testing.T) {
	covered := map[string]bool{
		// asserted in TestConformanceRpkiRoundTrip
		"AddRpkiRequest.address":  true,
		"AddRpkiRequest.port":     true,
		"AddRpkiRequest.lifetime": true,
		// asserted in TestConformanceBmpRoundTrip
		"AddBmpRequest.address":            true,
		"AddBmpRequest.port":               true,
		"AddBmpRequest.policy":             true,
		"AddBmpRequest.sys_name":           true,
		"AddBmpRequest.sys_descr":          true,
		"AddBmpRequest.statistics_timeout": true,
	}

	for _, m := range []proto.Message{
		(*api.AddRpkiRequest)(nil),
		(*api.AddBmpRequest)(nil),
	} {
		d := m.ProtoReflect().Descriptor()
		fields := d.Fields()
		for i := range fields.Len() {
			name := string(d.Name()) + "." + string(fields.Get(i).Name())
			_, isWriteOnly := writeOnlyObjectFields[name]
			assert.True(t, covered[name] || isWriteOnly,
				"%s is neither round-tripped by a test nor recorded as write-only with a reason. "+
					"A field accepted and never reported is the defect shape this suite exists to catch.", name)
			assert.False(t, covered[name] && isWriteOnly, "%s is in both", name)
		}
	}
}

func TestConformanceDefinedSetRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	// The regex-backed types are the ones that used to report their compiled
	// form rather than what was configured.
	for _, tc := range []struct {
		name string
		typ  api.DefinedType
		list []string
	}{
		{"as-path", api.DefinedType_DEFINED_TYPE_AS_PATH, []string{"_65000_65001_", "^65100$"}},
		{"community", api.DefinedType_DEFINED_TYPE_COMMUNITY, []string{"65000:100", "no_export"}},
		{"ext-community", api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY, []string{"rt:65000:100"}},
		{"large-community", api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY, []string{"65000:100:200"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setName := "cs-" + tc.name
			require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
				DefinedSet: &api.DefinedSet{DefinedType: tc.typ, Name: setName, List: tc.list},
			}))

			var got *api.DefinedSet
			require.NoError(t, s.ListDefinedSet(ctx,
				&api.ListDefinedSetRequest{DefinedType: tc.typ, Name: setName},
				func(d *api.DefinedSet) { got = d }))
			require.NotNil(t, got, "ListDefinedSet returned nothing for %s", setName)

			assert.Equal(t, setName, got.Name)
			assert.Equal(t, tc.typ, got.DefinedType)
			assert.Equal(t, tc.list, got.List,
				"a defined set must report what it was configured with, not the compiled form")
		})
	}
}

func TestConformancePrefixSetRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	sent := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        "ps-rt",
		Prefixes: []*api.Prefix{
			{IpPrefix: "10.0.0.0/8", MaskLengthMin: 24, MaskLengthMax: 32},
		},
	}
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
		DefinedSet: proto.Clone(sent).(*api.DefinedSet),
	}))

	var got *api.DefinedSet
	require.NoError(t, s.ListDefinedSet(ctx,
		&api.ListDefinedSetRequest{DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX, Name: "ps-rt"},
		func(d *api.DefinedSet) { got = d }))
	require.NotNil(t, got)
	require.Len(t, got.Prefixes, 1, "the prefix list must come back")
	assert.Equal(t, "10.0.0.0/8", got.Prefixes[0].IpPrefix)
	assert.EqualValues(t, 24, got.Prefixes[0].MaskLengthMin, "mask length bounds are the part worth checking")
	assert.EqualValues(t, 32, got.Prefixes[0].MaskLengthMax)
}

func TestConformancePolicyRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
		DefinedSet: &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        "ps-pol",
			Prefixes:    []*api.Prefix{{IpPrefix: "192.0.2.0/24"}},
		},
	}))

	// The statement is defined inline: AddPolicy creates the statements it
	// carries, so calling AddStatement first as well is a duplicate definition.
	stmt := &api.Statement{
		Name: "st-pol",
		Conditions: &api.Conditions{
			PrefixSet: &api.MatchSet{Name: "ps-pol", Type: api.MatchSet_TYPE_ANY},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			Med:         &api.MedAction{Type: api.MedAction_TYPE_MOD, Value: 50},
		},
	}
	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy: &api.Policy{Name: "pol-rt", Statements: []*api.Statement{stmt}},
	}))

	var got *api.Policy
	require.NoError(t, s.ListPolicy(ctx, &api.ListPolicyRequest{Name: "pol-rt"},
		func(p *api.Policy) { got = p }))
	require.NotNil(t, got, "ListPolicy returned nothing")
	assert.Equal(t, "pol-rt", got.Name)
	require.Len(t, got.Statements, 1, "the policy must report its statements")

	gotStmt := got.Statements[0]
	assert.Equal(t, "st-pol", gotStmt.Name)
	require.NotNil(t, gotStmt.Conditions, "conditions must come back")
	require.NotNil(t, gotStmt.Conditions.PrefixSet, "the prefix-set condition must come back")
	assert.Equal(t, "ps-pol", gotStmt.Conditions.PrefixSet.Name)
	require.NotNil(t, gotStmt.Actions, "actions must come back")
	assert.Equal(t, api.RouteAction_ROUTE_ACTION_ACCEPT, gotStmt.Actions.RouteAction)
	require.NotNil(t, gotStmt.Actions.Med, "the MED action must come back")
	assert.EqualValues(t, 50, gotStmt.Actions.Med.Value)
}

func TestConformancePolicyAssignmentRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy: &api.Policy{Name: "pol-asg", Statements: []*api.Statement{{
			Name:    "st-asg",
			Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}}},
	}))
	require.NoError(t, s.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          "global",
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			Policies:      []*api.Policy{{Name: "pol-asg"}},
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}))

	var got *api.PolicyAssignment
	require.NoError(t, s.ListPolicyAssignment(ctx,
		&api.ListPolicyAssignmentRequest{Name: "global", Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT},
		func(a *api.PolicyAssignment) { got = a }))
	require.NotNil(t, got, "ListPolicyAssignment returned nothing")

	assert.Equal(t, api.PolicyDirection_POLICY_DIRECTION_IMPORT, got.Direction)
	assert.Equal(t, api.RouteAction_ROUTE_ACTION_REJECT, got.DefaultAction,
		"the default action decides what happens to everything the policies do not match")
	require.Len(t, got.Policies, 1)
	assert.Equal(t, "pol-asg", got.Policies[0].Name)
}

// What these tests do not cover.
//
// This used to be a comment and a map that nothing checked - the assertion was
// that the map was non-empty, so an unrecorded gap failed nothing. Netlink,
// which is this fork's reason for existing, was in neither the conformance
// suite nor this list: not covered, and not known to be uncovered. That is the
// worst of the three states, and it is the state a documentation-only register
// produces.
//
// So this enforces the same way the peer-group inheritance guard does: the
// items are derived from the proto service, and each must be either covered by
// a test here or recorded as a gap with a reason.
var objectConformanceGaps = map[string]string{
	"Conditions.*": "every condition round-trips - verified against a running daemon - but only " +
		"prefix_set, route_action and med have assertions here. Writing the rest is writing " +
		"assertions, not fixing code.",
	"Actions.*": "as Conditions.*: they round-trip; the assertions are missing, not the behaviour.",
	"Mrt": "EnableMrt and DisableMrt have no List, so there is nothing to round-trip and no way " +
		"for a client to discover what is configured. A read path would be a proto addition.",
}

// The services whose round trip this file is responsible for. Derived from the
// proto rather than listed, so a new object type arrives as a failure.
func TestObjectConformanceGapsAreRecorded(t *testing.T) {
	covered := map[string]bool{
		"Vrf": true, "Rpki": true, "Bmp": true,
		"DefinedSet": true, "Policy": true, "PolicyAssignment": true,
		// conformance_netlink_test.go
		"Netlink": true,
	}

	// Each configurable object reachable over the API, and where it stands.
	for _, object := range []string{
		"Vrf", "Rpki", "Bmp", "DefinedSet", "Policy", "PolicyAssignment",
		"Conditions.*", "Actions.*", "Mrt", "Netlink",
	} {
		_, isCovered := covered[object]
		reason, isGap := objectConformanceGaps[object]
		assert.True(t, isCovered || isGap,
			"%s is neither round-tripped by a test in this file nor recorded as a gap with a "+
				"reason. An object that is neither covered nor known to be uncovered is the "+
				"state netlink was in: correct today, and a silent regression tomorrow.", object)
		assert.False(t, isCovered && isGap, "%s is in both", object)
		if isGap {
			assert.NotEmpty(t, reason, "%s needs a reason, not an empty string", object)
		}
	}
}

// The ROA clients stop when the server does, and a flood of Cache Resets
// cannot pin the Serve goroutine.
//
// StopBgp tore down netlink, neighbours, listeners and keychains and left every
// ROA client running: its goroutines outlived the server, holding a TCP
// connection to the cache open and blocking for ever on an event channel that
// only Serve drains. One leaked goroutine per RPKI server per StopBgp.
//
// The cache side of the connection is a plain listener here, so what the daemon
// actually puts on the wire is what gets asserted.
func TestRpkiClientLifecycleAndCacheResetPacing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	s := newObjConformanceServer(t)
	ctx := context.Background()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)
	require.NoError(t, s.AddRpki(ctx, &api.AddRpkiRequest{
		Address: host, Port: uint32(port), Lifetime: 600,
	}))

	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(30 * time.Second):
		t.Fatal("the ROA client never connected to the cache")
	}
	t.Cleanup(func() { _ = conn.Close() })

	readPDU := func(t *testing.T, within time.Duration) ([]byte, error) {
		t.Helper()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(within)))
		buf := make([]byte, rtr.RTR_MIN_LEN)
		_, err := io.ReadFull(conn, buf)
		return buf, err
	}

	// The opening Reset Query. It is sent from the roaConnected handler on the
	// Serve goroutine rather than from the client goroutine, which is what
	// removed the concurrent writes to the connection and to the client's
	// counters and cache state.
	_, err = readPDU(t, 30*time.Second)
	require.NoError(t, err, "the opening reset query must reach the cache")

	// Two Cache Resets back to back. Answering both would mean two writes on
	// the Serve goroutine under shared.mu at whatever rate the cache chooses;
	// only the first is answered.
	cacheReset, err := rtr.NewRTRCacheReset().Serialize()
	require.NoError(t, err)
	for range 2 {
		_, err = conn.Write(cacheReset)
		require.NoError(t, err)
	}

	_, err = readPDU(t, 30*time.Second)
	require.NoError(t, err, "the first cache reset must be answered")

	_, err = readPDU(t, 2*time.Second)
	require.Error(t, err, "the second cache reset arrived within the pacing interval and must be ignored")
	assert.True(t, errors.Is(err, os.ErrDeadlineExceeded),
		"expected nothing to read, got %v", err)

	// And the client goes away with the server.
	require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))

	_, err = readPDU(t, 30*time.Second)
	require.Error(t, err, "StopBgp must close the connection to the cache")
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF),
		"expected the connection to be closed, got %v", err)

	// Releasing the goroutines is asserted separately, in
	// TestRoaClientStopReleasesItsGoroutines: whether the last disconnect event
	// is drained before Serve returns is a race between two ready select cases,
	// so an end-to-end assertion here would pass about half the time with the
	// guards removed - a test that cannot be relied on to fail.
}

// A stopped ROA client does not block on the event channel, and its lifetime
// timer does not fire.
//
// eventCh is unbuffered and only Serve drains it. Once Serve has returned,
// established()'s deferred roaDisconnected send, tryConnect's roaConnected
// send, the read loop's roaRTR send and the lifetime timer's lifetimeout all
// blocked for ever - one leaked goroutine each, holding whatever they had.
//
// Asserted against the primitives rather than a live server, because the
// blocking only happens once nothing is draining, and arranging that
// end-to-end is inherently racy.
func TestRoaClientStopReleasesItsGoroutines(t *testing.T) {
	// Nobody ever reads this, which is the point.
	ch := make(chan *roaEvent)

	t.Run("a send on a stopped client gives up", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		c := &roaClient{host: "203.0.113.30:3323", eventCh: ch, ctx: ctx, cancelfnc: cancel}
		c.cancelfnc()

		done := make(chan bool, 1)
		go func() { done <- c.sendEvent(&roaEvent{EventType: roaDisconnected, Src: c.host}) }()

		select {
		case sent := <-done:
			assert.False(t, sent, "a stopped client must report that the event went nowhere")
		case <-time.After(10 * time.Second):
			t.Fatal("sendEvent blocked on a channel nobody drains")
		}
	})

	t.Run("stop disarms the lifetime timer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		c := &roaClient{host: "203.0.113.31:3323", eventCh: ch, ctx: ctx, cancelfnc: cancel}
		// lifetimeout sends on ch, so if the timer fires at all its goroutine
		// parks there for ever. Short enough that a missing Stop shows up
		// immediately rather than on a timeout.
		fired := make(chan struct{})
		c.timer = time.AfterFunc(50*time.Millisecond, func() {
			close(fired)
			c.lifetimeout()
		})

		c.stop()
		assert.Nil(t, c.timer, "stop must clear the timer as well as halt it")

		select {
		case <-fired:
			t.Fatal("the lifetime timer fired after the client was stopped")
		case <-time.After(500 * time.Millisecond):
		}
	})
}
