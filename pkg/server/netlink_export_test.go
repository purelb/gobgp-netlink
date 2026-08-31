//go:build linux

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
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	go_netlink "github.com/vishvananda/netlink"
)

func TestValidateRouteProtocol(t *testing.T) {
	for _, tt := range []struct {
		name  string
		proto int
		ok    bool
	}{
		{"RTPROT_BGP", RTPROT_BGP, true},
		{"upper bound", 255, true},
		{"lower bound", 5, true},

		// Out of range. Negative is reachable because the API field is int32,
		// and it is the worst case: the netlink library only writes the protocol
		// when > 0, so routes would install as RTPROT_UNSPEC while the cleanup
		// filter still looked for the negative value.
		{"zero", 0, false},
		{"negative", -1, false},
		{"above 255", 256, false},
		{"far above", 100000, false},

		// Reserved. Using one of these would make the cleanup sweep delete the
		// system's own routes.
		{"RTPROT_REDIRECT", 1, false},
		{"RTPROT_KERNEL", 2, false},
		{"RTPROT_BOOT", 3, false},
		{"RTPROT_STATIC", 4, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteProtocol(tt.proto)
			if tt.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestSweepTablesOnlyConfiguredTables pins the narrowing: the stale-route sweep
// may only touch tables this daemon is configured to export into.
//
// Previously it enumerated the main table plus every VRF table present on the
// host, so it deleted other daemons' routes in tables it never writes to.
func TestSweepTablesOnlyConfiguredTables(t *testing.T) {
	e := &netlinkExportClient{
		rules: []*exportRule{
			{Name: "a", TableId: 100},
			{Name: "b", TableId: 200},
			{Name: "dup", TableId: 100},
		},
		vrfRules: map[string]*vrfExportConfig{
			"red": {VrfName: "red", LinuxTableId: 300},
		},
	}
	assert.Equal(t, []int{100, 200, 300}, e.sweepTables())
}

func TestSweepTablesIncludesMainOnlyWhenNamed(t *testing.T) {
	// TableId 0 means the main table, and it is the default for a global rule,
	// so naming it is how an operator opts main in.
	withMain := &netlinkExportClient{rules: []*exportRule{{Name: "global", TableId: 0}}}
	assert.Equal(t, []int{0}, withMain.sweepTables())

	// A rule for a dedicated table must not pull the main table in with it.
	withoutMain := &netlinkExportClient{rules: []*exportRule{{Name: "vrfonly", TableId: 100}}}
	assert.Equal(t, []int{100}, withoutMain.sweepTables())
}

func TestSweepTablesEmptyWithoutRules(t *testing.T) {
	// No rules means this daemon owns nothing, so there is nothing to reconcile
	// and the sweep must not run at all.
	e := &netlinkExportClient{}
	assert.Empty(t, e.sweepTables())
}

// TestCleanupStaleRoutesRunsOnce guards the invariant that the sweep is a
// startup reconciliation.
//
// StartNetlink runs on every enable and config change. A second sweep would
// delete this daemon's own live routes while e.exported still listed them, after
// which exportRoute's idempotency check returns early and never reprograms them.
func TestCleanupStaleRoutesRunsOnce(t *testing.T) {
	// No rules, so cleanupStaleRoutes returns before touching the kernel and the
	// test needs no privileges.
	e := &netlinkExportClient{logger: logger}

	assert.False(t, e.sweptStaleRoutes)
	assert.NoError(t, e.cleanupStaleRoutesOnce())
	assert.True(t, e.sweptStaleRoutes)

	// Second call must be a no-op.
	assert.NoError(t, e.cleanupStaleRoutesOnce())
	assert.True(t, e.sweptStaleRoutes)
}

// newTestExportClient builds an export client over a fake kernel. The server is
// nil because none of the cleanup or export paths under test reach back into it.
func newTestExportClient(t *testing.T, f *fakeNetlink, rules ...*exportRule) *netlinkExportClient {
	t.Helper()
	e, err := newNetlinkExportClientWithHandle(nil, logger, f, RTPROT_BGP, 0)
	assert.NoError(t, err)
	e.rules = rules
	return e
}

// TestNewExportClientDoesNotSweep is the acceptance criterion for taking the
// route-deletion sweep out of the constructor.
//
// Constructing the client used to delete routes across every table on the host,
// which made `go test` destructive on any machine also running FRR.
func TestNewExportClientDoesNotSweep(t *testing.T) {
	f := newFakeNetlink()
	f.addRoute(go_netlink.Route{Table: 254, Dst: mustCIDR(t, "10.0.0.0/24"), Protocol: RTPROT_BGP})

	_ = newTestExportClient(t, f)

	_, del, _ := f.counts()
	assert.Equal(t, 0, del, "constructing the client must not delete routes")
	assert.Equal(t, 1, f.routeCount())
}

// TestCleanupStaleRoutesOnlyTouchesConfiguredTables is the core of the sweep
// narrowing: a route in a table this daemon does not export to belongs to
// someone else (FRR uses protocol 186 too) and must survive.
func TestCleanupStaleRoutesOnlyTouchesConfiguredTables(t *testing.T) {
	f := newFakeNetlink()
	// Ours: table 100, which a rule names.
	f.addRoute(go_netlink.Route{Table: 100, Dst: mustCIDR(t, "10.1.0.0/24"), Protocol: RTPROT_BGP})
	// Someone else's: same protocol, tables we never export to.
	f.addRoute(go_netlink.Route{Table: 254, Dst: mustCIDR(t, "10.2.0.0/24"), Protocol: RTPROT_BGP})
	f.addRoute(go_netlink.Route{Table: 300, Dst: mustCIDR(t, "10.3.0.0/24"), Protocol: RTPROT_BGP})

	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 100})
	assert.NoError(t, e.cleanupStaleRoutes())

	assert.False(t, f.hasRoute(100, "10.1.0.0/24"), "our own stale route should be swept")
	assert.True(t, f.hasRoute(254, "10.2.0.0/24"), "main-table route must survive")
	assert.True(t, f.hasRoute(300, "10.3.0.0/24"), "unconfigured VRF table must survive")

	// Positive control. The same routes must be swept once a rule names their
	// tables, proving the survivals above come from the table scoping and not
	// from the sweep being unable to see them.
	f2 := newFakeNetlink()
	f2.addRoute(go_netlink.Route{Table: 254, Dst: mustCIDR(t, "10.2.0.0/24"), Protocol: RTPROT_BGP})
	f2.addRoute(go_netlink.Route{Table: 300, Dst: mustCIDR(t, "10.3.0.0/24"), Protocol: RTPROT_BGP})

	e2 := newTestExportClient(t, f2,
		&exportRule{Name: "main", TableId: 0}, // 0 means the main table
		&exportRule{Name: "vrf", TableId: 300},
	)
	assert.NoError(t, e2.cleanupStaleRoutes())

	assert.False(t, f2.hasRoute(254, "10.2.0.0/24"), "main-table route should be swept once a rule names it")
	assert.False(t, f2.hasRoute(300, "10.3.0.0/24"), "table 300 should be swept once a rule names it")
}

// TestCleanupStaleRoutesSkipsOtherProtocols guards the protocol filter.
func TestCleanupStaleRoutesSkipsOtherProtocols(t *testing.T) {
	f := newFakeNetlink()
	f.addRoute(go_netlink.Route{Table: 100, Dst: mustCIDR(t, "10.1.0.0/24"), Protocol: RTPROT_BGP})
	f.addRoute(go_netlink.Route{Table: 100, Dst: mustCIDR(t, "10.9.0.0/24"), Protocol: 3}) // RTPROT_BOOT

	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 100})
	assert.NoError(t, e.cleanupStaleRoutes())

	assert.False(t, f.hasRoute(100, "10.1.0.0/24"))
	assert.True(t, f.hasRoute(100, "10.9.0.0/24"), "a route with another protocol is not ours")
}

// TestCleanupStaleRoutesSkipsDefaultRoute: a nil Dst is the default route. We
// never export one, and deleting it would isolate the node.
func TestCleanupStaleRoutesSkipsDefaultRoute(t *testing.T) {
	f := newFakeNetlink()
	f.addRoute(go_netlink.Route{Table: 100, Dst: nil, Protocol: RTPROT_BGP})

	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 100})
	assert.NoError(t, e.cleanupStaleRoutes())

	assert.Equal(t, 1, f.routeCount(), "default route must survive the sweep")

	e.statsMu.RLock()
	skipped := e.stats.CleanupSkipped
	e.statsMu.RUnlock()
	assert.Equal(t, uint64(1), skipped, "skipping should be counted, not silent")
}

// TestCleanupStaleRoutesLeavesTableOnListError: a table we cannot enumerate must
// be left alone rather than partially swept.
func TestCleanupStaleRoutesLeavesTableOnListError(t *testing.T) {
	f := newFakeNetlink()
	f.addRoute(go_netlink.Route{Table: 100, Dst: mustCIDR(t, "10.1.0.0/24"), Protocol: RTPROT_BGP})
	f.routeListErr = errors.New("dump failed")

	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 100})
	assert.NoError(t, e.cleanupStaleRoutes())

	assert.Equal(t, 1, f.routeCount(), "a table we could not list must be untouched")
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	assert.NoError(t, err)
	return n
}
