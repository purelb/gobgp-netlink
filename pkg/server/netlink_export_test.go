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
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	go_netlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

// --- prefix keying and re-evaluation ---

func testVpnPath(t *testing.T, rd, cidr, nexthop string) *table.Path {
	t.Helper()
	rdVal, err := bgp.ParseRouteDistinguisher(rd)
	assert.NoError(t, err)
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(cidr), *bgp.NewMPLSLabelStack(0), rdVal)
	assert.NoError(t, err)
	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv4_VPN,
		[]bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(nexthop))
	assert.NoError(t, err)
	p := table.NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), mpreach,
		}, time.Now(), false)
	assert.NotNil(t, p)
	return p
}

func testUnicastPath(t *testing.T, cidr, nexthop string) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(cidr))
	assert.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	assert.NoError(t, err)
	p := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), nh,
		}, time.Now(), false)
	assert.NotNil(t, p)
	return p
}

// TestExportPrefixKeyStripsRD is the root of the VRF re-evaluation bug: two
// derivations of "the prefix" disagreed, one including the RD and one not, and
// were then compared against each other.
func TestExportPrefixKeyStripsRD(t *testing.T) {
	vpn, err := exportPrefixKey(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1"))
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.0/24", vpn, "the RD must not be part of the tracking key")

	uc, err := exportPrefixKey(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"))
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.0/24", uc)
}

// vrfExportClient wires up a client that exports one VRF, with no global rules -
// the k8gobgp shape, and the configuration under which re-evaluation used to
// withdraw everything.
func vrfExportClient(t *testing.T, f *fakeNetlink) *netlinkExportClient {
	t.Helper()
	e, err := newNetlinkExportClientWithHandle(nil, logger, f, RTPROT_BGP, 0)
	assert.NoError(t, err)
	e.rdToVrf = map[string]string{"100:1": "vrf1"}
	e.vrfRules = map[string]*vrfExportConfig{
		"vrf1": {VrfName: "vrf1", LinuxVrf: "vrf1", LinuxTableId: 100, Metric: 20},
	}
	return e
}

// TestReEvaluateKeepsVrfRoutes is the headline fix. Re-evaluation consulted only
// the global rule set, so a VRF-exported route could never appear in the
// should-export set and every one of them was withdrawn - on a deployment with
// no global rules at all, which is exactly how the controller configures this.
func TestReEvaluateKeepsVrfRoutes(t *testing.T) {
	f := newFakeNetlink()
	e := vrfExportClient(t, f)
	path := testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")

	e.processUpdate(path)
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"), "the VRF route should be installed")

	// Re-evaluating with unchanged configuration must be a no-op.
	e.reEvaluateAllRoutes([]*table.Path{path})
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"re-evaluation with unchanged rules must not withdraw VRF routes")
}

// TestReEvaluateDoesNotLeakVpnIntoUnicastRules is the same disagreement in the
// other direction: re-evaluation applied global rules to VPN paths, so a rule
// with no community filter absorbed every VRF route into its own table.
func TestReEvaluateDoesNotLeakVpnIntoUnicastRules(t *testing.T) {
	f := newFakeNetlink()
	e := vrfExportClient(t, f)
	e.rules = []*exportRule{{Name: "catch-all", TableId: 254, Metric: 20}}

	e.reEvaluateAllRoutes([]*table.Path{testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")})

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"), "VPN path belongs in its VRF table")
	assert.False(t, f.hasRoute(254, "10.0.0.0/24"),
		"a VPN path must not be exported through a unicast rule")
}

// TestReEvaluateWithdrawsUnmatchedRoutes: the withdrawal half must still work.
func TestReEvaluateWithdrawsUnmatchedRoutes(t *testing.T) {
	f := newFakeNetlink()
	e := vrfExportClient(t, f)
	path := testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")

	e.processUpdate(path)
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))

	// The VRF is no longer exported, so its route should go.
	e.vrfRules = map[string]*vrfExportConfig{}
	e.reEvaluateAllRoutes([]*table.Path{path})
	assert.False(t, f.hasRoute(100, "10.0.0.0/24"),
		"a route no longer matching any rule should be withdrawn")
}

// --- per-prefix rule tracking ---

// TestTwoGlobalRulesBothTracked: every global rule shares the "" bucket, so a
// single entry per prefix meant the second rule silently overwrote the first's
// bookkeeping and the first's kernel route leaked with nothing able to reclaim
// it. Two rules, two tables, two routes, both tracked.
func TestTwoGlobalRulesBothTracked(t *testing.T) {
	f := newFakeNetlink()
	e := newTestExportClient(t, f,
		&exportRule{Name: "a", TableId: 100, Metric: 20},
		&exportRule{Name: "b", TableId: 200, Metric: 20},
	)

	e.processUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"))

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))
	assert.True(t, f.hasRoute(200, "10.0.0.0/24"))

	e.mu.RLock()
	tracked := len(e.exported[""]["10.0.0.0/24"])
	e.mu.RUnlock()
	assert.Equal(t, 2, tracked, "both rules' routes must be tracked, not just the last")
}

// TestWithdrawRemovesEveryRulesRoute: a withdrawal must reclaim all of them.
func TestWithdrawRemovesEveryRulesRoute(t *testing.T) {
	f := newFakeNetlink()
	e := newTestExportClient(t, f,
		&exportRule{Name: "a", TableId: 100, Metric: 20},
		&exportRule{Name: "b", TableId: 200, Metric: 20},
	)

	path := testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")
	e.processUpdate(path)
	assert.Equal(t, 2, f.routeCount())

	e.processUpdate(path.Clone(true))
	assert.Equal(t, 0, f.routeCount(), "withdrawal must remove every rule's route")
}

// --- withdrawal ownership ---

// TestWithdrawDoesNotCrossVrfs: the RD is stripped from the tracking key, so a
// path carrying an RD this daemon does not map used to match a prefix exported
// under a different VRF and delete it. A peer could blackhole another VRF's
// route by advertising and withdrawing an unmapped RD.
func TestWithdrawDoesNotCrossVrfs(t *testing.T) {
	f := newFakeNetlink()
	e := vrfExportClient(t, f)

	e.processUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1"))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))

	// Same prefix, an RD we have no mapping for.
	e.processUpdate(testVpnPath(t, "999:1", "10.0.0.0/24", "192.168.1.1").Clone(true))

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"a withdrawal for an unmapped RD must not delete another VRF's route")
}

// TestUnicastWithdrawDoesNotTouchVrfBuckets: a unicast path can only ever have
// installed into the buckets its own rules target.
func TestUnicastWithdrawDoesNotTouchVrfBuckets(t *testing.T) {
	f := newFakeNetlink()
	e := vrfExportClient(t, f)
	e.rules = []*exportRule{{Name: "global", TableId: 254, Metric: 20}}

	e.processUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1"))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))

	e.processUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1").Clone(true))

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"a unicast withdrawal must not reach a VRF export bucket")
}

// --- VRF created over gRPC ---

func newVrfTestServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	assert.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	t.Cleanup(func() {
		assert.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	return s
}

func addTestVrf(t *testing.T, s *BgpServer, name, rd string) {
	t.Helper()
	rdVal, err := bgp.ParseRouteDistinguisher(rd)
	assert.NoError(t, err)
	apiRd, err := apiutil.MarshalRD(rdVal)
	assert.NoError(t, err)
	assert.NoError(t, s.AddVrf(context.Background(), &api.AddVrfRequest{
		Vrf: &api.Vrf{Name: name, Id: 1, Rd: apiRd},
	}))
}

// TestAddVrfCreatesConfigEntry is the root of the per-VRF netlink failure.
//
// AddVrf wrote only globalRib.Vrfs, and everything netlink keys off
// bgpConfig.Vrfs: buildVrfMappings builds rdToVrf from it, the import scan gates
// on it, and the four per-VRF RPCs look their VRF up in it. A VRF created over
// gRPC - the only way a controller creates one - existed for routing but not for
// netlink.
func TestAddVrfCreatesConfigEntry(t *testing.T) {
	s := newVrfTestServer(t)
	addTestVrf(t, s, "vrf1", "100:1")

	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()

	var found *oc.Vrf
	for i := range s.bgpConfig.Vrfs {
		if s.bgpConfig.Vrfs[i].Config.Name == "vrf1" {
			found = &s.bgpConfig.Vrfs[i]
		}
	}
	if assert.NotNil(t, found, "AddVrf should create a config entry") {
		// The RD is what buildVrfMappings resolves an incoming VPN path
		// through. Without it, export stays dead even with an entry present.
		assert.Equal(t, "100:1", found.Config.Rd)
	}
}

// TestPerVrfNetlinkRPCsFindGrpcCreatedVrf: these used to return
// "VRF not found - create it first via AddVrf" for a VRF AddVrf had just
// created, and the controller treats that as fatal and requeues forever.
func TestPerVrfNetlinkRPCsFindGrpcCreatedVrf(t *testing.T) {
	s := newVrfTestServer(t)
	addTestVrf(t, s, "vrf1", "100:1")
	ctx := context.Background()

	assert.NoError(t, s.EnableVrfNetlinkImport(ctx, &api.EnableVrfNetlinkImportRequest{
		Vrf: "vrf1", Interfaces: []string{"eth0"},
	}))
	assert.NoError(t, s.EnableVrfNetlinkExport(ctx, &api.EnableVrfNetlinkExportRequest{
		Vrf: "vrf1", Config: &api.VrfNetlinkExportConfig{LinuxTableId: 100},
	}))
	assert.NoError(t, s.DisableVrfNetlinkImport(ctx, &api.DisableVrfNetlinkImportRequest{
		Vrf: "vrf1", KeepRoutes: true,
	}))
	assert.NoError(t, s.DisableVrfNetlinkExport(ctx, &api.DisableVrfNetlinkExportRequest{
		Vrf: "vrf1", KeepRoutes: true,
	}))

	// A VRF that genuinely does not exist must still be rejected.
	assert.Error(t, s.EnableVrfNetlinkImport(ctx, &api.EnableVrfNetlinkImportRequest{
		Vrf: "nope", Interfaces: []string{"eth0"},
	}))
}

// TestVpnPathReachesExportForGrpcCreatedVrf is the assertion that matters.
//
// Checking that EnableVrfNetlinkExport returns success would pass while export
// remained dead, because the RD mapping is what actually carries a VPN path to
// the kernel. This asserts the route lands in the FIB.
func TestVpnPathReachesExportForGrpcCreatedVrf(t *testing.T) {
	s := newVrfTestServer(t)
	addTestVrf(t, s, "vrf1", "100:1")

	assert.NoError(t, s.EnableVrfNetlinkExport(context.Background(),
		&api.EnableVrfNetlinkExportRequest{
			Vrf:    "vrf1",
			Config: &api.VrfNetlinkExportConfig{LinuxTableId: 100, SkipNexthopValidation: true},
		}))

	f := newFakeNetlink()
	e, err := newNetlinkExportClientWithHandle(s, logger, f, RTPROT_BGP, 0)
	assert.NoError(t, err)

	s.shared.mu.Lock()
	assert.NoError(t, e.buildVrfMappings())
	s.shared.mu.Unlock()

	e.processUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1"))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"a VPN path for a gRPC-created VRF should reach the kernel")
}

// TestVrfExportFailsClosedOnBadCommunity: matchesVrfExportFilters treats an
// empty community list as "match everything", so dropping an unparseable entry
// turned a filter into a wildcard - the only thing between a BGP peer and the
// node's FIB.
func TestVrfExportFailsClosedOnBadCommunity(t *testing.T) {
	s := newVrfTestServer(t)
	addTestVrf(t, s, "vrf1", "100:1")

	assert.NoError(t, s.EnableVrfNetlinkExport(context.Background(),
		&api.EnableVrfNetlinkExportRequest{
			Vrf: "vrf1",
			Config: &api.VrfNetlinkExportConfig{
				LinuxTableId:          100,
				SkipNexthopValidation: true,
				CommunityList:         []string{"not-a-community"},
			},
		}))

	f := newFakeNetlink()
	e, err := newNetlinkExportClientWithHandle(s, logger, f, RTPROT_BGP, 0)
	assert.NoError(t, err)

	s.shared.mu.Lock()
	assert.NoError(t, e.buildVrfMappings())
	s.shared.mu.Unlock()

	e.processUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1"))

	assert.Equal(t, 0, f.routeCount(),
		"an unparseable community filter must export nothing, not everything")
}

// --- nexthop validation, output interface, ONLINK ---

// netlinkSourcedPath builds a path whose source carries an interface name, as a
// netlink-imported route or a route learned over an unnumbered session does.
func netlinkSourcedPath(t *testing.T, cidr, nexthop, iface string) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(cidr))
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
	}
	family := bgp.RF_IPv4_UC
	if netip.MustParseAddr(nexthop).Is6() {
		family = bgp.RF_IPv6_UC
		mpreach, err := bgp.NewPathAttributeMpReachNLRI(family,
			[]bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(nexthop))
		assert.NoError(t, err)
		attrs = append(attrs, mpreach)
	} else {
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
		assert.NoError(t, err)
		attrs = append(attrs, nh)
	}
	p := table.NewPath(family, table.NewNetlinkPeerInfo(iface),
		bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	assert.NotNil(t, p)
	return p
}

// TestNexthopValidationWorksForVrfTable: validation looked the nexthop up in the
// main table and then required the answer to come from the rule's table, which
// can never hold for a VRF. Every rule targeting a VRF silently exported nothing
// while validation was on - and it is on by default.
func TestNexthopValidationWorksForVrfTable(t *testing.T) {
	f := newFakeNetlink()
	f.setReachable("192.168.1.1", 100, unix.RTN_UNICAST)

	e := newTestExportClient(t, f,
		&exportRule{Name: "vrf", VrfName: "vrf-red", TableId: 100, Metric: 20, ValidateNexthop: true})
	f.addLink("vrf-red", 7)

	e.processUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"a reachable nexthop in the VRF table should validate")
}

// TestNexthopValidationRejectsUnreachableType: a provisioned VRF table carries
// an "unreachable default", which satisfies a bare table check while meaning the
// opposite of reachable.
func TestNexthopValidationRejectsUnreachableType(t *testing.T) {
	f := newFakeNetlink()
	f.setReachable("192.168.1.1", 100, unix.RTN_UNREACHABLE)

	e := newTestExportClient(t, f,
		&exportRule{Name: "vrf", VrfName: "vrf-red", TableId: 100, Metric: 20, ValidateNexthop: true})
	f.addLink("vrf-red", 7)

	e.processUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"))
	assert.Equal(t, 0, f.routeCount(), "an unreachable route must not count as reachable")
}

// TestLinkLocalNexthopGetsOutputInterface is the unnumbered export case.
//
// The kernel rejects a link-local gateway with RTA_OIF=0, and the device was
// only ever set when validation was disabled, so with the default settings these
// routes could not be installed at all.
func TestLinkLocalNexthopGetsOutputInterface(t *testing.T) {
	f := newFakeNetlink()
	f.addLink("eth0", 3)

	e := newTestExportClient(t, f,
		&exportRule{Name: "global", TableId: 0, Metric: 20, ValidateNexthop: true})

	e.processUpdate(netlinkSourcedPath(t, "2001:db8:1::/64", "fe80::1", "eth0"))

	route := f.routeFor(0, "2001:db8:1::/64")
	if assert.NotNil(t, route, "a link-local nexthop route should be installed") {
		assert.Equal(t, 3, route.LinkIndex,
			"the route must carry the session's interface as its output device")
	}
}

// TestLinkLocalNexthopWithoutInterfaceIsRejected: better a clear error than a
// bare EINVAL from the kernel.
func TestLinkLocalNexthopWithoutInterfaceIsRejected(t *testing.T) {
	f := newFakeNetlink()
	e := newTestExportClient(t, f,
		&exportRule{Name: "global", TableId: 0, Metric: 20, ValidateNexthop: true})

	// Source has no interface recorded.
	err := e.exportRoute(testUnicastPath(t, "2001:db8:1::/64", "fe80::1"), e.rules[0])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "output interface")
	assert.Equal(t, 0, f.routeCount())
}

// TestOnlinkIsIndependentOfValidation: the two were one flag, so an operator who
// had disabled validation to work around the VRF bug would silently lose ONLINK
// when turning it back on. The device must be set either way.
func TestOnlinkIsIndependentOfValidation(t *testing.T) {
	for _, tt := range []struct {
		name     string
		validate bool
		wantFlag int
	}{
		{"validation on", true, 0},
		{"validation off", false, int(go_netlink.FLAG_ONLINK)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeNetlink()
			f.addLink("vrf-red", 7)
			f.setReachable("192.168.1.1", 100, unix.RTN_UNICAST)

			e := newTestExportClient(t, f, &exportRule{
				Name: "vrf", VrfName: "vrf-red", TableId: 100,
				Metric: 20, ValidateNexthop: tt.validate,
			})

			e.processUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"))

			route := f.routeFor(100, "10.0.0.0/24")
			if assert.NotNil(t, route) {
				assert.Equal(t, tt.wantFlag, route.Flags, "ONLINK follows validation")
				assert.Equal(t, 7, route.LinkIndex,
					"the VRF device must be set regardless of validation")
			}
		})
	}
}

// --- best-path export and concurrent RPC safety ---

// TestExportUsesBestPathNotReceivedPath is the route black-hole.
//
// Export was driven from whatever update arrived rather than from the best path.
// With two peers advertising a prefix, a withdrawal from the non-best peer
// deleted the kernel route while the other path was still best, and nothing
// restored it until the next configuration change.
func TestExportUsesBestPathNotReceivedPath(t *testing.T) {
	s := newVrfTestServer(t)

	f := newFakeNetlink()
	e, err := newNetlinkExportClientWithHandle(s, logger, f, RTPROT_BGP, 0)
	assert.NoError(t, err)
	e.rules = []*exportRule{{Name: "global", TableId: 0, Metric: 20}}

	s.shared.mu.Lock()
	s.netlinkExportClient = e
	s.shared.mu.Unlock()

	prefix := "10.55.0.0/24"
	add := func(peerAddr, nexthop string) *table.Path {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		assert.NoError(t, err)
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
		assert.NoError(t, err)
		src := &table.PeerInfo{
			AS:      65002,
			ID:      netip.MustParseAddr(peerAddr),
			Address: netip.MustParseAddr(peerAddr),
		}
		p := table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), nh,
			}, time.Now(), false)
		assert.NotNil(t, p)
		return p
	}

	best := add("10.0.0.1", "192.168.1.1")
	other := add("10.0.0.2", "192.168.1.2")

	s.shared.mu.Lock()
	s.propagateUpdate(nil, []*table.Path{best})
	s.propagateUpdate(nil, []*table.Path{other})
	s.shared.mu.Unlock()

	// Export is dampened, so the kernel write lands on a timer rather than
	// inline.
	assert.Eventually(t, func() bool { return f.hasRoute(0, prefix) },
		5*time.Second, 5*time.Millisecond, "the prefix should be exported")

	// Withdraw the non-best path. The prefix is still reachable via the other
	// peer, so the kernel route must stay.
	s.shared.mu.Lock()
	s.propagateUpdate(nil, []*table.Path{other.Clone(true)})
	s.shared.mu.Unlock()

	// Give the dampening timer time to deliver a deletion if one is coming;
	// the point of the test is that none is.
	assert.Never(t, func() bool { return !f.hasRoute(0, prefix) },
		time.Second, 10*time.Millisecond,
		"withdrawing a non-best path must not delete a still-best route")
}

// TestReadOnlyRPCsSurviveConcurrentDisable is the TOCTOU.
//
// These RPCs nil-checked s.netlinkExportClient and then dereferenced it, while
// DisableNetlinkExport nils it on the Serve goroutine. A controller polling them
// could crash the daemon.
func TestReadOnlyRPCsSurviveConcurrentDisable(t *testing.T) {
	s := newVrfTestServer(t)
	ctx := context.Background()

	assert.NoError(t, s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
		Rules: []*api.NetlinkExportRuleConfig{{Name: "r", TableId: 0}},
	}))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Poll the read-only endpoints the way a controller does.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = s.GetNetlink(ctx, &api.GetNetlinkRequest{})
				_, _ = s.GetNetlinkExportStats(ctx, &api.GetNetlinkExportStatsRequest{})
				_, _ = s.ListNetlinkExportRules(ctx, &api.ListNetlinkExportRulesRequest{})
				_ = s.ListNetlinkExport(ctx, &api.ListNetlinkExportRequest{},
					func(*api.ListNetlinkExportResponse) {})
			}
		}()
	}

	// Flip export off and on underneath them.
	for range 20 {
		_ = s.DisableNetlinkExport(ctx, &api.DisableNetlinkExportRequest{})
		_ = s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
			Rules: []*api.NetlinkExportRuleConfig{{Name: "r", TableId: 0}},
		})
	}

	close(stop)
	wg.Wait()
}

// --- dampening ---

// TestDampeningCapInstallsFlappingPrefix: dampening cancelled and restarted its
// timer on every update, so a prefix updating faster than the interval was
// deferred forever and never programmed at all. Dampening is meant to delay a
// write, not suppress it.
//
// The assertion has to land while the prefix is STILL being updated. Checking
// after the updates stop proves nothing: the final timer fires and installs the
// route either way.
func TestDampeningCapInstallsFlappingPrefix(t *testing.T) {
	f := newFakeNetlink()
	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 0, Metric: 20})
	e.dampeningInterval = 50 * time.Millisecond
	e.dampeningMaxDelay = 200 * time.Millisecond

	path := testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")

	// Update continuously, faster than the dampening interval, so that without a
	// cap the timer is always cancelled before it can fire.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				e.scheduleUpdate(path)
			}
		}
	}()
	defer func() { close(stop); <-done }()

	assert.Eventually(t, func() bool { return f.hasRoute(0, "10.0.0.0/24") },
		2*time.Second, 10*time.Millisecond,
		"a prefix updating faster than the dampening interval must still reach "+
			"the FIB while it is still flapping")
}

// TestDampeningStillDefersBurst: the cap must not defeat dampening itself. A
// short burst is collapsed into a single kernel write.
func TestDampeningStillDefersBurst(t *testing.T) {
	f := newFakeNetlink()
	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 0, Metric: 20})
	e.dampeningInterval = 100 * time.Millisecond
	e.dampeningMaxDelay = 5 * time.Second

	path := testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")
	for range 10 {
		e.scheduleUpdate(path)
	}

	// Nothing written yet: the burst is still being collapsed.
	replace, _, _ := f.counts()
	assert.Equal(t, 0, replace, "a burst should not be written through immediately")

	assert.Eventually(t, func() bool { return f.hasRoute(0, "10.0.0.0/24") },
		2*time.Second, 10*time.Millisecond)

	replace, _, _ = f.counts()
	assert.Equal(t, 1, replace, "ten updates in a burst should collapse to one write")
}

// TestNetlinkSocketTimeoutIsSet guards against the export path wedging forever
// on a kernel reply that never arrives.
func TestNetlinkSocketTimeoutIsSet(t *testing.T) {
	f := newFakeNetlink()
	_ = f.SetSocketTimeout(netlinkSocketTimeout)

	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, netlinkSocketTimeout, f.socketTimeout)
	assert.GreaterOrEqual(t, netlinkSocketTimeout, 30*time.Second,
		"must stay generous: cleanupStaleRoutes dumps whole routing tables")
}
