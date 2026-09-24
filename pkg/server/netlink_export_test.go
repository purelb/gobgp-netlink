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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// newOnLinkFake is a fake whose test nexthops, 192.168.0.0/16, are on a
// connected link. A rule built without ValidateNexthop installs its nexthops
// ONLINK, which the kernel - and the fake - refuse without a device; export
// finds that device by resolving the nexthop, as on a real host.
func newOnLinkFake() *fakeNetlink {
	f := newFakeNetlink()
	f.addConnected("192.168.0.0/16", 2)
	return f
}

func newTestExportClient(t testing.TB, f *fakeNetlink, rules ...*exportRule) *netlinkExportClient {
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

func testUnicastPath(t testing.TB, cidr, nexthop string) *table.Path {
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
	// The VRF's device, which exists wherever the VRF does. Without validation
	// the route goes in ONLINK on it, and without it the kernel refuses.
	f.addLink("vrf1", 10)
	return e
}

// TestReEvaluateKeepsVrfRoutes is the headline fix. Re-evaluation consulted only
// the global rule set, so a VRF-exported route could never appear in the
// should-export set and every one of them was withdrawn - on a deployment with
// no global rules at all, which is exactly how the controller configures this.
func TestReEvaluateKeepsVrfRoutes(t *testing.T) {
	f := newOnLinkFake()
	e := vrfExportClient(t, f)
	path := testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")

	e.processUpdate(pathUpdate(path))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"), "the VRF route should be installed")

	// Re-evaluating with unchanged configuration must be a no-op.
	e.reEvaluateAllRoutes([][]*table.Path{{path}})
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"re-evaluation with unchanged rules must not withdraw VRF routes")
}

// TestReEvaluateDoesNotLeakVpnIntoUnicastRules is the same disagreement in the
// other direction: re-evaluation applied global rules to VPN paths, so a rule
// with no community filter absorbed every VRF route into its own table.
func TestReEvaluateDoesNotLeakVpnIntoUnicastRules(t *testing.T) {
	f := newOnLinkFake()
	e := vrfExportClient(t, f)
	e.rules = []*exportRule{{Name: "catch-all", TableId: 254, Metric: 20}}

	e.reEvaluateAllRoutes([][]*table.Path{{testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")}})

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"), "VPN path belongs in its VRF table")
	assert.False(t, f.hasRoute(254, "10.0.0.0/24"),
		"a VPN path must not be exported through a unicast rule")
}

// TestReEvaluateWithdrawsUnmatchedRoutes: the withdrawal half must still work.
func TestReEvaluateWithdrawsUnmatchedRoutes(t *testing.T) {
	f := newOnLinkFake()
	e := vrfExportClient(t, f)
	path := testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")

	e.processUpdate(pathUpdate(path))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))

	// The VRF is no longer exported, so its route should go.
	e.vrfRules = map[string]*vrfExportConfig{}
	e.reEvaluateAllRoutes([][]*table.Path{{path}})
	assert.False(t, f.hasRoute(100, "10.0.0.0/24"),
		"a route no longer matching any rule should be withdrawn")
}

// --- per-prefix rule tracking ---

// TestTwoGlobalRulesBothTracked: every global rule shares the "" bucket, so a
// single entry per prefix meant the second rule silently overwrote the first's
// bookkeeping and the first's kernel route leaked with nothing able to reclaim
// it. Two rules, two tables, two routes, both tracked.
func TestTwoGlobalRulesBothTracked(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f,
		&exportRule{Name: "a", TableId: 100, Metric: 20},
		&exportRule{Name: "b", TableId: 200, Metric: 20},
	)

	e.processUpdate(pathUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")))

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))
	assert.True(t, f.hasRoute(200, "10.0.0.0/24"))

	e.mu.RLock()
	tracked := len(e.exported[""]["10.0.0.0/24"])
	e.mu.RUnlock()
	assert.Equal(t, 2, tracked, "both rules' routes must be tracked, not just the last")
}

// TestWithdrawRemovesEveryRulesRoute: a withdrawal must reclaim all of them.
func TestWithdrawRemovesEveryRulesRoute(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f,
		&exportRule{Name: "a", TableId: 100, Metric: 20},
		&exportRule{Name: "b", TableId: 200, Metric: 20},
	)

	path := testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")
	e.processUpdate(pathUpdate(path))
	assert.Equal(t, 2, f.routeCount())

	e.processUpdate(pathUpdate(path.Clone(true)))
	assert.Equal(t, 0, f.routeCount(), "withdrawal must remove every rule's route")
}

// --- withdrawal ownership ---

// TestWithdrawDoesNotCrossVrfs: the RD is stripped from the tracking key, so a
// path carrying an RD this daemon does not map used to match a prefix exported
// under a different VRF and delete it. A peer could blackhole another VRF's
// route by advertising and withdrawing an unmapped RD.
func TestWithdrawDoesNotCrossVrfs(t *testing.T) {
	f := newOnLinkFake()
	e := vrfExportClient(t, f)

	e.processUpdate(pathUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))

	// Same prefix, an RD we have no mapping for.
	e.processUpdate(pathUpdate(testVpnPath(t, "999:1", "10.0.0.0/24", "192.168.1.1").Clone(true)))

	assert.True(t, f.hasRoute(100, "10.0.0.0/24"),
		"a withdrawal for an unmapped RD must not delete another VRF's route")
}

// TestUnicastWithdrawDoesNotTouchVrfBuckets: a unicast path can only ever have
// installed into the buckets its own rules target.
func TestUnicastWithdrawDoesNotTouchVrfBuckets(t *testing.T) {
	f := newOnLinkFake()
	e := vrfExportClient(t, f)
	e.rules = []*exportRule{{Name: "global", TableId: 254, Metric: 20}}

	e.processUpdate(pathUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")))
	assert.True(t, f.hasRoute(100, "10.0.0.0/24"))

	e.processUpdate(pathUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1").Clone(true)))

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
	// The VRF's device: validation is skipped, so the route goes in ONLINK on it.
	f.addLink("vrf1", 10)
	e, err := newNetlinkExportClientWithHandle(s, logger, f, RTPROT_BGP, 0)
	assert.NoError(t, err)

	s.shared.mu.Lock()
	assert.NoError(t, e.buildVrfMappings())
	s.shared.mu.Unlock()

	e.processUpdate(pathUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")))
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

	e.processUpdate(pathUpdate(testVpnPath(t, "100:1", "10.0.0.0/24", "192.168.1.1")))

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

	e.processUpdate(pathUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")))
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

	e.processUpdate(pathUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")))
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

	e.processUpdate(pathUpdate(netlinkSourcedPath(t, "2001:db8:1::/64", "fe80::1", "eth0")))

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
	err := e.exportRoute([]*table.Path{testUnicastPath(t, "2001:db8:1::/64", "fe80::1")}, e.rules[0])
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

			e.processUpdate(pathUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")))

			route := f.routeFor(100, "10.0.0.0/24")
			if assert.NotNil(t, route) {
				assert.Equal(t, tt.wantFlag, route.Flags, "ONLINK follows validation")
				assert.Equal(t, 7, route.LinkIndex,
					"the VRF device must be set regardless of validation")
			}
		})
	}
}

// --- skip-nexthop-validation on a non-VRF rule ---
//
// Without validation a nexthop is installed ONLINK, and the kernel refuses
// ONLINK without a device. A VRF rule has the VRF device and a link-local
// nexthop the session's interface, but a non-VRF rule had nothing, so
// skip-nexthop-validation on one could never install a route.
//
// The fake below has three devices a nexthop could be placed on: 3, where the
// on-link LAN is and where the off-link nexthop's gateway is; 4, where a
// directly connected eBGP peer is; and 5, with fe80::/64. A route that lands on
// a device it should not makes that visible.

// sessionPath builds an IPv4 path learned from a BGP session.
func sessionPath(t *testing.T, cidr, nexthop string, src *table.PeerInfo) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(cidr))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	return table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), nh},
		time.Now(), false)
}

// ebgpPeer is a directly connected eBGP session: no multihop.
func ebgpPeer(addr string) *table.PeerInfo {
	a := netip.MustParseAddr(addr)
	return &table.PeerInfo{PeerType: oc.PEER_TYPE_EXTERNAL, AS: 65100, ID: a, Address: a}
}

func skipValidationFake() *fakeNetlink {
	f := newFakeNetlink()
	f.addConnected("192.168.1.0/24", 3)
	f.setVia("10.9.9.9", "192.168.1.254", 3) // off-link: reached through a gateway on 3
	f.addConnected("172.16.0.0/24", 4)       // where the eBGP peer is
	f.addConnected("fe80::/64", 5)
	f.setLocal("192.168.1.100")
	return f
}

var skipValidationRule = &exportRule{Name: "global", TableId: 254, Metric: 20}

// A nexthop on a connected link goes in ONLINK on that link.
func TestSkipValidationInstallsOnTheNexthopsOwnLink(t *testing.T) {
	f := skipValidationFake()
	e := newTestExportClient(t, f, skipValidationRule)

	require.NoError(t, e.exportRoute([]*table.Path{testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")}, skipValidationRule))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, "192.168.1.1", r.Gw.String())
	assert.Equal(t, 3, r.LinkIndex, "the device the kernel says the nexthop is on")
	assert.Equal(t, int(go_netlink.FLAG_ONLINK), r.Flags)
}

// A third-party nexthop from a directly connected eBGP peer is on the peer's
// link even though no connected prefix covers it - the case ONLINK exists for.
// It goes on the peer's link, never on the device of the gateway the kernel
// would otherwise route it through.
func TestSkipValidationUsesADirectlyConnectedEbgpPeersLink(t *testing.T) {
	f := skipValidationFake()
	e := newTestExportClient(t, f, skipValidationRule)

	require.NoError(t, e.exportRoute(
		[]*table.Path{sessionPath(t, "10.0.0.0/24", "10.9.9.9", ebgpPeer("172.16.0.5"))}, skipValidationRule))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, 4, r.LinkIndex, "the peer's link, not the gateway's device 3")
	assert.Equal(t, int(go_netlink.FLAG_ONLINK), r.Flags)
}

// Where the nexthop's link cannot be known, it is refused with the reason, not
// placed on a device it may not be on - which would black-hole the prefix.
func TestSkipValidationRefusesANexthopItCannotPlace(t *testing.T) {
	multihop := ebgpPeer("172.16.0.5")
	multihop.MultihopTtl = 2
	ibgp := ebgpPeer("172.16.0.5")
	ibgp.PeerType = oc.PEER_TYPE_INTERNAL

	for _, tt := range []struct {
		name string
		path func(t *testing.T) *table.Path
	}{
		{"off-link, no session", func(t *testing.T) *table.Path {
			return testUnicastPath(t, "10.0.0.0/24", "10.9.9.9")
		}},
		{"off-link, multihop eBGP", func(t *testing.T) *table.Path {
			return sessionPath(t, "10.0.0.0/24", "10.9.9.9", multihop)
		}},
		{"off-link, iBGP", func(t *testing.T) *table.Path {
			return sessionPath(t, "10.0.0.0/24", "10.9.9.9", ibgp)
		}},
		{"off-link, link-local peer", func(t *testing.T) *table.Path {
			return sessionPath(t, "10.0.0.0/24", "10.9.9.9", ebgpPeer("fe80::5"))
		}},
		{"one of this host's own addresses", func(t *testing.T) *table.Path {
			return testUnicastPath(t, "10.0.0.0/24", "192.168.1.100")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := skipValidationFake()
			e := newTestExportClient(t, f, skipValidationRule)

			err := e.exportRoute([]*table.Path{tt.path(t)}, skipValidationRule)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "on-link")
			assert.Equal(t, 0, f.routeCount())
		})
	}
}

// Each nexthop of an ECMP route is placed on its own link, and one that cannot
// be placed is left out while the others stay.
func TestSkipValidationPlacesEachEcmpNexthop(t *testing.T) {
	f := skipValidationFake()
	e := newTestExportClient(t, f, skipValidationRule)
	multihop := ebgpPeer("172.16.0.6")
	multihop.MultihopTtl = 2

	require.NoError(t, e.exportRoute([]*table.Path{
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"),
		sessionPath(t, "10.0.0.0/24", "10.9.9.9", ebgpPeer("172.16.0.5")),
		sessionPath(t, "10.0.0.0/24", "10.8.8.8", multihop),
	}, skipValidationRule))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	var got []string
	for _, nh := range r.MultiPath {
		got = append(got, fmt.Sprintf("%s dev %d flags %d", nh.Gw, nh.LinkIndex, nh.Flags))
	}
	onlink := int(go_netlink.FLAG_ONLINK)
	assert.Equal(t, []string{
		fmt.Sprintf("10.9.9.9 dev 4 flags %d", onlink),
		fmt.Sprintf("192.168.1.1 dev 3 flags %d", onlink),
	}, got, "the multihop path's nexthop cannot be placed and is left out")
}

// With validation on, a non-VRF route is exactly what it was: no device, no
// ONLINK, the kernel resolving the nexthop itself.
func TestValidatedNonVrfRouteIsUnchanged(t *testing.T) {
	f := skipValidationFake()
	rule := &exportRule{Name: "global", TableId: 254, Metric: 20, ValidateNexthop: true}
	e := newTestExportClient(t, f, rule)

	require.NoError(t, e.exportRoute([]*table.Path{testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")}, rule))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, 0, r.LinkIndex)
	assert.Equal(t, 0, r.Flags)
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

	f := newOnLinkFake()
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
	f := newOnLinkFake()
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
				e.scheduleUpdate(pathUpdate(path))
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
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 0, Metric: 20})
	e.dampeningInterval = 100 * time.Millisecond
	e.dampeningMaxDelay = 5 * time.Second

	path := testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")
	for range 10 {
		e.scheduleUpdate(pathUpdate(path))
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

// TestListVrfReportsNetlinkImport gates the netlink import information that
// `gobgp vrf` shows.
//
// Netlink import is configured per VRF in bgpConfig, not on the RIB's VRF, so
// ListVrf has to look it up. Nothing asserted that it did, and the v4.9.0 merge
// dropped the lookup while still compiling: the column simply went blank. That
// is the same shape as the other hooks the merge lost - a call site inside a
// function that was replaced wholesale - and it is invisible to the compiler
// because the field just stays at its zero value.
func TestListVrfReportsNetlinkImport(t *testing.T) {
	s := newVrfTestServer(t)
	addTestVrf(t, s, "vrf1", "100:1")

	// Configure netlink import for it, the way EnableVrfNetlinkImport does.
	assert.NoError(t, s.EnableVrfNetlinkImport(context.Background(),
		&api.EnableVrfNetlinkImportRequest{Vrf: "vrf1", Interfaces: []string{"eth0", "eth1"}}))

	var got *api.Vrf
	assert.NoError(t, s.ListVrf(context.Background(), &api.ListVrfRequest{Name: "vrf1"},
		func(v *api.Vrf) { got = v }))

	if assert.NotNil(t, got, "the VRF must be listed") {
		assert.True(t, got.GetNetlink().GetImportEnabled(),
			"ListVrf must report netlink import; a blank column is the symptom")
		assert.Equal(t, []string{"eth0", "eth1"}, got.GetNetlink().GetImportInterfaces())
	}
}

// TestDampeningFlushIsBudgeted gates the burst bound that BFD depends on.
//
// Dampening used to arm a time.AfterFunc per prefix. A peer flap therefore
// scheduled N timers inside one dampening interval and they all fired together,
// each doing a RouteReplace serialised on a single netlink socket. Several
// hundred VIPs is more CPU than a 500m cgroup quota allows in 100ms, so the
// container throttled for the remainder of the period - landing the stall on
// exactly the event BFD is watching for, and able to expire sessions to peers
// that are perfectly healthy.
//
// One timer now drains the map, at most dampenFlushBudget prefixes per pass,
// re-arming after a short yield so a burst is spread rather than delayed. This
// asserts the whole burst still lands, and that it takes more than one pass to
// do it.
func TestDampeningFlushIsBudgeted(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "r", TableId: 0, Metric: 20})
	e.dampeningInterval = 20 * time.Millisecond
	e.dampeningMaxDelay = 5 * time.Second

	const total = dampenFlushBudget + 25
	for i := range total {
		e.scheduleUpdate(pathUpdate(testUnicastPath(t, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), "192.168.1.1")))
	}

	// One timer for the whole map, not one per prefix.
	e.dampenMu.Lock()
	pending := len(e.pendingUpdates)
	armed := e.flushTimer != nil
	e.dampenMu.Unlock()
	assert.Equal(t, total, pending, "every prefix should be pending")
	assert.True(t, armed, "a single flush timer should be armed")

	// The flush is driven directly rather than waited for. Polling for the
	// first pass raced the re-arm: the yield and the poll interval are both
	// 5ms, so a second pass could complete between the poll observing a
	// non-zero count and the assertion re-reading it, and under load that gap
	// widens. Calling flushDampened makes "one pass" exact instead of
	// approximate.
	makeDue := func() {
		e.dampenMu.Lock()
		if e.flushTimer != nil {
			e.flushTimer.Stop()
			e.flushTimer = nil
		}
		for _, entry := range e.pendingUpdates {
			entry.dueAt = time.Now().Add(-time.Millisecond)
		}
		e.dampenMu.Unlock()
	}

	makeDue()
	e.flushDampened()

	replace, _, _ := f.counts()
	assert.Equal(t, dampenFlushBudget, replace,
		"one pass must program exactly the budget; that is what throttles the cgroup")

	// Everything still lands across subsequent passes.
	for range 10 {
		if r, _, _ := f.counts(); r == total {
			break
		}
		makeDue()
		e.flushDampened()
	}

	replace, _, _ = f.counts()
	assert.Equal(t, total, replace, "the whole burst must still be programmed")

	e.dampenMu.Lock()
	left := len(e.pendingUpdates)
	timer := e.flushTimer
	e.dampenMu.Unlock()
	assert.Zero(t, left, "nothing should remain pending")
	assert.Nil(t, timer, "the flush timer should be disarmed when the map empties")
}

// BenchmarkScheduleBurst measures the cost of scheduling a burst of distinct
// prefixes, which is the peer-flap shape §7.4 exists to bound.
//
// It exists because the flush rewrite has a failure mode the correctness tests
// cannot see: scheduleUpdate holds dampenMu while it re-arms, so any per-update
// work that scales with the number of pending prefixes is quadratic across a
// burst AND serialises the export hook. Growth much beyond linear in the
// reported ns/op is the regression.
func benchmarkScheduleBurst(b *testing.B, n int) {
	prefixes := make([]string, n)
	for i := range prefixes {
		prefixes[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}

	for b.Loop() {
		b.StopTimer()
		f := newFakeNetlink()
		e := newTestExportClient(b, f, &exportRule{Name: "bench", TableId: 254})
		// Long enough that nothing fires mid-burst: this measures scheduling,
		// not flushing.
		e.dampeningInterval = time.Hour
		paths := make([]*table.Path, n)
		for i, p := range prefixes {
			paths[i] = testUnicastPath(b, p, "192.168.1.1")
		}
		b.StartTimer()

		for _, p := range paths {
			e.scheduleUpdate(pathUpdate(p))
		}

		b.StopTimer()
		e.dampenMu.Lock()
		if e.flushTimer != nil {
			e.flushTimer.Stop()
			e.flushTimer = nil
		}
		e.dampenMu.Unlock()
		b.StartTimer()
	}
}

func BenchmarkScheduleBurst100(b *testing.B)  { benchmarkScheduleBurst(b, 100) }
func BenchmarkScheduleBurst400(b *testing.B)  { benchmarkScheduleBurst(b, 400) }
func BenchmarkScheduleBurst1600(b *testing.B) { benchmarkScheduleBurst(b, 1600) }

// EnableNetlinkExport accepts dampening_interval and route_protocol and applies
// both, but GetNetlink reported neither. A controller could set them and had no
// way to confirm they took, or to detect drift afterwards - the same blindness
// remove_private had on the peer-group path.
func TestGetNetlinkEchoesExportSettings(t *testing.T) {
	s := newVrfTestServer(t)
	ctx := context.Background()

	// Defaults before anything is configured.
	got, err := s.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint32(0), got.DampeningInterval)
	assert.Equal(t, int32(0), got.RouteProtocol)

	require.NoError(t, s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
		DampeningInterval: 250,
		RouteProtocol:     186,
		Rules:             []*api.NetlinkExportRuleConfig{{Name: "r", TableId: 0}},
	}))

	got, err = s.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)
	assert.True(t, got.ExportEnabled)
	assert.Equal(t, uint32(250), got.DampeningInterval, "dampening_interval must be echoed back")
	assert.Equal(t, int32(186), got.RouteProtocol, "route_protocol must be echoed back")
}

// pathUpdate is the export state for one path: installed through it, or for a
// withdrawal, removed. It is what the export hook produces when
// use-multiple-paths is off.
func pathUpdate(p *table.Path) exportUpdate {
	if p.IsWithdraw {
		return exportUpdate{ref: p}
	}
	return exportUpdate{ref: p, paths: []*table.Path{p}}
}

// --- ECMP export ---

// testPathWithCommunity is testUnicastPath carrying one standard community, for
// the rule-filter cases.
func testPathWithCommunity(t testing.TB, cidr, nexthop string, community uint32) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(cidr))
	assert.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	assert.NoError(t, err)
	return table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), nh,
			bgp.NewPathAttributeCommunities([]uint32{community}),
		}, time.Now(), false)
}

func setUpdate(paths ...*table.Path) exportUpdate {
	return exportUpdate{ref: paths[0], paths: paths}
}

// gateways lists the nexthops a kernel route forwards over, in route order.
func gateways(r *go_netlink.Route) []string {
	var out []string
	for _, nh := range routeNexthopList(r) {
		out = append(out, nh.Gw.String())
	}
	return out
}

// A multipath set installs one kernel route with a nexthop per path.
//
// The export took one path and installed one gateway, so a node running
// use-multiple-paths selected and advertised several paths and forwarded over
// one of them.
func TestExportSetInstallsEveryNexthop(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "global", TableId: 254, Metric: 20})

	e.processUpdate(setUpdate(
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.2"),
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"),
	))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Nil(t, r.Gw, "an ECMP route carries its gateways in MultiPath")
	assert.Equal(t, []string{"192.168.1.1", "192.168.1.2"}, gateways(r),
		"one nexthop per path, in a stable order whatever the selection order")
	assert.Equal(t, 1, f.routeCount(), "one kernel route for the prefix, not one per path")
}

// A set of one is the route this daemon always installed. A node that does not
// run multipath must see no change at all in what reaches its FIB.
func TestExportSingleNexthopKeepsTheSingleGatewayForm(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "global", TableId: 254, Metric: 20})

	e.processUpdate(setUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, "192.168.1.1", r.Gw.String())
	assert.Empty(t, r.MultiPath)
}

// Two sessions to one router give two paths with one nexthop. Installing it
// twice would weight the route toward that router.
func TestExportSetInstallsADuplicateNexthopOnce(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "global", TableId: 254, Metric: 20})

	e.processUpdate(setUpdate(
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"),
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"),
	))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, "192.168.1.1", r.Gw.String(), "a single distinct nexthop is a single-gateway route")
	assert.Empty(t, r.MultiPath)
}

// Losing one of several paths reprograms the route in place. It must not delete
// it: that leaves the prefix with no route until the add lands, which for a
// service VIP is dropped traffic on every peer flap.
//
// Any change of gateway used to be done as a delete followed by an add.
func TestLosingOnePathReplacesTheRouteInPlace(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "global", TableId: 254, Metric: 20})

	a := testUnicastPath(t, "10.0.0.0/24", "192.168.1.1")
	b := testUnicastPath(t, "10.0.0.0/24", "192.168.1.2")
	e.processUpdate(setUpdate(a, b))
	_, delBefore, _ := f.counts()

	e.processUpdate(setUpdate(a))

	r := f.routeFor(254, "10.0.0.0/24")
	require.NotNil(t, r, "the prefix still has a path, so it must still have a route")
	assert.Equal(t, []string{"192.168.1.1"}, gateways(r))
	_, delAfter, _ := f.counts()
	assert.Equal(t, delBefore, delAfter, "the route must be replaced, never deleted and re-added")
}

// A nexthop that fails validation is left out; the route keeps the others.
// Before, one path's unreachable nexthop failed the whole export - fine when
// there was only one path, wrong when there are several.
func TestExportSetLeavesOutAnUnreachableNexthop(t *testing.T) {
	f := newFakeNetlink()
	f.setReachable("192.168.1.1", unix_RT_TABLE_MAIN, unix.RTN_UNICAST)
	e := newTestExportClient(t, f,
		&exportRule{Name: "global", TableId: unix_RT_TABLE_MAIN, Metric: 20, ValidateNexthop: true})

	e.processUpdate(setUpdate(
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"),
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.2"), // not reachable
	))

	r := f.routeFor(unix_RT_TABLE_MAIN, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, []string{"192.168.1.1"}, gateways(r))
}

// Rules match paths, so a rule installs the part of the set it matches. If three
// paths tie and a rule's filter accepts two, that rule's route has two nexthops.
func TestExportSetHonoursEachRulesFilter(t *testing.T) {
	const tagged = 65000<<16 | 100
	f := newOnLinkFake()
	e := newTestExportClient(t, f,
		&exportRule{Name: "tagged", TableId: 100, Metric: 20, Communities: []uint32{tagged}})

	e.processUpdate(setUpdate(
		testPathWithCommunity(t, "10.0.0.0/24", "192.168.1.1", tagged),
		testPathWithCommunity(t, "10.0.0.0/24", "192.168.1.2", tagged),
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.3"),
	))

	r := f.routeFor(100, "10.0.0.0/24")
	require.NotNil(t, r)
	assert.Equal(t, []string{"192.168.1.1", "192.168.1.2"}, gateways(r),
		"only the paths the rule's filter accepts are its nexthops")
}

// ListNetlinkExport reports every nexthop of an ECMP route.
//
// It read the route's single gateway, which an ECMP route does not have - its
// nexthops are in MultiPath - so every ECMP route was listed as "<nil>".
func TestListNetlinkExportReportsEveryNexthop(t *testing.T) {
	f := newOnLinkFake()
	e := newTestExportClient(t, f, &exportRule{Name: "global", TableId: 254, Metric: 20})
	e.processUpdate(setUpdate(
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.1"),
		testUnicastPath(t, "10.0.0.0/24", "192.168.1.2"),
	))
	e.processUpdate(setUpdate(testUnicastPath(t, "10.0.1.0/24", "192.168.1.3")))

	s := NewBgpServer()
	s.shared.mu.Lock()
	s.netlinkExportClient = e
	s.shared.mu.Unlock()

	listed := map[string]*api.ListNetlinkExportResponse_ExportedRoute{}
	require.NoError(t, s.ListNetlinkExport(context.Background(), &api.ListNetlinkExportRequest{},
		func(r *api.ListNetlinkExportResponse) { listed[r.Route.Prefix] = r.Route }))
	require.Len(t, listed, 2)

	ecmp := listed["10.0.0.0/24"]
	assert.Equal(t, []string{"192.168.1.1", "192.168.1.2"}, ecmp.Nexthops)
	assert.Empty(t, ecmp.Nexthop, "an ECMP route has no single gateway")

	single := listed["10.0.1.0/24"]
	assert.Equal(t, []string{"192.168.1.3"}, single.Nexthops)
	assert.Equal(t, "192.168.1.3", single.Nexthop)
}

// A rule gives up its route when none of the selected paths match it any more.
//
// Export only ever added or replaced. When the best path moved from one
// carrying a rule's community to one without it, that rule's route stayed in
// the kernel pointing at the old path's nexthop - even once that path had been
// withdrawn from BGP altogether.
func TestRuleRouteIsRemovedWhenItsPathsLeaveTheSet(t *testing.T) {
	const tagged = 65000<<16 | 100
	f := newOnLinkFake()
	e := newTestExportClient(t, f,
		&exportRule{Name: "tagged", TableId: 100, Metric: 20, Communities: []uint32{tagged}},
		&exportRule{Name: "all", TableId: 200, Metric: 20})

	e.processUpdate(setUpdate(testPathWithCommunity(t, "10.0.0.0/24", "192.168.1.1", tagged)))
	require.True(t, f.hasRoute(100, "10.0.0.0/24"))
	require.True(t, f.hasRoute(200, "10.0.0.0/24"))

	e.processUpdate(setUpdate(testUnicastPath(t, "10.0.0.0/24", "192.168.1.2")))

	assert.False(t, f.hasRoute(100, "10.0.0.0/24"),
		"the tagged rule matches nothing selected now, so its route must go")
	r := f.routeFor(200, "10.0.0.0/24")
	require.NotNil(t, r, "the untagged rule still matches")
	assert.Equal(t, "192.168.1.2", r.Gw.String())
}

// Withdrawing one rule's route during re-evaluation must not forget the other
// rules' routes for the same prefix.
//
// It deleted the whole prefix from the tracking bucket, and every global rule
// shares one bucket - so the surviving rule's route stayed in the kernel and
// was never withdrawn again.
func TestReEvaluationKeepsTheOtherRulesTracking(t *testing.T) {
	const tagged = 65000<<16 | 100
	f := newOnLinkFake()
	tagRule := &exportRule{Name: "tagged", TableId: 100, Metric: 20, Communities: []uint32{tagged}}
	allRule := &exportRule{Name: "all", TableId: 200, Metric: 20}
	e := newTestExportClient(t, f, tagRule, allRule)

	p := testPathWithCommunity(t, "10.0.0.0/24", "192.168.1.1", tagged)
	e.processUpdate(setUpdate(p))
	require.True(t, f.hasRoute(100, "10.0.0.0/24"))
	require.True(t, f.hasRoute(200, "10.0.0.0/24"))

	// Drop the tagged rule; re-evaluation withdraws its route and keeps the other.
	e.setRules([]*exportRule{allRule})
	e.reEvaluateAllRoutes([][]*table.Path{{p}})
	require.False(t, f.hasRoute(100, "10.0.0.0/24"))
	require.True(t, f.hasRoute(200, "10.0.0.0/24"))

	// Now the prefix goes. The surviving route must go with it.
	e.processUpdate(exportUpdate{ref: p.Clone(true)})
	assert.False(t, f.hasRoute(200, "10.0.0.0/24"),
		"the surviving rule's route leaked: re-evaluation had dropped its tracking")
}

// The export hook follows the multipath set, through the real RIB.
//
// It was driven by the best path alone, so a second peer advertising a tying
// path - which changes the multipath set and not the best path - never reached
// the kernel.
func TestNetlinkExportFollowsTheMultipathSet(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1,
			UseMultiplePaths: true, EbgpMaximumPaths: 2,
		},
	}))
	t.Cleanup(func() { assert.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{})) })

	f := newOnLinkFake()
	e, err := newNetlinkExportClientWithHandle(s, logger, f, RTPROT_BGP, 0)
	require.NoError(t, err)
	e.rules = []*exportRule{{Name: "global", TableId: 254, Metric: 20}}
	s.shared.mu.Lock()
	s.netlinkExportClient = e
	s.shared.mu.Unlock()

	const prefix = "10.70.0.0/24"
	peerPath := func(i int) *table.Path {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(t, err)
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(fmt.Sprintf("192.168.70.%d", i)))
		require.NoError(t, err)
		addr := netip.MustParseAddr(fmt.Sprintf("10.0.70.%d", i))
		return table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{AS: 65100 + uint32(i), ID: addr, Address: addr},
			bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), nh},
			time.Now(), false)
	}
	send := func(p *table.Path) {
		s.shared.mu.Lock()
		s.propagateUpdate(nil, []*table.Path{p})
		s.shared.mu.Unlock()
	}
	kernel := func() []string {
		r := f.routeFor(254, prefix)
		if r == nil {
			return nil
		}
		return gateways(r)
	}

	// Export is dampened, so each kernel write lands on a timer rather than
	// inline. settled waits out more than one interval, for the assertions that
	// something did NOT change.
	becomes := func(want []string, msg string) {
		t.Helper()
		require.Eventually(t, func() bool { return slices.Equal(kernel(), want) },
			5*time.Second, 5*time.Millisecond, "%s: kernel has %v", msg, kernel())
	}
	settled := func() { time.Sleep(3 * e.dampeningInterval) }

	p1, p2, p3 := peerPath(1), peerPath(2), peerPath(3)

	send(p1)
	becomes([]string{"192.168.70.1"}, "the first path installs a single-gateway route")

	// The best path does not change here; only the multipath set does.
	send(p2)
	becomes([]string{"192.168.70.1", "192.168.70.2"},
		"a second tying path must reach the kernel as a second nexthop")

	// A third tie is capped out by maximum-paths: nothing may change.
	send(p3)
	settled()
	assert.Equal(t, []string{"192.168.70.1", "192.168.70.2"}, kernel(),
		"maximum-paths caps the kernel route too")

	// Withdrawing an installed path lets the capped-out one in, by replacement.
	_, delBefore, _ := f.counts()
	send(p1.Clone(true))
	becomes([]string{"192.168.70.2", "192.168.70.3"}, "the capped-out tie takes the withdrawn path's place")
	settled()
	_, delAfter, _ := f.counts()
	assert.Equal(t, delBefore, delAfter, "losing a path must replace the route, not delete it")

	// And the prefix goes when its last path does.
	send(p2.Clone(true))
	send(p3.Clone(true))
	becomes(nil, "no paths left, so no route")
}
