//go:build linux

// Copyright (C) 2025 Acnodal Inc.
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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestNetlinkClient(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(t, err)

	n, err := newNetlinkClient(s)
	assert.NoError(t, err)
	// newNetlinkClient starts a 5s scan goroutine. Without this it runs for the
	// life of the test binary and contends with every later test in the package.
	// stopLocked requires shared.mu, matching its production callers, which all
	// run inside mgmtOperation.
	t.Cleanup(func() {
		s.shared.mu.Lock()
		n.stopLocked(false)
		s.shared.mu.Unlock()
	})
}

func TestEnableNetlink(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(t, err)

	// Test enabling import
	s.bgpConfig.Netlink.Import.Enabled = true
	s.bgpConfig.Netlink.Import.Vrf = "vrf1"
	s.bgpConfig.Netlink.Import.InterfaceList = []string{"eth0", "eth1"}
	err = s.StartNetlink(context.Background())
	assert.NoError(t, err)
	assert.True(t, s.bgpConfig.Netlink.Import.Enabled)
	assert.Equal(t, "vrf1", s.bgpConfig.Netlink.Import.Vrf)
	assert.Equal(t, []string{"eth0", "eth1"}, s.bgpConfig.Netlink.Import.InterfaceList)

	// Test enabling export with rules
	// Note: Export configuration now uses Rules structure instead of direct fields
	s.bgpConfig.Netlink.Export.Enabled = true
	err = s.StartNetlink(context.Background())
	assert.NoError(t, err)
	assert.True(t, s.bgpConfig.Netlink.Export.Enabled)
}

func TestEnableNetlinkImportGRPC(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(t, err)

	// Test nil request
	err = s.EnableNetlinkImport(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil request")

	// Test enabling import via gRPC
	err = s.EnableNetlinkImport(context.Background(), &api.EnableNetlinkImportRequest{
		Vrf:        "testvrf",
		Interfaces: []string{"eth0", "eth1"},
	})
	assert.NoError(t, err)

	// Verify config was updated
	assert.True(t, s.bgpConfig.Netlink.Import.Enabled)
	assert.Equal(t, "testvrf", s.bgpConfig.Netlink.Import.Vrf)
	assert.Equal(t, []string{"eth0", "eth1"}, s.bgpConfig.Netlink.Import.InterfaceList)
}

func TestEnableNetlinkExportGRPC(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(t, err)

	// Test nil request
	err = s.EnableNetlinkExport(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil request")

	// Test enabling export via gRPC with rules
	err = s.EnableNetlinkExport(context.Background(), &api.EnableNetlinkExportRequest{
		DampeningInterval: 500,
		RouteProtocol:     186,
		Rules: []*api.NetlinkExportRuleConfig{
			{
				Name:          "rule1",
				CommunityList: []string{"65000:100"},
				Vrf:           "exportvrf",
				TableId:       100,
				Metric:        10,
			},
			{
				Name:               "rule2",
				LargeCommunityList: []string{"65000:1:1"},
				TableId:            200,
				ValidateNexthop:    true,
			},
		},
	})
	assert.NoError(t, err)

	// Verify config was updated
	assert.True(t, s.bgpConfig.Netlink.Export.Enabled)
	assert.Equal(t, uint32(500), s.bgpConfig.Netlink.Export.DampeningInterval)
	assert.Equal(t, 186, s.bgpConfig.Netlink.Export.RouteProtocol)
	assert.Len(t, s.bgpConfig.Netlink.Export.Rules, 2)

	// Verify first rule
	assert.Equal(t, "rule1", s.bgpConfig.Netlink.Export.Rules[0].Name)
	assert.Equal(t, []string{"65000:100"}, s.bgpConfig.Netlink.Export.Rules[0].CommunityList)
	assert.Equal(t, "exportvrf", s.bgpConfig.Netlink.Export.Rules[0].Vrf)
	assert.Equal(t, 100, s.bgpConfig.Netlink.Export.Rules[0].TableId)
	assert.Equal(t, uint32(10), s.bgpConfig.Netlink.Export.Rules[0].Metric)

	// Verify second rule
	assert.Equal(t, "rule2", s.bgpConfig.Netlink.Export.Rules[1].Name)
	assert.Equal(t, []string{"65000:1:1"}, s.bgpConfig.Netlink.Export.Rules[1].LargeCommunityList)
	assert.Equal(t, 200, s.bgpConfig.Netlink.Export.Rules[1].TableId)
}

func TestEnableNetlinkExportDefaultRouteProtocol(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(t, err)

	// Test that route_protocol=0 doesn't override existing config
	s.bgpConfig.Netlink.Export.RouteProtocol = 200 // Set existing value
	err = s.EnableNetlinkExport(context.Background(), &api.EnableNetlinkExportRequest{
		RouteProtocol: 0, // Zero should not override
	})
	assert.NoError(t, err)

	// RouteProtocol should remain unchanged when 0 is passed
	assert.Equal(t, 200, s.bgpConfig.Netlink.Export.RouteProtocol)
}

// newTestImportServer starts a server with global netlink import configured for
// the given interfaces, plus an import client over a synthetic topology.
//
// The scan loop is deliberately not started: these tests drive runImportCycle
// directly so assertions are deterministic rather than racing a 5s ticker.
func newTestImportServer(t *testing.T, interfaces []string, topology map[string][]*netutils.ConnectedRoute) (*BgpServer, *netlinkClient) {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	assert.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	t.Cleanup(func() {
		assert.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	s.shared.mu.Lock()
	s.bgpConfig.Netlink.Import.Enabled = true
	s.bgpConfig.Netlink.Import.InterfaceList = interfaces
	s.shared.mu.Unlock()

	n := &netlinkClient{
		server:   s,
		dead:     make(chan struct{}),
		done:     make(chan struct{}),
		rescanCh: make(chan struct{}, 1),
		scan: func(iface string) ([]*netutils.ConnectedRoute, error) {
			routes, ok := topology[iface]
			if !ok {
				return nil, fmt.Errorf("failed to find interface %s", iface)
			}
			return routes, nil
		},
		advertisedPaths: make(map[string]map[string]*importedRoute),
	}
	return s, n
}

func connected(t *testing.T, cidr string) *netutils.ConnectedRoute {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	assert.NoError(t, err)
	return &netutils.ConnectedRoute{Prefix: ipnet, NextHop: ip}
}

func advertisedCount(n *netlinkClient, vrf string) int {
	n.pathsMu.RLock()
	defer n.pathsMu.RUnlock()
	return len(n.advertisedPaths[vrf])
}

// TestImportScanSeam proves the import path is testable without a real
// interface. A CI runner has no eth0, so before the seam existed every import
// test drove an empty scan and asserted nothing.
func TestImportScanSeam(t *testing.T) {
	_, n := newTestImportServer(t, []string{"eth0", "eth1"},
		map[string][]*netutils.ConnectedRoute{
			"eth0": {connected(t, "10.0.1.1/24")},
			"eth1": {connected(t, "10.0.2.1/24"), connected(t, "2001:db8::1/64")},
		})

	n.runImportCycle()
	assert.Equal(t, 3, advertisedCount(n, ""), "all three connected routes should be imported")
}

// TestImportScanSeamSkipsFailedInterface: one unreadable interface must not
// abort the scan of the others.
func TestImportScanSeamSkipsFailedInterface(t *testing.T) {
	_, n := newTestImportServer(t, []string{"missing0", "eth0"},
		map[string][]*netutils.ConnectedRoute{
			"eth0": {connected(t, "10.0.1.1/24")},
		})

	n.runImportCycle()
	assert.Equal(t, 1, advertisedCount(n, ""), "the readable interface should still be imported")
}

// TestImportCycleWithdrawsVanishedRoutes: a prefix that disappears from the
// interface between passes must be withdrawn.
func TestImportCycleWithdrawsVanishedRoutes(t *testing.T) {
	topology := map[string][]*netutils.ConnectedRoute{
		"eth0": {connected(t, "10.0.1.1/24"), connected(t, "10.0.2.1/24")},
	}
	_, n := newTestImportServer(t, []string{"eth0"}, topology)

	n.runImportCycle()
	assert.Equal(t, 2, advertisedCount(n, ""))

	topology["eth0"] = []*netutils.ConnectedRoute{connected(t, "10.0.1.1/24")}
	n.runImportCycle()
	assert.Equal(t, 1, advertisedCount(n, ""), "the vanished prefix should be withdrawn")
}

// TestImportCycleDiscardsScanInvalidatedMidFlight is the generation counter.
//
// A scan runs without the server lock, so state it depends on can change while
// it is in flight. Publishing anyway would resurrect tracking entries that
// withdrawVrfLocked had just cleared, and because the VRF is disabled by then
// nothing would ever clear them again: the routes would be gone from the RIB but
// recorded as advertised forever.
func TestImportCycleDiscardsScanInvalidatedMidFlight(t *testing.T) {
	scanning := make(chan struct{})
	release := make(chan struct{})

	_, n := newTestImportServer(t, []string{"eth0"}, nil)
	var once sync.Once
	n.scan = func(iface string) ([]*netutils.ConnectedRoute, error) {
		// Block the first scan mid-flight so the test can invalidate it.
		once.Do(func() {
			close(scanning)
			<-release
		})
		return []*netutils.ConnectedRoute{connected(t, "10.0.1.1/24")}, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		n.runImportCycle()
	}()

	<-scanning
	// Invalidate while the scan is between phases, exactly as a concurrent
	// DisableVrfNetlinkImport would.
	n.server.shared.mu.Lock()
	n.generation++
	n.server.shared.mu.Unlock()
	close(release)
	<-done

	assert.Equal(t, 0, advertisedCount(n, ""),
		"a scan invalidated mid-flight must not publish")

	// The next pass sees the current world and publishes normally.
	n.runImportCycle()
	assert.Equal(t, 1, advertisedCount(n, ""))
}

// TestStopLockedDoesNotWaitForScanLoop guards against the deadlock the previous
// <-n.done handshake caused: stop runs holding shared.mu, and the scan loop
// needs that same lock to finish a pass, so waiting for it could never succeed.
func TestStopLockedDoesNotWaitForScanLoop(t *testing.T) {
	s, n := newTestImportServer(t, []string{"eth0"},
		map[string][]*netutils.ConnectedRoute{
			"eth0": {connected(t, "10.0.1.1/24")},
		})

	n.runImportCycle()
	assert.Equal(t, 1, advertisedCount(n, ""))

	// Start the loop so there is a live goroutine to contend with.
	go n.loop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.shared.mu.Lock()
		n.stopLocked(true)
		s.shared.mu.Unlock()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stopLocked blocked; it must not wait for the scan loop")
	}

	assert.Equal(t, 0, advertisedCount(n, ""), "stop should clear tracked paths")
}

// TestMergeImportWork: a VRF named by both the global block and its own block
// must be scanned once. Two entries would share one tracking bucket, each pass
// withdrawing what the other just added.
func TestMergeImportWork(t *testing.T) {
	got := mergeImportWork([]importWork{
		{vrfName: "", interfaces: []string{"eth0"}},
		{vrfName: "vrf1", interfaces: []string{"eth1"}},
		{vrfName: "vrf1", interfaces: []string{"eth2", "eth1"}},
	})

	assert.Len(t, got, 2)
	assert.Equal(t, "", got[0].vrfName)
	assert.Equal(t, []string{"eth0"}, got[0].interfaces)
	assert.Equal(t, "vrf1", got[1].vrfName)
	assert.Equal(t, []string{"eth1", "eth2"}, got[1].interfaces,
		"interfaces should merge without duplicates")
}

// TestVrfImportWithdrawalReachesRib is the regression test for cached paths
// being mutated in place.
//
// The import loop used to store the live *table.Path it handed to addPathList.
// For a VRF, fixupApiPath runs that path through Vrf.ToGlobalPath, which
// rewrites the NLRI to the VPN family in place. Withdrawing the cached object
// then handed ToGlobalPath a VPN-family path it has no case for, so it returned
// "unsupported route family for vrf", fixupApiPath propagated that, and
// addPathList dropped the whole withdrawal batch. The route stayed in the RIB
// and kept being advertised.
//
// Caching the kernel route and rebuilding the path is what fixes it, and this
// test fails without that: it was found on live hardware, not here, because
// there was no VRF import withdrawal test at all.
func TestVrfImportWithdrawalReachesRib(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	assert.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	t.Cleanup(func() {
		assert.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	rd, err := bgp.ParseRouteDistinguisher("64553:175")
	assert.NoError(t, err)
	apiRd, err := apiutil.MarshalRD(rd)
	assert.NoError(t, err)
	assert.NoError(t, s.AddVrf(context.Background(), &api.AddVrfRequest{
		Vrf: &api.Vrf{Name: "vrf1", Id: 1, Rd: apiRd},
	}))

	topology := map[string][]*netutils.ConnectedRoute{
		"kubevrf0": {connected(t, "172.31.9.1/24")},
	}

	s.shared.mu.Lock()
	for i := range s.bgpConfig.Vrfs {
		if s.bgpConfig.Vrfs[i].Config.Name == "vrf1" {
			s.bgpConfig.Vrfs[i].NetlinkImport.Enabled = true
			s.bgpConfig.Vrfs[i].NetlinkImport.InterfaceList = []string{"kubevrf0"}
		}
	}
	s.shared.mu.Unlock()

	n := &netlinkClient{
		server: s, dead: make(chan struct{}), done: make(chan struct{}),
		rescanCh: make(chan struct{}, 1),
		scan: func(iface string) ([]*netutils.ConnectedRoute, error) {
			routes, ok := topology[iface]
			if !ok {
				return nil, fmt.Errorf("failed to find interface %s", iface)
			}
			return routes, nil
		},
		advertisedPaths: make(map[string]map[string]*importedRoute),
	}

	n.runImportCycle()
	assert.Equal(t, 1, advertisedCount(n, "vrf1"), "the route should be imported")

	statsAfterImport := n.getStats()
	assert.Zero(t, statsAfterImport.Errors, "import must not error")

	// The address goes away.
	topology["kubevrf0"] = nil
	n.runImportCycle()

	assert.Equal(t, 0, advertisedCount(n, "vrf1"), "tracking should be cleared")

	st := n.getStats()
	assert.Zero(t, st.Errors,
		"the withdrawal must not fail; a non-zero error count means the cached "+
			"path was converted to the VPN family twice")
	assert.Equal(t, uint64(1), st.Withdrawn, "the withdrawal must reach the RIB")
}
