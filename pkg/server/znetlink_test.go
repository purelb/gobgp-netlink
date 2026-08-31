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
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"

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
	t.Cleanup(func() { n.stop(false) })
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

// newTestImportClient builds an import client over a synthetic interface
// topology, without starting the scan loop.
//
// The loop is deliberately not started: these tests drive runImport directly so
// the assertions are deterministic rather than racing a 5s ticker.
func newTestImportClient(s *BgpServer, topology map[string][]*netutils.ConnectedRoute) *netlinkClient {
	return &netlinkClient{
		server: s,
		dead:   make(chan struct{}),
		done:   make(chan struct{}),
		scan: func(iface string) ([]*netutils.ConnectedRoute, error) {
			routes, ok := topology[iface]
			if !ok {
				return nil, fmt.Errorf("failed to find interface %s", iface)
			}
			return routes, nil
		},
		advertisedPaths: make(map[string]map[string]*table.Path),
	}
}

func connected(t *testing.T, cidr string) *netutils.ConnectedRoute {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	assert.NoError(t, err)
	return &netutils.ConnectedRoute{Prefix: ipnet, NextHop: ip}
}

// TestImportScanSeam proves the import path is testable without a real
// interface. A CI runner has no eth0, so before the seam existed every import
// test drove an empty scan and asserted nothing.
func TestImportScanSeam(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	assert.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	n := newTestImportClient(s, map[string][]*netutils.ConnectedRoute{
		"eth0": {connected(t, "10.0.1.1/24")},
		"eth1": {connected(t, "10.0.2.1/24"), connected(t, "2001:db8::1/64")},
	})

	n.importForVrf("", []string{"eth0", "eth1"})

	n.pathsMu.RLock()
	got := len(n.advertisedPaths[""])
	n.pathsMu.RUnlock()
	assert.Equal(t, 3, got, "all three connected routes should be imported")
}

// TestImportScanSeamSkipsFailedInterface: one unreadable interface must not
// abort the scan of the others.
func TestImportScanSeamSkipsFailedInterface(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	assert.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	n := newTestImportClient(s, map[string][]*netutils.ConnectedRoute{
		"eth0": {connected(t, "10.0.1.1/24")},
	})

	n.importForVrf("", []string{"missing0", "eth0"})

	n.pathsMu.RLock()
	got := len(n.advertisedPaths[""])
	n.pathsMu.RUnlock()
	assert.Equal(t, 1, got, "the readable interface should still be imported")
}
