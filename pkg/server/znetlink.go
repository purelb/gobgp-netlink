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
	"log/slog"
	"net/netip"
	"sync"
	"time"

	custom_net "github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/netlink"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type netlinkImportStats struct {
	Imported     uint64
	Withdrawn    uint64
	Errors       uint64
	LastImport   time.Time
	LastWithdraw time.Time
	LastError    time.Time
	LastErrorMsg string
}

type netlinkClient struct {
	client *netlink.NetlinkClient
	server *BgpServer
	dead   chan struct{}
	done   chan struct{} // signals loop has exited
	// advertisedPaths tracks paths per VRF (vrf name -> prefix -> path)
	// empty string key is used for global table
	advertisedPaths map[string]map[string]*table.Path
	pathsMu         sync.RWMutex // protects advertisedPaths
	stats           netlinkImportStats
	statsMu         sync.RWMutex
}

func newNetlinkClient(s *BgpServer) (*netlinkClient, error) {
	s.logger.Debug("creating new netlink client", slog.String("Topic", "netlink"))
	n, err := netlink.NewNetlinkClient(s.logger)
	if err != nil {
		return nil, err
	}
	w := &netlinkClient{
		client:          n,
		server:          s,
		dead:            make(chan struct{}),
		done:            make(chan struct{}),
		advertisedPaths: make(map[string]map[string]*table.Path),
	}
	w.runImport()
	go w.loop()
	return w, nil
}

func (n *netlinkClient) runImport() {
	// Count VRFs in both config and RIB for debugging
	configVrfCount := len(n.server.bgpConfig.Vrfs)
	ribVrfCount := 0
	if n.server.globalRib != nil {
		ribVrfCount = len(n.server.globalRib.Vrfs)
	}

	n.server.logger.Debug("Running netlink import",
		slog.String("Topic", "netlink"),
		slog.Int("ConfigVRFs", configVrfCount),
		slog.Int("RibVRFs", ribVrfCount))

	// Import for global table
	if n.server.bgpConfig.Netlink.Import.Enabled {
		vrfName := n.server.bgpConfig.Netlink.Import.Vrf
		interfaces := n.server.bgpConfig.Netlink.Import.InterfaceList
		n.server.logger.Debug("Global netlink import enabled",
			slog.String("Topic", "netlink"),
			slog.String("TargetVRF", vrfName),
			slog.Any("Interfaces", interfaces))
		n.importForVrf(vrfName, interfaces)
	}

	// Import for each VRF with netlink-import configured
	// Check both bgpConfig.Vrfs and globalRib.Vrfs since VRFs added via API
	// may not be in bgpConfig.Vrfs yet
	vrfConfigMap := make(map[string]*oc.Vrf)
	for i := range n.server.bgpConfig.Vrfs {
		vrf := &n.server.bgpConfig.Vrfs[i]
		vrfConfigMap[vrf.Config.Name] = vrf
	}

	// Iterate over active VRFs in the RIB
	if n.server.globalRib != nil {
		for vrfName := range n.server.globalRib.Vrfs {
			// Look up VRF config
			vrfConfig, hasConfig := vrfConfigMap[vrfName]

			n.server.logger.Debug("Checking VRF for import",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.Bool("HasConfig", hasConfig))

			if hasConfig && vrfConfig.NetlinkImport.Enabled {
				n.server.logger.Info("Starting VRF import",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrfName),
					slog.Any("Interfaces", vrfConfig.NetlinkImport.InterfaceList))
				n.importForVrf(vrfName, vrfConfig.NetlinkImport.InterfaceList)
			} else if hasConfig {
				n.server.logger.Debug("VRF import not enabled",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrfName),
					slog.Bool("ImportEnabled", vrfConfig.NetlinkImport.Enabled))
			} else {
				n.server.logger.Debug("No config found for VRF",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrfName))
			}
		}
	}
}

func (n *netlinkClient) importForVrf(vrfName string, interfaces []string) {
	n.pathsMu.Lock()
	// Initialize VRF tracking if needed
	if n.advertisedPaths[vrfName] == nil {
		n.advertisedPaths[vrfName] = make(map[string]*table.Path)
	}
	previousPaths := n.advertisedPaths[vrfName]
	n.pathsMu.Unlock()

	n.server.logger.Debug("Starting VRF import scan",
		slog.String("Topic", "netlink"),
		slog.String("VRF", vrfName),
		slog.Any("Interfaces", interfaces))

	currentPaths := make(map[string]*table.Path)

	// Resolve any glob patterns ("eth*", "vlan*") to concrete interface names
	// before scanning. This must happen here rather than inside
	// GetGlobalUnicastRoutes: the concrete name is stored on the path source as
	// NetlinkIfName and surfaces through the API and CLI, so a pattern must never
	// be passed downstream.
	interfaces, err := custom_net.ExpandInterfacePatterns(interfaces, n.server.logger)
	if err != nil {
		n.server.logger.Error("failed to expand interface patterns",
			slog.String("Topic", "netlink"),
			slog.String("VRF", vrfName),
			slog.Any("Error", err))
		return
	}

	// Scan interfaces for this VRF
	for _, iface := range interfaces {
		routes, err := custom_net.GetGlobalUnicastRoutes(iface, n.server.logger)
		if err != nil {
			n.server.logger.Error("failed to get connected routes",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.String("Interface", iface),
				slog.Any("Error", err))
			continue
		}
		n.server.logger.Debug("Found routes on interface",
			slog.String("Topic", "netlink"),
			slog.String("VRF", vrfName),
			slog.String("Interface", iface),
			slog.Int("RouteCount", len(routes)))
		for _, path := range n.ipNetsToPaths(routes, iface) {
			key := path.GetNlri().String()
			currentPaths[key] = path
			n.server.logger.Debug("Adding route to current paths",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.String("Route", key),
				slog.String("Family", path.GetFamily().String()))
		}
	}

	n.server.logger.Debug("VRF import scan complete",
		slog.String("Topic", "netlink"),
		slog.String("VRF", vrfName),
		slog.Int("CurrentPaths", len(currentPaths)),
		slog.Int("AdvertisedPaths", len(previousPaths)))

	// Find new paths to add
	newPathList := make([]*table.Path, 0)
	for key, path := range currentPaths {
		if _, ok := previousPaths[key]; !ok {
			newPathList = append(newPathList, path)
			n.server.logger.Debug("New route to import",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.String("Route", key),
				slog.String("Family", path.GetFamily().String()))
		}
	}

	// Find old paths to withdraw
	withdrawnPathList := make([]*table.Path, 0)
	for key, path := range previousPaths {
		if _, ok := currentPaths[key]; !ok {
			n.server.logger.Debug("Withdrawing route from netlink",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.String("Route", path.GetNlri().String()))
			withdrawnPathList = append(withdrawnPathList, path.Clone(true))
		}
	}

	// Update advertised paths for this VRF
	n.pathsMu.Lock()
	n.advertisedPaths[vrfName] = currentPaths
	n.pathsMu.Unlock()

	// Propagate changes
	if len(newPathList) > 0 {
		n.server.logger.Info("Importing routes to VRF",
			slog.String("Topic", "netlink"),
			slog.String("VRF", vrfName),
			slog.Int("RouteCount", len(newPathList)))
		if err := n.server.addPathList(vrfName, newPathList); err != nil {
			n.server.logger.Error("failed to add path from netlink",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.Any("Error", err))
			n.statsMu.Lock()
			n.stats.Errors++
			n.stats.LastError = time.Now()
			n.stats.LastErrorMsg = err.Error()
			n.statsMu.Unlock()
		} else {
			n.server.logger.Info("Successfully imported routes to VRF",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.Int("RouteCount", len(newPathList)))
			n.statsMu.Lock()
			n.stats.Imported += uint64(len(newPathList))
			n.stats.LastImport = time.Now()
			n.statsMu.Unlock()
		}
	}

	if len(withdrawnPathList) > 0 {
		if err := n.server.addPathList(vrfName, withdrawnPathList); err != nil {
			n.server.logger.Error("failed to withdraw path from netlink",
				slog.String("Topic", "netlink"),
				slog.String("VRF", vrfName),
				slog.Any("Error", err))
			n.statsMu.Lock()
			n.stats.Errors++
			n.stats.LastError = time.Now()
			n.stats.LastErrorMsg = err.Error()
			n.statsMu.Unlock()
		} else {
			n.statsMu.Lock()
			n.stats.Withdrawn += uint64(len(withdrawnPathList))
			n.stats.LastWithdraw = time.Now()
			n.statsMu.Unlock()
		}
	}
}

// rescan triggers an immediate import scan (called when VRFs are added/changed)
func (n *netlinkClient) rescan() {
	n.server.logger.Debug("Triggering immediate netlink import rescan", slog.String("Topic", "netlink"))
	n.runImport()
}

func (n *netlinkClient) loop() {
	n.server.logger.Debug("starting netlink client loop", slog.String("Topic", "netlink"))
	defer close(n.done) // signal loop has exited
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.dead:
			return
		case <-ticker.C:
			n.runImport()
		}
	}
}

func (n *netlinkClient) ipNetsToPaths(routes []*custom_net.ConnectedRoute, iface string) []*table.Path {
	pathList := make([]*table.Path, 0, len(routes))
	for _, route := range routes {
		pathNlri, err := table.NewNlriFromAPI(route.Prefix)
		if err != nil {
			n.server.logger.Warn("failed to create nlri from netlink route",
				slog.String("Topic", "netlink"),
				slog.Any("Route", route),
				slog.Any("Error", err))
			continue
		}

		pattr := make([]bgp.PathAttributeInterface, 0)
		origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
		pattr = append(pattr, origin)

		family := bgp.RF_IPv4_UC
		if route.Prefix.IP.To4() == nil {
			family = bgp.RF_IPv6_UC
			// Set unspecified nexthop - will be updated to peer's local address by UpdatePathAttrs
			mpreach, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{pathNlri}, netip.MustParseAddr("::"))
			pattr = append(pattr, mpreach)
		} else {
			// Set unspecified nexthop - will be updated to peer's local address by UpdatePathAttrs
			nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
			pattr = append(pattr, nexthop)
		}

		source := table.NewNetlinkPeerInfo(iface)

		path := table.NewPath(family, source, pathNlri, false, pattr, time.Now(), false)
		path.SetIsFromExternal(true)
		pathList = append(pathList, path)
	}
	return pathList
}

// getStats returns a copy of the current import statistics
func (n *netlinkClient) getStats() netlinkImportStats {
	n.statsMu.RLock()
	defer n.statsMu.RUnlock()
	return n.stats
}

// stop shuts down the netlink import client
// If withdrawRoutes is true (keep_routes=false), withdraw all imported routes from RIB
func (n *netlinkClient) stop(withdrawRoutes bool) {
	// Signal loop to exit
	close(n.dead)

	// Wait for loop goroutine to exit before accessing advertisedPaths
	<-n.done

	if withdrawRoutes {
		n.pathsMu.Lock()
		for vrfName, vrfPaths := range n.advertisedPaths {
			withdrawList := make([]*table.Path, 0, len(vrfPaths))
			for _, path := range vrfPaths {
				withdrawList = append(withdrawList, path.Clone(true))
			}
			if len(withdrawList) > 0 {
				if err := n.server.addPathList(vrfName, withdrawList); err != nil {
					n.server.logger.Error("failed to withdraw paths during stop",
						slog.String("Topic", "netlink"),
						slog.String("VRF", vrfName),
						slog.Any("Error", err))
				}
			}
		}
		n.advertisedPaths = make(map[string]map[string]*table.Path)
		n.pathsMu.Unlock()
	}
}

// withdrawVrf withdraws all imported routes for a specific VRF
func (n *netlinkClient) withdrawVrf(vrfName string) {
	n.pathsMu.Lock()
	defer n.pathsMu.Unlock()

	if vrfPaths, ok := n.advertisedPaths[vrfName]; ok {
		withdrawList := make([]*table.Path, 0, len(vrfPaths))
		for _, path := range vrfPaths {
			withdrawList = append(withdrawList, path.Clone(true))
		}
		if len(withdrawList) > 0 {
			if err := n.server.addPathList(vrfName, withdrawList); err != nil {
				n.server.logger.Error("failed to withdraw VRF paths",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrfName),
					slog.Any("Error", err))
			}
		}
		delete(n.advertisedPaths, vrfName)
	}
}
