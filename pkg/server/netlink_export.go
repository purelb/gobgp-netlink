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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	go_netlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// RTPROT_BGP is the Linux route protocol for BGP routes
	RTPROT_BGP = 186

	// Default dampening interval to prevent flapping
	defaultDampeningInterval = 100 * time.Millisecond
)

// Route protocols reserved by the kernel and iproute2. Exporting under one of
// these would make our routes indistinguishable from the system's own, and
// cleanupStaleRoutes would then delete the system's routes.
var reservedRouteProtocols = map[int]string{
	1: "RTPROT_REDIRECT",
	2: "RTPROT_KERNEL",
	3: "RTPROT_BOOT",
	4: "RTPROT_STATIC",
}

// validateRouteProtocol rejects values that cannot be used safely as the export
// route protocol.
//
// The protocol is not merely a label: cleanupStaleRoutes uses it as the sole
// filter for a route-deletion sweep, so an out-of-range or reserved value is a
// destructive misconfiguration rather than a cosmetic one.
//
// Out-of-range values are especially bad because the kernel and the filter
// disagree. The netlink library only writes the protocol when it is > 0, so a
// negative value installs routes as RTPROT_UNSPEC(0) while the sweep still looks
// for the negative number - the daemon's own routes become unattributable and
// can never be cleaned up. Values above 255 truncate to a uint8 on write but not
// on the comparison, with the same split-brain result.
func validateRouteProtocol(proto int) error {
	if proto < 1 || proto > 255 {
		return fmt.Errorf("route protocol %d out of range (must be 1-255)", proto)
	}
	if name, reserved := reservedRouteProtocols[proto]; reserved {
		return fmt.Errorf("route protocol %d is reserved (%s) and cannot be used for export", proto, name)
	}
	return nil
}

// netlinkHandle is the kernel surface the export client uses.
//
// It exists so the export path can be tested. netlink_export.go is the file
// that programs the node's FIB and it had no test coverage at all, because
// every operation went straight to a *netlink.Handle and therefore to the real
// kernel. *netlink.Handle satisfies this as-is, so production code needs no
// adapter.
//
// Declared here rather than reusing pkg/netlink's NetlinkManager: that
// interface has three methods, wraps package-level functions rather than a
// handle, and is not what this client needs.
type netlinkHandle interface {
	Close()
	LinkByName(name string) (go_netlink.Link, error)
	LinkList() ([]go_netlink.Link, error)
	RouteDel(route *go_netlink.Route) error
	RouteGet(destination net.IP) ([]go_netlink.Route, error)
	RouteGetWithOptions(destination net.IP, options *go_netlink.RouteGetOptions) ([]go_netlink.Route, error)
	RouteList(link go_netlink.Link, family int) ([]go_netlink.Route, error)
	RouteListFiltered(family int, filter *go_netlink.Route, filterMask uint64) ([]go_netlink.Route, error)
	RouteReplace(route *go_netlink.Route) error
	SetSocketTimeout(to time.Duration) error
}

// Compile-time assertion that the real handle still satisfies the seam.
var _ netlinkHandle = (*go_netlink.Handle)(nil)

// exportRule defines a rule for exporting BGP routes to Linux routing tables
type exportRule struct {
	Name             string
	Communities      []uint32              // Standard communities (32-bit)
	LargeCommunities []*bgp.LargeCommunity // Large communities (96-bit)
	VrfName          string                // VRF name (empty = global table)
	TableId          int                   // Linux routing table ID
	Metric           uint32                // Route metric
	ValidateNexthop  bool                  // Validate nexthop reachability (default: true)
}

// exportedRouteInfo tracks metadata about an exported route
type exportedRouteInfo struct {
	Route      *go_netlink.Route // The Linux route that was installed
	RuleName   string            // Which export rule matched
	ExportedAt time.Time         // When the route was exported
}

// isRouteAbsent reports whether a netlink error means the route is already gone.
//
// ESRCH/ENOENT are the kernel saying the route is not there, which is the state
// a delete is trying to reach. Every other errno stays an error: EPERM means we
// lack the capability, EINVAL means the request was malformed, and silently
// swallowing either would hide a real failure.
func isRouteAbsent(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}

// exportPrefixKey returns the prefix a path is tracked and programmed under.
//
// There is one derivation because there used to be three, and they disagreed.
// reEvaluateAllRoutes used nlri.String(), which for a VPN family includes the RD
// ("100:1:10.0.0.0/24"), while exportRoute used IPPrefix(), which does not
// ("10.0.0.0/24"). The two were then compared against each other, never matched,
// and every VRF-exported route was withdrawn on any re-evaluation.
//
// The RD-stripped form is the correct one: it is what net.ParseCIDR and the
// kernel's RTA_DST need. VRFs are separated by the outer tracking key, not here.
func exportPrefixKey(path *table.Path) (string, error) {
	nlri := path.GetNlri()
	switch family := path.GetFamily(); family {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		vpnNlri, ok := nlri.(*bgp.LabeledVPNIPAddrPrefix)
		if !ok {
			return "", fmt.Errorf("unexpected VPN NLRI type for family %s", family.String())
		}
		return vpnNlri.IPPrefix(), nil
	default:
		return nlri.String(), nil
	}
}

// dampenEntry tracks pending route updates for dampening
type dampenEntry struct {
	path      *table.Path
	timer     *time.Timer
	updatedAt time.Time
}

// exportStats tracks export operation statistics
type exportStats struct {
	Exported          uint64    // Total routes exported
	Withdrawn         uint64    // Total routes withdrawn
	Errors            uint64    // Total errors
	NexthopValidation uint64    // Nexthop validation attempts
	NexthopFailed     uint64    // Nexthop validation failures
	DampenedUpdates   uint64    // Updates that were dampened
	CleanupDeleted    uint64    // Stale routes deleted by the startup sweep
	CleanupSkipped    uint64    // Routes the startup sweep left in place
	LastExport        time.Time // Last successful export
	LastWithdraw      time.Time // Last successful withdrawal
	LastError         time.Time // Last error
	LastErrorMsg      string    // Last error message
}

// vrfExportConfig holds per-VRF export configuration
type vrfExportConfig struct {
	VrfName            string                // GoBGP VRF name
	LinuxVrf           string                // Target Linux VRF name (default: same as VrfName)
	LinuxTableId       int                   // Target Linux table ID (0 = auto-lookup)
	Metric             uint32                // Route metric
	ValidateNexthop    bool                  // Validate nexthop reachability
	CommunityList      []uint32              // Standard communities (parsed)
	LargeCommunityList []*bgp.LargeCommunity // Large communities (parsed)
}

// netlinkExportClient manages exporting BGP routes to Linux routing tables
type netlinkExportClient struct {
	client netlinkHandle
	server *BgpServer
	logger *slog.Logger
	rules  []*exportRule
	// exported tracks installed routes: vrf -> prefix -> one entry per rule.
	//
	// The per-prefix list is not incidental. Two rules can legitimately install
	// different kernel routes for the same prefix (different table, different
	// metric), and the kernel keeps both. A single entry per prefix meant the
	// second rule overwrote the first's bookkeeping and the first's route leaked
	// permanently, invisible to withdraw, flush and flushVrf. Every global rule
	// shares the "" bucket, so this was the default case, not an edge case.
	exported map[string]map[string][]*exportedRouteInfo
	mu       sync.RWMutex

	// VRF export mapping
	rdToVrf  map[string]string           // RD string -> VRF name
	vrfRules map[string]*vrfExportConfig // VRF name -> export config

	// Dampening
	dampeningInterval time.Duration
	pendingUpdates    map[string]*dampenEntry // prefix -> entry
	dampenMu          sync.Mutex

	// Statistics
	stats   exportStats
	statsMu sync.RWMutex

	// Route protocol
	routeProtocol int

	// sweptStaleRoutes records that the startup sweep has already run for this
	// client, so a later StartNetlink cannot delete our own live routes.
	// Guarded by mu.
	sweptStaleRoutes bool

	// Shutdown
	stopCh  chan struct{}
	stopped bool // protects against double stop()
}

// newNetlinkExportClient creates a new netlink export client talking to the real
// kernel.
func newNetlinkExportClient(server *BgpServer, logger *slog.Logger, routeProtocol int, dampeningInterval time.Duration) (*netlinkExportClient, error) {
	handle, err := go_netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to create netlink handle: %w", err)
	}
	return newNetlinkExportClientWithHandle(server, logger, handle, routeProtocol, dampeningInterval)
}

// newNetlinkExportClientWithHandle builds the client over a caller-supplied
// kernel handle, so tests can substitute a fake for the real netlink socket.
func newNetlinkExportClientWithHandle(server *BgpServer, logger *slog.Logger, handle netlinkHandle, routeProtocol int, dampeningInterval time.Duration) (*netlinkExportClient, error) {
	// Validate here rather than only at the gRPC entry point: the TOML config
	// path reaches this constructor without passing through EnableNetlinkExport.
	// Clamp rather than fail, because refusing to start export on a bad value
	// turns a typo into an outage.
	if routeProtocol == 0 {
		routeProtocol = RTPROT_BGP
	} else if err := validateRouteProtocol(routeProtocol); err != nil {
		logger.Warn("Invalid netlink export route protocol, falling back to RTPROT_BGP",
			slog.String("Topic", "netlink"),
			slog.Int("Configured", routeProtocol),
			slog.Int("Using", RTPROT_BGP),
			slog.Any("Error", err))
		routeProtocol = RTPROT_BGP
	}

	if dampeningInterval == 0 {
		dampeningInterval = defaultDampeningInterval
	}

	client := &netlinkExportClient{
		client:            handle,
		server:            server,
		logger:            logger,
		rules:             make([]*exportRule, 0),
		exported:          make(map[string]map[string][]*exportedRouteInfo),
		rdToVrf:           make(map[string]string),
		vrfRules:          make(map[string]*vrfExportConfig),
		pendingUpdates:    make(map[string]*dampenEntry),
		routeProtocol:     routeProtocol,
		dampeningInterval: dampeningInterval,
		stopCh:            make(chan struct{}),
	}

	// NOTE: cleanupStaleRoutes is deliberately NOT called here. It issues
	// host-wide RouteDel sweeps, which made merely constructing this client
	// destructive, including from unit tests. StartNetlink calls it explicitly
	// after construction instead.
	return client, nil
}

// sweepTables returns the routing tables the stale-route sweep is allowed to
// touch: exactly those named by a configured export rule, global or per-VRF.
//
// Previously the sweep enumerated the main table plus every VRF table present on
// the host, whether or not this daemon had any reason to write to it. That
// deleted other daemons' routes in tables it never exports to, while at the same
// time missing rules that name a plain table-id with no VRF device.
func (e *netlinkExportClient) sweepTables() []int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tables := make(map[int]struct{}, len(e.rules)+len(e.vrfRules))
	for _, rule := range e.rules {
		tables[rule.TableId] = struct{}{}
	}
	for _, vrf := range e.vrfRules {
		tables[vrf.LinuxTableId] = struct{}{}
	}

	out := make([]int, 0, len(tables))
	for id := range tables {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// listRoutesForSweep lists a single table, retrying once if the kernel reports a
// truncated dump.
//
// ErrDumpInterrupted means the routing table changed mid-dump, which is routine
// on a busy node. The results are partial, so acting on them would under-report
// what is present. Treating it as a plain error would skip the table silently.
func (e *netlinkExportClient) listRoutesForSweep(tableId int) ([]go_netlink.Route, error) {
	list := func() ([]go_netlink.Route, error) {
		if tableId == 0 {
			return e.client.RouteList(nil, go_netlink.FAMILY_ALL)
		}
		return e.client.RouteListFiltered(go_netlink.FAMILY_ALL,
			&go_netlink.Route{Table: tableId}, go_netlink.RT_FILTER_TABLE)
	}

	routes, err := list()
	if err != nil && errors.Is(err, go_netlink.ErrDumpInterrupted) {
		e.logger.Debug("Route dump interrupted, retrying",
			slog.String("Topic", "netlink"),
			slog.Int("Table", tableId))
		routes, err = list()
	}
	return routes, err
}

// cleanupStaleRoutesOnce runs the stale-route sweep at most once per client.
//
// StartNetlink is called on every enable and every config change, but the sweep
// is only meaningful once: on a later call this daemon's own routes are live and
// tracked in e.exported, and deleting them would leave exportRoute's idempotency
// check refusing to reprogram them.
func (e *netlinkExportClient) cleanupStaleRoutesOnce() error {
	e.mu.Lock()
	if e.sweptStaleRoutes {
		e.mu.Unlock()
		return nil
	}
	e.sweptStaleRoutes = true
	e.mu.Unlock()

	return e.cleanupStaleRoutes()
}

// cleanupStaleRoutes removes routes with our protocol left behind by a previous
// run, restricted to the tables this daemon is configured to export into.
//
// Caveat worth knowing: protocol 186 (RTPROT_BGP) is the correct standard value
// and is therefore shared with FRR and other BGP daemons. Within a table that
// this daemon exports to, a route with our protocol is assumed to be ours. If
// another BGP daemon writes to the same table, give this one a dedicated
// table-id or a distinct route-protocol.
func (e *netlinkExportClient) cleanupStaleRoutes() error {
	tables := e.sweepTables()
	if len(tables) == 0 {
		e.logger.Info("No export rules configured, skipping stale route cleanup",
			slog.String("Topic", "netlink"))
		return nil
	}

	e.logger.Info("Cleaning up stale netlink routes from previous runs",
		slog.String("Topic", "netlink"),
		slog.Int("Protocol", e.routeProtocol),
		slog.Any("Tables", tables))

	deleted, skipped := 0, 0

	for _, tableId := range tables {
		routes, err := e.listRoutesForSweep(tableId)
		if err != nil {
			e.logger.Warn("Failed to list routes from table, leaving it untouched",
				slog.String("Topic", "netlink"),
				slog.Int("Table", tableId),
				slog.Any("Error", err))
			continue
		}

		for _, route := range routes {
			if route.Protocol != go_netlink.RouteProtocol(e.routeProtocol) {
				skipped++
				continue
			}
			// A nil Dst is the default route. We never export one, and deleting
			// the node's default route would isolate it.
			if route.Dst == nil {
				e.logger.Info("Skipping default route during cleanup",
					slog.String("Topic", "netlink"),
					slog.Int("Table", route.Table))
				skipped++
				continue
			}

			e.logger.Debug("Deleting stale route",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", route.Dst.String()),
				slog.Int("Table", route.Table),
				slog.Int("Protocol", int(route.Protocol)),
				slog.Int("Metric", route.Priority))

			if err := e.client.RouteDel(&route); err != nil {
				e.logger.Warn("Failed to delete stale route",
					slog.String("Topic", "netlink"),
					slog.String("Prefix", route.Dst.String()),
					slog.Int("Table", route.Table),
					slog.Any("Error", err))
				continue
			}
			deleted++
		}
	}

	e.statsMu.Lock()
	e.stats.CleanupDeleted += uint64(deleted)
	e.stats.CleanupSkipped += uint64(skipped)
	e.statsMu.Unlock()

	// Info, not Debug: an operator upgrading to the narrowed sweep needs to be
	// able to tell a working sweep from a no-op one.
	e.logger.Info("Stale route cleanup complete",
		slog.String("Topic", "netlink"),
		slog.Int("Protocol", e.routeProtocol),
		slog.Any("Tables", tables),
		slog.Int("Deleted", deleted),
		slog.Int("Skipped", skipped))

	return nil
}

// trackExportedLocked records a route this daemon installed. Caller holds e.mu.
//
// One entry per (vrf, prefix, rule): re-exporting through the same rule replaces
// its entry, a different rule adds one.
func (e *netlinkExportClient) trackExportedLocked(vrfName, prefix string, info *exportedRouteInfo) {
	if e.exported[vrfName] == nil {
		e.exported[vrfName] = make(map[string][]*exportedRouteInfo)
	}
	entries := e.exported[vrfName][prefix]
	for i, existing := range entries {
		if existing.RuleName == info.RuleName {
			entries[i] = info
			return
		}
	}
	e.exported[vrfName][prefix] = append(entries, info)
}

// findExportedLocked returns this rule's tracked entry, if any. Caller holds e.mu.
func (e *netlinkExportClient) findExportedLocked(vrfName, prefix, ruleName string) *exportedRouteInfo {
	for _, info := range e.exported[vrfName][prefix] {
		if info.RuleName == ruleName {
			return info
		}
	}
	return nil
}

// untrackExportedLocked drops one rule's entry, pruning empty levels so the
// tracking map does not accumulate empty maps. Caller holds e.mu.
func (e *netlinkExportClient) untrackExportedLocked(vrfName, prefix, ruleName string) {
	entries := e.exported[vrfName][prefix]
	kept := entries[:0]
	for _, info := range entries {
		if info.RuleName != ruleName {
			kept = append(kept, info)
		}
	}
	if len(kept) == 0 {
		delete(e.exported[vrfName], prefix)
		if len(e.exported[vrfName]) == 0 {
			delete(e.exported, vrfName)
		}
		return
	}
	e.exported[vrfName][prefix] = kept
}

// setRules replaces all rules with a new set (for dynamic reconfiguration)
func (e *netlinkExportClient) setRules(rules []*exportRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// buildVrfMappings builds RD-to-VRF mapping and VRF export rules from server config
func (e *netlinkExportClient) buildVrfMappings() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear existing mappings
	e.rdToVrf = make(map[string]string)
	e.vrfRules = make(map[string]*vrfExportConfig)

	// Build mappings from server VRF configuration
	for _, vrf := range e.server.bgpConfig.Vrfs {
		// Map RD to VRF name
		if vrf.Config.Rd != "" {
			e.rdToVrf[vrf.Config.Rd] = vrf.Config.Name
		}

		// Check if this VRF has netlink-export enabled
		if !vrf.NetlinkExport.Enabled {
			continue
		}

		// Build VRF export config
		vrfExport := &vrfExportConfig{
			VrfName:      vrf.Config.Name,
			LinuxVrf:     vrf.NetlinkExport.LinuxVrf,
			LinuxTableId: vrf.NetlinkExport.LinuxTableId,
			Metric:       vrf.NetlinkExport.Metric,
		}

		// Default LinuxVrf to GoBGP VRF name if not specified
		if vrfExport.LinuxVrf == "" {
			vrfExport.LinuxVrf = vrf.Config.Name
		}

		// Set ValidateNexthop (default: true)
		if vrf.NetlinkExport.ValidateNexthop != nil {
			vrfExport.ValidateNexthop = *vrf.NetlinkExport.ValidateNexthop
		} else {
			vrfExport.ValidateNexthop = true
		}

		// Parse communities.
		//
		// A community filter that fails to parse must not silently widen the
		// filter. matchesVrfExportFilters treats an empty list as "match
		// everything", so skipping bad entries turned "export routes carrying
		// this community" into "install every route this peer advertises into
		// the node's FIB" - the filter is the only thing standing between a BGP
		// peer and the kernel routing table. Refuse the VRF instead.
		badFilter := false
		vrfExport.CommunityList = make([]uint32, 0, len(vrf.NetlinkExport.CommunityList))
		for _, commStr := range vrf.NetlinkExport.CommunityList {
			comm, err := table.ParseCommunity(commStr)
			if err != nil {
				e.logger.Error("Invalid community in VRF export config, disabling export for this VRF",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrf.Config.Name),
					slog.String("Community", commStr),
					slog.Any("Error", err))
				badFilter = true
				continue
			}
			vrfExport.CommunityList = append(vrfExport.CommunityList, comm)
		}

		// Parse large communities
		vrfExport.LargeCommunityList = make([]*bgp.LargeCommunity, 0, len(vrf.NetlinkExport.LargeCommunityList))
		for _, lcommStr := range vrf.NetlinkExport.LargeCommunityList {
			lcomm, err := bgp.ParseLargeCommunity(lcommStr)
			if err != nil {
				e.logger.Error("Invalid large community in VRF export config, disabling export for this VRF",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrf.Config.Name),
					slog.String("LargeCommunity", lcommStr),
					slog.Any("Error", err))
				badFilter = true
				continue
			}
			vrfExport.LargeCommunityList = append(vrfExport.LargeCommunityList, lcomm)
		}

		if badFilter {
			// Fail closed: leave this VRF out of vrfRules entirely, and reclaim
			// anything already installed for it. buildVrfMappings rebuilds
			// vrfRules from scratch but does not touch e.exported, so without the
			// reclaim the routes would stay in the kernel and untracked.
			if err := e.flushVrfLocked(vrf.Config.Name); err != nil {
				e.logger.Warn("Failed to reclaim routes for VRF with invalid filter",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrf.Config.Name),
					slog.Any("Error", err))
			}
			continue
		}

		// Lookup Linux table ID if not specified
		if vrfExport.LinuxTableId == 0 {
			tableId, err := e.lookupLinuxVrfTableId(vrfExport.LinuxVrf)
			if err != nil {
				e.logger.Warn("Failed to lookup Linux VRF table ID, will use main table",
					slog.String("Topic", "netlink"),
					slog.String("VRF", vrf.Config.Name),
					slog.String("LinuxVRF", vrfExport.LinuxVrf),
					slog.Any("Error", err))
			} else {
				vrfExport.LinuxTableId = tableId
			}
		}

		e.vrfRules[vrf.Config.Name] = vrfExport

		e.logger.Info("Configured VRF export",
			slog.String("Topic", "netlink"),
			slog.String("VRF", vrf.Config.Name),
			slog.String("LinuxVRF", vrfExport.LinuxVrf),
			slog.Int("LinuxTable", vrfExport.LinuxTableId),
			slog.Any("Metric", vrfExport.Metric),
			slog.Bool("ValidateNexthop", vrfExport.ValidateNexthop))
	}

	return nil
}

// lookupLinuxVrfTableId looks up the Linux routing table ID for a VRF name
func (e *netlinkExportClient) lookupLinuxVrfTableId(vrfName string) (int, error) {
	// Get all links
	links, err := e.client.LinkList()
	if err != nil {
		return 0, fmt.Errorf("failed to list links: %w", err)
	}

	// Find the VRF link
	for _, link := range links {
		if link.Type() == "vrf" && link.Attrs().Name == vrfName {
			// VRF found - get its table ID
			// The table ID is stored in the link's Attrs
			if vrfLink, ok := link.(*go_netlink.Vrf); ok {
				return int(vrfLink.Table), nil
			}
		}
	}

	return 0, fmt.Errorf("VRF %s not found in Linux", vrfName)
}

// reEvaluateAllRoutes re-evaluates all routes in the RIB against new rules
// This should be called after rules are updated to ensure existing routes
// are exported/withdrawn according to the new rules
func (e *netlinkExportClient) reEvaluateAllRoutes(pathList []*table.Path) {
	e.logger.Info("Re-evaluating all routes with new export rules",
		slog.String("Topic", "netlink"),
		slog.Int("PathCount", len(pathList)))

	// exportKey identifies one installed route: which tracking bucket, which
	// prefix, which rule. It must be built the same way here as on the export
	// path, or the comparison below withdraws everything.
	type exportKey struct {
		vrf    string
		prefix string
		rule   string
	}
	shouldExport := make(map[exportKey]bool)

	for _, path := range pathList {
		if path.IsWithdraw {
			continue
		}

		prefix, err := exportPrefixKey(path)
		if err != nil {
			e.logger.Warn("Skipping path with unusable prefix during re-evaluation",
				slog.String("Topic", "netlink"),
				slog.Any("Error", err))
			continue
		}

		// Dispatch exactly as processUpdate does. Re-evaluation used to apply
		// the global rule set to every path regardless of family, which was wrong
		// in both directions: VRF routes were exported through a separate
		// per-VRF path and so could never appear in shouldExport (in a VRF-only
		// deployment e.rules is empty, so every tracked route was withdrawn),
		// while VPN paths were simultaneously matched against unicast rules and
		// dumped into those rules' tables. Steady state and re-evaluation
		// disagreed.
		for _, applied := range e.exportPathToRules(path) {
			shouldExport[exportKey{vrf: applied.VrfName, prefix: prefix, rule: applied.Name}] = true
		}
	}

	// Now withdraw routes that are currently exported but no longer match any rule
	routesToWithdraw := make([]struct {
		vrf    string
		prefix string
		rule   string
		route  *go_netlink.Route
	}, 0)

	e.mu.RLock()
	for vrfName, vrfRoutes := range e.exported {
		for prefix, entries := range vrfRoutes {
			for _, info := range entries {
				if shouldExport[exportKey{vrf: vrfName, prefix: prefix, rule: info.RuleName}] {
					continue
				}
				routesToWithdraw = append(routesToWithdraw, struct {
					vrf    string
					prefix string
					rule   string
					route  *go_netlink.Route
				}{vrfName, prefix, info.RuleName, info.Route})
			}
		}
	}
	e.mu.RUnlock()

	// Withdraw routes outside the lock
	for _, w := range routesToWithdraw {
		e.logger.Info("Withdrawing route that no longer matches any rule",
			slog.String("Topic", "netlink"),
			slog.String("Prefix", w.prefix),
			slog.String("VRF", w.vrf))

		// Delete the route directly
		err := e.client.RouteDel(w.route)
		if err != nil {
			e.statsMu.Lock()
			e.stats.Errors++
			e.stats.LastError = time.Now()
			e.stats.LastErrorMsg = fmt.Sprintf("RouteDel failed for %s: %v", w.prefix, err)
			e.statsMu.Unlock()
			e.logger.Warn("Failed to withdraw route",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", w.prefix),
				slog.String("VRF", w.vrf),
				slog.Any("Error", err))
		} else {
			// Remove from tracking
			e.mu.Lock()
			delete(e.exported[w.vrf], w.prefix)
			if len(e.exported[w.vrf]) == 0 {
				delete(e.exported, w.vrf)
			}
			e.mu.Unlock()

			e.statsMu.Lock()
			e.stats.Withdrawn++
			e.stats.LastWithdraw = time.Now()
			e.statsMu.Unlock()
		}
	}

	e.logger.Info("Route re-evaluation complete",
		slog.String("Topic", "netlink"))
}

// vrfExportRule resolves the export rule a VPN path should be programmed with,
// or nil if this daemon does not export that VRF or the path fails its filters.
func (e *netlinkExportClient) vrfExportRule(path *table.Path) *exportRule {
	vpnNlri, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix)
	if !ok {
		return nil
	}

	e.mu.RLock()
	vrfName, known := e.rdToVrf[vpnNlri.RD.String()]
	var vrfExport *vrfExportConfig
	if known {
		vrfExport = e.vrfRules[vrfName]
	}
	e.mu.RUnlock()

	if vrfExport == nil {
		return nil
	}
	if !e.matchesVrfExportFilters(path, vrfExport) {
		return nil
	}

	return &exportRule{
		Name:            vrfName + "-vrf-export",
		VrfName:         vrfExport.LinuxVrf,
		TableId:         vrfExport.LinuxTableId,
		Metric:          vrfExport.Metric,
		ValidateNexthop: vrfExport.ValidateNexthop,
	}
}

// exportPathToRules programs a path into the kernel through every rule that
// matches it, and returns those rules.
//
// This is the single dispatch point for export. Steady-state updates and
// re-evaluation both go through it, so they cannot disagree about which rules
// apply to a path - which they did: VPN paths went only to the per-VRF path on
// one route and only to the global rules on the other.
//
// A rule whose export attempt fails is still returned. The caller uses the
// result to decide what to keep, and a transient failure to re-program a route
// must not be read as "this rule no longer wants it" and turned into a
// withdrawal.
func (e *netlinkExportClient) exportPathToRules(path *table.Path) []*exportRule {
	var applied []*exportRule

	export := func(rule *exportRule) {
		applied = append(applied, rule)
		if err := e.exportRoute(path, rule); err != nil {
			e.logger.Warn("Failed to export route",
				slog.String("Topic", "netlink"),
				slog.String("Rule", rule.Name),
				slog.String("VRF", rule.VrfName),
				slog.Any("Error", err))
		}
	}

	switch path.GetFamily() {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		// VPN paths are exported only through their VRF's configuration.
		if rule := e.vrfExportRule(path); rule != nil {
			export(rule)
		}
	default:
		e.mu.RLock()
		rules := slices.Clone(e.rules)
		e.mu.RUnlock()
		for _, rule := range rules {
			if e.matchesRule(path, rule) {
				export(rule)
			}
		}
	}

	return applied
}

// matchesRule checks if a path matches an export rule's community filters
func (e *netlinkExportClient) matchesRule(path *table.Path, rule *exportRule) bool {
	// If no community filters specified, match all routes
	if len(rule.Communities) == 0 && len(rule.LargeCommunities) == 0 {
		return true
	}

	// Get communities from path
	communities := path.GetCommunities()
	largeCommunities := path.GetLargeCommunities()

	// Check standard communities (OR logic - match if path has ANY community from the list)
	if len(rule.Communities) > 0 {
		pathCommSet := make(map[uint32]bool)
		for _, comm := range communities {
			pathCommSet[comm] = true
		}

		// If path has ANY of the rule communities, it matches
		for _, ruleComm := range rule.Communities {
			if pathCommSet[ruleComm] {
				return true
			}
		}
	}

	// Check large communities (OR logic - match if path has ANY large community from the list)
	if len(rule.LargeCommunities) > 0 {
		pathLargeCommSet := make(map[string]bool)
		for _, lc := range largeCommunities {
			key := fmt.Sprintf("%d:%d:%d", lc.ASN, lc.LocalData1, lc.LocalData2)
			pathLargeCommSet[key] = true
		}

		// If path has ANY of the rule large communities, it matches
		for _, ruleLc := range rule.LargeCommunities {
			key := fmt.Sprintf("%d:%d:%d", ruleLc.ASN, ruleLc.LocalData1, ruleLc.LocalData2)
			if pathLargeCommSet[key] {
				return true
			}
		}
	}

	// No match found
	return false
}

// isLinkLocal reports whether an address is IPv6 link-local (fe80::/10).
//
// These need special handling throughout: they are per-link, so they cannot be
// resolved or installed without an interface to scope them to.
func isLinkLocal(ip net.IP) bool {
	return ip.To4() == nil && ip.IsLinkLocalUnicast()
}

// outgoingInterface returns the device a route should be installed on, or ""
// to let the kernel decide.
//
// A link-local nexthop must have one: it is only meaningful on the link it was
// learned from. That link is the BGP session's interface, recorded on the peer's
// PeerInfo when the session comes up, or the scan interface for a
// netlink-imported path.
//
// For a VRF-scoped rule the device is the VRF itself, which is what places the
// route in that VRF's table.
func (e *netlinkExportClient) outgoingInterface(path *table.Path, rule *exportRule, nexthop net.IP) string {
	if isLinkLocal(nexthop) {
		if src := path.GetSource(); src != nil {
			if iface := src.GetNeighborInterface(); iface != "" {
				return iface
			}
		}
		// Fall through: a VRF device is better than nothing, though it will not
		// usually be the right link for a link-local nexthop.
	}
	return rule.VrfName
}

// isNexthopReachable checks whether a nexthop is reachable in the table the rule
// exports into.
//
// The lookup has to be scoped to that table. It used to call plain RouteGet,
// which the kernel resolves in the main table, and then require the answer to
// come from the rule's table - a condition that can never hold for a non-main
// table, so every rule targeting a VRF silently exported nothing while
// validation was on, which is the default.
func (e *netlinkExportClient) isNexthopReachable(nh net.IP, rule *exportRule) bool {
	e.statsMu.Lock()
	e.stats.NexthopValidation++
	e.statsMu.Unlock()

	failed := func() bool {
		e.statsMu.Lock()
		e.stats.NexthopFailed++
		e.statsMu.Unlock()
		return false
	}

	var opts *go_netlink.RouteGetOptions
	switch {
	case rule.VrfName != "":
		// Equivalent to "ip route get <nh> vrf <name>": the kernel's l3mdev
		// redirect sends the lookup into that VRF's table.
		opts = &go_netlink.RouteGetOptions{VrfName: rule.VrfName}
	case isLinkLocal(nh):
		// A link-local nexthop is ambiguous without a link. Nothing to scope it
		// to here, so leave it to the caller's interface handling rather than
		// failing a route that is perfectly valid.
		return true
	}

	routes, err := e.client.RouteGetWithOptions(nh, opts)
	if err != nil || len(routes) == 0 {
		return failed()
	}

	// If we're exporting to a specific table, verify the nexthop route is in that table
	if tableId := rule.TableId; tableId > 0 {
		for _, route := range routes {
			// A provisioned VRF table carries an "unreachable default", which
			// satisfies the table check while meaning the opposite of reachable.
			if route.Table == tableId && route.Type == unix.RTN_UNICAST {
				return true
			}
		}
		// Nexthop not in target table
		return failed()
	}

	return true
}

// exportRoute exports a BGP path to the Linux routing table according to a rule
func (e *netlinkExportClient) exportRoute(path *table.Path, rule *exportRule) error {
	// Get prefix - handle both regular and VPN families
	nlri := path.GetNlri()
	var prefix string
	family := path.GetFamily()

	if family == bgp.RF_IPv4_VPN || family == bgp.RF_IPv6_VPN {
		// VPN family - extract plain prefix without RD
		if vpnNlri, ok := nlri.(*bgp.LabeledVPNIPAddrPrefix); ok {
			prefix = vpnNlri.IPPrefix()
			e.logger.Debug("Processing VPN family path",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.String("RD", vpnNlri.RD.String()),
				slog.String("Family", family.String()))
		} else {
			return fmt.Errorf("unexpected VPN NLRI type for family %s", family.String())
		}
	} else {
		// Regular unicast family
		prefix = nlri.String()
	}

	// Get nexthop - always require a valid nexthop
	nexthop := path.GetNexthop()
	if nexthop.IsUnspecified() {
		return fmt.Errorf("no valid nexthop for %s", prefix)
	}

	// Convert nexthop to net.IP
	nexthopIP := net.IP(nexthop.AsSlice())

	// Validate nexthop if enabled (default: true)
	if rule.ValidateNexthop {
		if !e.isNexthopReachable(nexthopIP, rule) {
			e.logger.Debug("Nexthop validation failed",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.String("Nexthop", nexthop.String()),
				slog.String("Rule", rule.Name),
				slog.String("VRF", rule.VrfName))
			return fmt.Errorf("nexthop %s not reachable", nexthop.String())
		}
	}

	// Check whether this rule already installed this prefix (idempotency).
	//
	// The lookup is per rule, not per prefix: another rule may have its own
	// kernel route for the same prefix in a different table, and that one is not
	// ours to reason about here.
	e.mu.RLock()
	existingInfo := e.findExportedLocked(rule.VrfName, prefix, rule.Name)
	e.mu.RUnlock()

	if existingInfo != nil {
		existingRoute := existingInfo.Route
		if existingRoute.Table == rule.TableId &&
			existingRoute.Priority == int(rule.Metric) &&
			existingRoute.Gw.Equal(nexthopIP) {
			// Already installed with identical parameters.
			return nil
		}

		// Parameters changed. The kernel identifies a route by table and metric,
		// so the old one is a distinct entry and RouteReplace would leave it
		// behind; delete it explicitly.
		e.logger.Info("Route parameters changed, deleting old route before re-export",
			slog.String("Topic", "netlink"),
			slog.String("Prefix", prefix),
			slog.String("Rule", rule.Name),
			slog.Int("OldMetric", existingRoute.Priority),
			slog.Any("NewMetric", rule.Metric),
			slog.Int("OldTable", existingRoute.Table),
			slog.Int("NewTable", rule.TableId))

		if err := e.client.RouteDel(existingRoute); err != nil && !isRouteAbsent(err) {
			e.logger.Warn("Failed to delete old route during parameter change",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.Any("Error", err))
		}

		e.mu.Lock()
		e.untrackExportedLocked(rule.VrfName, prefix, rule.Name)
		e.mu.Unlock()
	}

	// Create netlink route
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR %s: %w", prefix, err)
	}

	route := &go_netlink.Route{
		Dst:      ipNet,
		Gw:       nexthopIP,
		Table:    rule.TableId,
		Priority: int(rule.Metric),
		Protocol: go_netlink.RouteProtocol(e.routeProtocol),
	}

	// Resolve the output interface.
	//
	// This is independent of ONLINK, and it used to be conflated with it: the
	// device was looked up only when validation was disabled. A route whose
	// nexthop is an IPv6 link-local address needs an output interface in every
	// case, because the kernel rejects a link-local gateway carrying RTA_OIF=0
	// with EINVAL. That is exactly the unnumbered-peer case this fork exists to
	// support, so with validation on - the default - those routes could not be
	// installed at all.
	if linkName := e.outgoingInterface(path, rule, nexthopIP); linkName != "" {
		link, err := e.client.LinkByName(linkName)
		if err != nil {
			e.logger.Warn("Failed to look up outgoing interface for route",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.String("Interface", linkName),
				slog.Any("Error", err))
			if isLinkLocal(nexthopIP) {
				// Without a device the kernel will refuse this outright; say so
				// rather than letting RouteReplace fail with a bare EINVAL.
				return fmt.Errorf("link-local nexthop %s needs an output interface, %q not found",
					nexthop.String(), linkName)
			}
		} else {
			route.LinkIndex = link.Attrs().Index
			e.logger.Debug("Set outgoing interface for route",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.String("Interface", linkName),
				slog.Int("LinkIndex", route.LinkIndex))
		}
	} else if isLinkLocal(nexthopIP) {
		return fmt.Errorf("link-local nexthop %s has no known output interface", nexthop.String())
	}

	// ONLINK tells the kernel to accept a nexthop that is not covered by an
	// on-link prefix. It is a separate decision from whether we validated
	// reachability ourselves, and pairing the two meant that turning validation
	// back on silently dropped the flag and changed forwarding behaviour.
	if !rule.ValidateNexthop {
		route.Flags = int(go_netlink.FLAG_ONLINK)
		e.logger.Debug("Setting ONLINK flag for route with unvalidated nexthop",
			slog.String("Topic", "netlink"),
			slog.String("Prefix", prefix),
			slog.String("Nexthop", nexthop.String()))
	}

	// Add the route
	err = e.client.RouteReplace(route)
	if err != nil {
		e.statsMu.Lock()
		e.stats.Errors++
		e.stats.LastError = time.Now()
		e.stats.LastErrorMsg = fmt.Sprintf("RouteReplace failed for %s: %v", prefix, err)
		e.statsMu.Unlock()

		e.logger.Warn("Failed to export route",
			slog.String("Topic", "netlink"),
			slog.String("Prefix", prefix),
			slog.String("Nexthop", nexthop.String()),
			slog.String("Rule", rule.Name),
			slog.String("VRF", rule.VrfName),
			slog.Any("Error", err))
		return fmt.Errorf("failed to add route %s: %w", prefix, err)
	}

	// Track exported route
	e.mu.Lock()
	e.trackExportedLocked(rule.VrfName, prefix, &exportedRouteInfo{
		Route:      route,
		RuleName:   rule.Name,
		ExportedAt: time.Now(),
	})
	e.mu.Unlock()

	e.statsMu.Lock()
	e.stats.Exported++
	e.stats.LastExport = time.Now()
	e.statsMu.Unlock()

	e.logger.Info("Exported route to Linux",
		slog.String("Topic", "netlink"),
		slog.String("Prefix", prefix),
		slog.String("Nexthop", nexthop.String()),
		slog.String("Rule", rule.Name),
		slog.String("VRF", rule.VrfName),
		slog.Int("Table", rule.TableId),
		slog.Any("Metric", rule.Metric))

	return nil
}

// withdrawRoute removes a BGP path from the Linux routing table
func (e *netlinkExportClient) withdrawRoute(path *table.Path, vrfName string) error {
	// Get prefix - handle VPN families
	nlri := path.GetNlri()
	family := path.GetFamily()
	var prefix string

	// For VPN families, extract just the IP prefix without RD
	if family == bgp.RF_IPv4_VPN || family == bgp.RF_IPv6_VPN {
		if vpnNlri, ok := nlri.(*bgp.LabeledVPNIPAddrPrefix); ok {
			prefix = vpnNlri.IPPrefix()
		} else {
			prefix = nlri.String()
		}
	} else {
		prefix = nlri.String()
	}

	// Every rule that installed this prefix has its own kernel route, so a
	// withdrawal has to remove all of them, not just the first.
	e.mu.RLock()
	tracked := slices.Clone(e.exported[vrfName][prefix])
	e.mu.RUnlock()

	if len(tracked) == 0 {
		return nil // Not exported, nothing to do
	}

	var errs []error
	for _, info := range tracked {
		// ESRCH/ENOENT mean the route is already gone from the kernel, which is
		// the state we are trying to reach. Treating it as fatal would skip the
		// tracking removal below, and the stale entry would then make
		// exportRoute's idempotency check refuse to ever reinstall the prefix.
		// Reconcile our own bookkeeping instead.
		err := e.client.RouteDel(info.Route)
		if err != nil && isRouteAbsent(err) {
			e.logger.Info("Route already absent from kernel, clearing tracking",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.String("VRF", vrfName),
				slog.String("Rule", info.RuleName),
				slog.Any("Error", err))
			err = nil
		}
		if err != nil {
			e.statsMu.Lock()
			e.stats.Errors++
			e.stats.LastError = time.Now()
			e.stats.LastErrorMsg = fmt.Sprintf("RouteDel failed for %s: %v", prefix, err)
			e.statsMu.Unlock()

			e.logger.Warn("Failed to withdraw route",
				slog.String("Topic", "netlink"),
				slog.String("Prefix", prefix),
				slog.String("VRF", vrfName),
				slog.String("Rule", info.RuleName),
				slog.Any("Error", err))
			errs = append(errs, err)
			continue
		}

		e.mu.Lock()
		e.untrackExportedLocked(vrfName, prefix, info.RuleName)
		e.mu.Unlock()
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to delete route %s: %w", prefix, errors.Join(errs...))
	}

	e.statsMu.Lock()
	e.stats.Withdrawn++
	e.stats.LastWithdraw = time.Now()
	e.statsMu.Unlock()

	e.logger.Info("Withdrew route from Linux",
		slog.String("Topic", "netlink"),
		slog.String("Prefix", prefix),
		slog.String("VRF", vrfName))

	return nil
}

// processDampenedUpdate processes a route update after dampening delay
func (e *netlinkExportClient) processDampenedUpdate(path *table.Path) {
	nlri := path.GetNlri()
	prefix := nlri.String()

	e.dampenMu.Lock()
	delete(e.pendingUpdates, prefix)
	e.dampenMu.Unlock()

	// Process the update
	e.processUpdate(path)
}

// scheduleUpdate schedules a route update with dampening
func (e *netlinkExportClient) scheduleUpdate(path *table.Path) {
	if e.dampeningInterval == 0 {
		// No dampening, process immediately
		e.processUpdate(path)
		return
	}

	nlri := path.GetNlri()
	prefix := nlri.String()

	e.dampenMu.Lock()
	defer e.dampenMu.Unlock()

	// Check if there's already a pending update
	if entry, exists := e.pendingUpdates[prefix]; exists {
		// Cancel existing timer and create new one
		entry.timer.Stop()
		entry.path = path
		entry.updatedAt = time.Now()
		entry.timer = time.AfterFunc(e.dampeningInterval, func() {
			e.processDampenedUpdate(path)
		})
		e.statsMu.Lock()
		e.stats.DampenedUpdates++
		e.statsMu.Unlock()
	} else {
		// Create new dampening entry
		timer := time.AfterFunc(e.dampeningInterval, func() {
			e.processDampenedUpdate(path)
		})
		e.pendingUpdates[prefix] = &dampenEntry{
			path:      path,
			timer:     timer,
			updatedAt: time.Now(),
		}
	}
}

// withdrawTargets returns the tracking buckets a path is entitled to withdraw
// from.
//
// Withdrawal used to scan every bucket for the prefix and delete from all of
// them, with no check that the withdrawing path had anything to do with the
// route it was removing. Because the RD is stripped before that scan, a peer
// advertising and then withdrawing an unmapped RD for prefix P would delete
// P from a completely different VRF; and a peer withdrawing a prefix it never
// advertised still reached this code, because TableManager.Update returns a
// destination either way.
//
// A path may only withdraw from where it could have installed: a VPN path from
// its own RD's VRF, a unicast path from the buckets its rules target.
func (e *netlinkExportClient) withdrawTargets(path *table.Path) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	switch path.GetFamily() {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		vpnNlri, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix)
		if !ok {
			return nil
		}
		vrfName, known := e.rdToVrf[vpnNlri.RD.String()]
		if !known {
			// An RD we do not map is not ours to withdraw.
			return nil
		}
		vrfExport, enabled := e.vrfRules[vrfName]
		if !enabled {
			return nil
		}
		return []string{vrfExport.LinuxVrf}

	default:
		seen := make(map[string]struct{}, len(e.rules))
		targets := make([]string, 0, len(e.rules))
		for _, rule := range e.rules {
			if _, dup := seen[rule.VrfName]; dup {
				continue
			}
			seen[rule.VrfName] = struct{}{}
			targets = append(targets, rule.VrfName)
		}
		return targets
	}
}

// processUpdate processes a route update (export or withdrawal)
func (e *netlinkExportClient) processUpdate(path *table.Path) {
	family := path.GetFamily()
	nlri := path.GetNlri()

	e.logger.Debug("processUpdate called",
		slog.String("Topic", "netlink"),
		slog.String("Family", family.String()),
		slog.String("NLRI", nlri.String()),
		slog.Bool("IsWithdraw", path.IsWithdraw))

	if path.IsWithdraw {
		prefix, err := exportPrefixKey(path)
		if err != nil {
			e.logger.Warn("Skipping withdrawal with unusable prefix",
				slog.String("Topic", "netlink"),
				slog.Any("Error", err))
			return
		}

		vrfsToWithdraw := e.withdrawTargets(path)

		e.logger.Debug("Processing withdrawal",
			slog.String("Topic", "netlink"),
			slog.String("Prefix", prefix),
			slog.String("Family", family.String()),
			slog.Any("VRFs", vrfsToWithdraw))

		for _, vrfName := range vrfsToWithdraw {
			if err := e.withdrawRoute(path, vrfName); err != nil {
				e.logger.Warn("Failed to withdraw route",
					slog.String("Topic", "netlink"),
					slog.String("Prefix", prefix),
					slog.String("VRF", vrfName),
					slog.Any("Error", err))
			}
		}
		return
	}

	// Steady-state export goes through the same dispatch as re-evaluation, so
	// the two cannot disagree about which rules apply to a path.
	applied := e.exportPathToRules(path)
	e.logger.Debug("Processed path for export",
		slog.String("Topic", "netlink"),
		slog.String("Family", family.String()),
		slog.String("NLRI", nlri.String()),
		slog.Int("RulesApplied", len(applied)))
}

// matchesVrfExportFilters checks if a path matches VRF export community filters
func (e *netlinkExportClient) matchesVrfExportFilters(path *table.Path, vrfExport *vrfExportConfig) bool {
	// If no community filters specified, match all routes
	if len(vrfExport.CommunityList) == 0 && len(vrfExport.LargeCommunityList) == 0 {
		return true
	}

	// Get path communities
	pathComms := path.GetCommunities()
	pathCommSet := make(map[uint32]bool)
	for _, comm := range pathComms {
		pathCommSet[comm] = true
	}

	// Check standard communities (OR logic)
	for _, ruleComm := range vrfExport.CommunityList {
		if pathCommSet[ruleComm] {
			return true
		}
	}

	// Get large communities
	pathLargeComms := make(map[string]bool)
	for _, attr := range path.GetPathAttrs() {
		if lcomms, ok := attr.(*bgp.PathAttributeLargeCommunities); ok {
			for _, lc := range lcomms.Values {
				pathLargeComms[lc.String()] = true
			}
		}
	}

	// Check large communities (OR logic)
	for _, ruleLComm := range vrfExport.LargeCommunityList {
		if pathLargeComms[ruleLComm.String()] {
			return true
		}
	}

	return false
}

// getStats returns current export statistics
func (e *netlinkExportClient) getStats() exportStats {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()
	return e.stats
}

// listExported returns all currently exported routes
func (e *netlinkExportClient) listExported() map[string]map[string][]*exportedRouteInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Deep copy to avoid race conditions
	result := make(map[string]map[string][]*exportedRouteInfo)
	for vrfName, vrfRoutes := range e.exported {
		result[vrfName] = make(map[string][]*exportedRouteInfo)
		for prefix, entries := range vrfRoutes {
			copied := make([]*exportedRouteInfo, 0, len(entries))
			for _, info := range entries {
				copied = append(copied, &exportedRouteInfo{
					Route:      info.Route,
					RuleName:   info.RuleName,
					ExportedAt: info.ExportedAt,
				})
			}
			result[vrfName][prefix] = copied
		}
	}
	return result
}

// getRules returns a copy of the current export rules
func (e *netlinkExportClient) getRules() []*exportRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Deep copy to avoid race conditions
	result := make([]*exportRule, len(e.rules))
	for i, rule := range e.rules {
		// Copy the rule
		ruleCopy := &exportRule{
			Name:             rule.Name,
			Communities:      make([]uint32, len(rule.Communities)),
			LargeCommunities: make([]*bgp.LargeCommunity, len(rule.LargeCommunities)),
			VrfName:          rule.VrfName,
			TableId:          rule.TableId,
			Metric:           rule.Metric,
			ValidateNexthop:  rule.ValidateNexthop,
		}
		copy(ruleCopy.Communities, rule.Communities)
		copy(ruleCopy.LargeCommunities, rule.LargeCommunities)
		result[i] = ruleCopy
	}
	return result
}

// getVrfRules returns a copy of the VRF export rules
func (e *netlinkExportClient) getVrfRules() map[string]*vrfExportConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Deep copy to avoid race conditions
	result := make(map[string]*vrfExportConfig, len(e.vrfRules))
	for vrfName, rule := range e.vrfRules {
		ruleCopy := &vrfExportConfig{
			VrfName:            rule.VrfName,
			LinuxVrf:           rule.LinuxVrf,
			LinuxTableId:       rule.LinuxTableId,
			Metric:             rule.Metric,
			ValidateNexthop:    rule.ValidateNexthop,
			CommunityList:      make([]uint32, len(rule.CommunityList)),
			LargeCommunityList: make([]*bgp.LargeCommunity, len(rule.LargeCommunityList)),
		}
		copy(ruleCopy.CommunityList, rule.CommunityList)
		copy(ruleCopy.LargeCommunityList, rule.LargeCommunityList)
		result[vrfName] = ruleCopy
	}
	return result
}

// flush removes all exported routes
func (e *netlinkExportClient) flush() error {
	// A caller can hold a reference taken before DisableNetlinkExport ran, and
	// stop() closes the netlink handle. Check and snapshot in one critical
	// section so the client cannot be stopped between the two.
	e.mu.RLock()
	if e.stopped {
		e.mu.RUnlock()
		return fmt.Errorf("netlink export client is stopped")
	}
	routesToDelete := make([]*go_netlink.Route, 0)
	for _, vrfRoutes := range e.exported {
		for _, entries := range vrfRoutes {
			for _, info := range entries {
				routesToDelete = append(routesToDelete, info.Route)
			}
		}
	}
	e.mu.RUnlock()

	// Delete all routes
	for _, route := range routesToDelete {
		err := e.client.RouteDel(route)
		if err != nil {
			e.logger.Warn("Failed to delete route during flush",
				slog.String("Topic", "netlink"),
				slog.String("Route", route.Dst.String()),
				slog.Any("Error", err))
		}
	}

	// Clear tracking
	e.mu.Lock()
	e.exported = make(map[string]map[string][]*exportedRouteInfo)
	e.mu.Unlock()

	e.logger.Info("Flushed all exported routes",
		slog.String("Topic", "netlink"),
		slog.Int("Count", len(routesToDelete)))

	return nil
}

// stop shuts down the netlink export client
// If flushRoutes is true (keep_routes=false), remove all exported routes from Linux kernel
func (e *netlinkExportClient) stop(flushRoutes bool) error {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return nil // Already stopped
	}
	e.stopped = true
	e.mu.Unlock()

	// Flush routes first while client is still valid
	if flushRoutes {
		_ = e.flush()
	}

	// Signal shutdown
	close(e.stopCh)

	// Cancel pending dampened updates with proper locking
	e.dampenMu.Lock()
	for _, entry := range e.pendingUpdates {
		entry.timer.Stop()
	}
	e.pendingUpdates = make(map[string]*dampenEntry)
	e.dampenMu.Unlock()

	// Close netlink handle
	if e.client != nil {
		e.client.Close()
	}

	return nil
}

// flushVrf removes all exported routes for a specific VRF
func (e *netlinkExportClient) flushVrf(vrfName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flushVrfLocked(vrfName)
}

// flushVrfLocked is flushVrf for callers already holding e.mu, notably
// buildVrfMappings when it rejects a VRF whose community filter will not parse.
func (e *netlinkExportClient) flushVrfLocked(vrfName string) error {
	// vrfName is the GoBGP VRF name, which is what vrfRules is keyed by. The
	// tracking map is keyed by the *Linux* VRF, and the two differ whenever
	// linux-vrf is configured - in which case this used to flush the wrong
	// bucket and leave the real routes installed and untracked.
	trackingKey := vrfName
	if cfg, ok := e.vrfRules[vrfName]; ok && cfg.LinuxVrf != "" {
		trackingKey = cfg.LinuxVrf
	}

	var errs []error
	if vrfRoutes, ok := e.exported[trackingKey]; ok {
		for prefix, entries := range vrfRoutes {
			for _, info := range entries {
				if err := e.client.RouteDel(info.Route); err != nil && !isRouteAbsent(err) {
					errs = append(errs, fmt.Errorf("failed to delete %s: %w", prefix, err))
					e.logger.Warn("Failed to delete route during VRF flush",
						slog.String("Topic", "netlink"),
						slog.String("VRF", vrfName),
						slog.String("LinuxVRF", trackingKey),
						slog.String("Prefix", prefix),
						slog.String("Rule", info.RuleName),
						slog.Any("Error", err))
				}
			}
		}
		delete(e.exported, trackingKey)
	}
	delete(e.vrfRules, vrfName)

	if len(errs) > 0 {
		return fmt.Errorf("errors during flush: %v", errs)
	}
	return nil
}
