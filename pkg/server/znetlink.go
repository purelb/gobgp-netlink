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
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	custom_net "github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/vishvananda/netlink"
)

type netlinkImportStats struct {
	Imported  uint64
	Withdrawn uint64
	Errors    uint64
	Ticks     uint64 // import scan iterations; stops advancing once the loop exits
	// AddrEvents counts kernel address changes that triggered an import. Flat
	// while addresses are being added means the subscription is dead and the
	// daemon has silently fallen back to the 5s poll, which is otherwise
	// indistinguishable from a quiet node.
	AddrEvents   uint64
	LastImport   time.Time
	LastWithdraw time.Time
	LastError    time.Time
	LastErrorMsg string
}

// interfaceScanner reads the connected routes currently configured on an
// interface. The import loop goes through this rather than calling netutils
// directly so tests can supply a synthetic topology; a CI runner has no eth0,
// so without it every import test drives an empty scan and proves nothing.
type interfaceScanner func(iface string) ([]*custom_net.ConnectedRoute, error)

// addrEventSource subscribes to kernel address add/delete events, delivering
// them on ch until done is closed.
//
// Injected for the same reason as interfaceScanner: a CI runner has no
// interfaces to add addresses to, so without a seam here every event test would
// drive a subscription that never fires and prove nothing.
type addrEventSource func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error

// importWork is one VRF's scan target, captured from server config while the
// lock is held so the scan itself can run without it.
type importWork struct {
	vrfName    string
	interfaces []string
}

// importedRoute is the kernel state a path was built from, kept instead of the
// path itself.
//
// Caching the live *table.Path does not work: addPathList runs it through
// fixupApiPath, which calls Vrf.ToGlobalPath and rewrites the NLRI to the VPN
// family in place. The cached object is then already converted, so withdrawing
// it hands ToGlobalPath a VPN-family path it has no case for; it returns
// "unsupported route family for vrf", fixupApiPath propagates that, and
// addPathList drops the entire withdrawal batch. Cloning does not help either -
// Clone shares the root originInfo, so the mutation reaches through it.
//
// Rebuilding from the spec gives every path a fresh info, so each conversion
// starts from the unicast form exactly once.
type importedRoute struct {
	route *custom_net.ConnectedRoute
	iface string
}

type netlinkClient struct {
	server *BgpServer
	dead   chan struct{}
	done   chan struct{} // closed when the scan loop has exited
	// rescanCh asks the loop for an immediate pass. Buffered so rescan() never
	// blocks its caller, which holds shared.mu.
	rescanCh chan struct{}
	// scan reads connected routes for one interface. Always non-nil.
	scan interfaceScanner
	// subscribeAddr delivers kernel address events. Nil means poll only.
	subscribeAddr addrEventSource
	// importIfIndexes is the set of interface indexes the import actually reads
	// from, refreshed by each scan. Address events on anything else are ignored.
	//
	// Holding indexes rather than names keeps the comparison to one map lookup
	// on a path that sees every veth appearing and disappearing on the node.
	importIfIndexes atomic.Pointer[map[int]struct{}]
	// advertisedPaths tracks what has been imported, per VRF
	// (vrf name -> prefix -> the kernel route it came from).
	// The empty string key is used for the global table.
	advertisedPaths map[string]map[string]*importedRoute
	pathsMu         sync.RWMutex // protects advertisedPaths
	stats           netlinkImportStats
	statsMu         sync.RWMutex

	// generation and stopped are guarded by the server's shared.mu, not by
	// pathsMu. They are bumped whenever tracked state is invalidated, so a scan
	// that began before the change can tell it must not publish its results.
	generation uint64
	stopped    bool
}

func newNetlinkClient(s *BgpServer) (*netlinkClient, error) {
	s.logger.Debug("creating new netlink client", slog.String("Topic", "netlink"))
	w := &netlinkClient{
		server:   s,
		dead:     make(chan struct{}),
		done:     make(chan struct{}),
		rescanCh: make(chan struct{}, 1),
		scan: func(iface string) ([]*custom_net.ConnectedRoute, error) {
			return custom_net.GetGlobalUnicastRoutes(iface, s.logger)
		},
		subscribeAddr: func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
			return netlink.AddrSubscribeWithOptions(ch, done, netlink.AddrSubscribeOptions{
				// Without this a dropped multicast message silently ends the
				// subscription; the callback lets the loop notice and resubscribe.
				ReceiveBufferSize: 1 << 20,
			})
		},
		advertisedPaths: make(map[string]map[string]*importedRoute),
	}
	// The first pass happens on the loop goroutine rather than here. This
	// constructor is reached from StartNetlink, which runs under shared.mu, and
	// a scan performs blocking netlink syscalls that must never hold that lock.
	go w.loop()
	return w, nil
}

// collectWorkLocked builds the list of VRFs to scan from server configuration.
//
// Caller MUST hold n.server.shared.mu: this reads bgpConfig.Netlink,
// bgpConfig.Vrfs and globalRib.Vrfs, all of which are mutated on the Serve
// goroutine. Ranging globalRib.Vrfs unlocked races AddVrf and aborts the
// process with "concurrent map iteration and map write".
func (n *netlinkClient) collectWorkLocked() []importWork {
	var work []importWork

	// Global import target.
	if n.server.bgpConfig.Netlink.Import.Enabled {
		work = append(work, importWork{
			vrfName:    n.server.bgpConfig.Netlink.Import.Vrf,
			interfaces: slices.Clone(n.server.bgpConfig.Netlink.Import.InterfaceList),
		})
	}

	// Per-VRF import targets. VRFs created over gRPC land in globalRib.Vrfs but
	// not in bgpConfig.Vrfs, so the name comes from one and the config from the
	// other.
	vrfConfigMap := make(map[string]*oc.Vrf, len(n.server.bgpConfig.Vrfs))
	for i := range n.server.bgpConfig.Vrfs {
		vrf := &n.server.bgpConfig.Vrfs[i]
		vrfConfigMap[vrf.Config.Name] = vrf
	}

	if n.server.globalRib != nil {
		for vrfName := range n.server.globalRib.GetAllVrfsMap() {
			vrfConfig, hasConfig := vrfConfigMap[vrfName]
			if !hasConfig || !vrfConfig.NetlinkImport.Enabled {
				continue
			}
			work = append(work, importWork{
				vrfName:    vrfName,
				interfaces: slices.Clone(vrfConfig.NetlinkImport.InterfaceList),
			})
		}
	}

	// A VRF named by both the global block and its own block would otherwise be
	// scanned twice into one tracking bucket, each pass withdrawing what the
	// other just added. Merge them and scan once.
	return mergeImportWork(work)
}

// mergeImportWork combines entries targeting the same VRF, preserving order.
func mergeImportWork(work []importWork) []importWork {
	if len(work) < 2 {
		return work
	}
	idx := make(map[string]int, len(work))
	out := make([]importWork, 0, len(work))
	for _, w := range work {
		if i, seen := idx[w.vrfName]; seen {
			for _, iface := range w.interfaces {
				if !slices.Contains(out[i].interfaces, iface) {
					out[i].interfaces = append(out[i].interfaces, iface)
				}
			}
			continue
		}
		idx[w.vrfName] = len(out)
		out = append(out, w)
	}
	return out
}

// scanUnlocked reads the kernel state for each work item.
//
// Caller MUST NOT hold n.server.shared.mu. Every netlink syscall in the import
// path happens here: interface enumeration, per-interface address dumps, and
// glob expansion. None of it touches server state. Holding shared.mu across
// these would stall all BGP message processing for the duration of the scan,
// and they have no timeout.
func (n *netlinkClient) scanUnlocked(work []importWork) map[string]map[string]*importedRoute {
	scanned := make(map[string]map[string]*importedRoute, len(work))
	// Interfaces this pass actually read from, so address events can be
	// filtered to them. Collected here because this is where glob patterns are
	// resolved to concrete names.
	covered := make(map[string]struct{})

	for _, w := range work {
		// Resolve glob patterns ("eth*", "vlan*") to concrete interface names.
		// This must happen here rather than inside GetGlobalUnicastRoutes: the
		// concrete name is stored on the path source as NetlinkIfName and
		// surfaces through the API and CLI, so a pattern must never be passed
		// downstream.
		interfaces, err := custom_net.ExpandInterfacePatterns(w.interfaces, n.server.logger)
		if err != nil {
			n.server.logger.Error("failed to expand interface patterns",
				slog.String("Topic", "netlink"),
				slog.String("VRF", w.vrfName),
				slog.Any("Error", err))
			continue
		}

		current := make(map[string]*importedRoute)
		for _, iface := range interfaces {
			covered[iface] = struct{}{}
			routes, err := n.scan(iface)
			if err != nil {
				n.server.logger.Error("failed to get connected routes",
					slog.String("Topic", "netlink"),
					slog.String("VRF", w.vrfName),
					slog.String("Interface", iface),
					slog.Any("Error", err))
				continue
			}
			for _, route := range routes {
				// Build a path only to derive its canonical key; the spec is what
				// is kept, and publishLocked rebuilds paths from it.
				path := n.pathForRoute(route, iface)
				if path == nil {
					continue
				}
				current[path.GetNlri().String()] = &importedRoute{route: route, iface: iface}
			}
		}

		n.server.logger.Debug("VRF import scan complete",
			slog.String("Topic", "netlink"),
			slog.String("VRF", w.vrfName),
			slog.Int("CurrentPaths", len(current)))

		scanned[w.vrfName] = current
	}

	n.refreshImportIfIndexes(covered)
	return scanned
}

// publishLocked diffs one VRF's scan against what is currently advertised and
// pushes the difference into the RIB.
//
// Caller MUST hold n.server.shared.mu. This calls addPathList, which is the
// unlocked RIB primitive; internal/pkg/table has no synchronisation of its own.
func (n *netlinkClient) publishLocked(vrfName string, current map[string]*importedRoute) {
	// Re-read the tracking map here rather than using a copy taken before the
	// scan: withdrawVrfLocked may have emptied it while the scan was running.
	n.pathsMu.Lock()
	previous := n.advertisedPaths[vrfName]
	if previous == nil {
		previous = make(map[string]*importedRoute)
	}
	n.pathsMu.Unlock()

	// Both lists are built from the cached kernel state rather than from stored
	// paths, so every path handed to addPathList is freshly allocated and gets
	// converted to the VPN family exactly once.
	newPathList := make([]*table.Path, 0)
	for key, spec := range current {
		if _, ok := previous[key]; ok {
			continue
		}
		if path := n.pathForRoute(spec.route, spec.iface); path != nil {
			newPathList = append(newPathList, path)
		}
	}

	withdrawnPathList := make([]*table.Path, 0)
	for key, spec := range previous {
		if _, ok := current[key]; ok {
			continue
		}
		if path := n.pathForRoute(spec.route, spec.iface); path != nil {
			withdrawnPathList = append(withdrawnPathList, path.Clone(true))
		}
	}

	n.pathsMu.Lock()
	n.advertisedPaths[vrfName] = current
	n.pathsMu.Unlock()

	if len(newPathList) > 0 {
		n.server.logger.Info("Importing routes to VRF",
			slog.String("Topic", "netlink"),
			slog.String("VRF", vrfName),
			slog.Int("RouteCount", len(newPathList)))
		n.applyLocked(vrfName, newPathList, false)
	}
	if len(withdrawnPathList) > 0 {
		n.applyLocked(vrfName, withdrawnPathList, true)
	}
}

// applyLocked pushes a path list into the RIB and records the outcome.
// Caller MUST hold n.server.shared.mu.
func (n *netlinkClient) applyLocked(vrfName string, paths []*table.Path, withdraw bool) {
	if err := n.server.addPathList(vrfName, paths); err != nil {
		n.server.logger.Error("failed to apply netlink paths",
			slog.String("Topic", "netlink"),
			slog.String("VRF", vrfName),
			slog.Bool("Withdraw", withdraw),
			slog.Any("Error", err))
		n.statsMu.Lock()
		n.stats.Errors++
		n.stats.LastError = time.Now()
		n.stats.LastErrorMsg = err.Error()
		n.statsMu.Unlock()
		return
	}

	n.statsMu.Lock()
	if withdraw {
		n.stats.Withdrawn += uint64(len(paths))
		n.stats.LastWithdraw = time.Now()
	} else {
		n.stats.Imported += uint64(len(paths))
		n.stats.LastImport = time.Now()
	}
	n.statsMu.Unlock()
}

// runImportCycle performs one complete import pass in three phases: a locked
// config snapshot, an unlocked kernel scan, then a locked diff and publish.
//
// Called ONLY from loop(), which is the one goroutine that acquires shared.mu
// for import. Every other entry point (rescan, stopLocked, withdrawVrfLocked)
// already runs with the lock held and must not call this.
func (n *netlinkClient) runImportCycle() {
	mu := &n.server.shared.mu

	// Phase 1: snapshot configuration under the lock.
	mu.Lock()
	if n.stopped {
		mu.Unlock()
		return
	}
	gen := n.generation
	work := n.collectWorkLocked()
	mu.Unlock()

	if len(work) == 0 {
		return
	}

	// Phase 2: kernel syscalls, no lock held.
	scanned := n.scanUnlocked(work)

	// Phase 3: diff and publish under the lock.
	mu.Lock()
	defer mu.Unlock()

	// If tracked state was invalidated while we were scanning, these results
	// describe a world that no longer exists. Publishing them would resurrect
	// advertisedPaths entries that withdrawVrfLocked had just cleared, after
	// which the next pass would see no difference and the routes would never be
	// re-added.
	if n.stopped || n.generation != gen {
		n.server.logger.Debug("Discarding import scan invalidated during the scan",
			slog.String("Topic", "netlink"))
		return
	}

	for _, w := range work {
		n.publishLocked(w.vrfName, scanned[w.vrfName])
	}
}

// rescan asks the scan loop to run a pass as soon as it can.
//
// Callers hold shared.mu, so this must not scan inline: the scan performs
// blocking netlink syscalls with no timeout, and holding shared.mu across them
// would stall every BGP session on the node.
func (n *netlinkClient) rescan() {
	n.server.logger.Debug("Requesting netlink import rescan", slog.String("Topic", "netlink"))
	select {
	case n.rescanCh <- struct{}{}:
	default:
		// A pass is already queued; it will pick up the new configuration.
	}
}

func (n *netlinkClient) loop() {
	n.server.logger.Debug("starting netlink client loop", slog.String("Topic", "netlink"))
	defer close(n.done) // signal loop has exited
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// First pass immediately. The constructor no longer scans inline, because it
	// runs under shared.mu and a scan must never hold that lock.
	n.tick()

	// Address events remove the latency; the ticker remains the correctness
	// mechanism. Netlink multicast drops silently under ENOBUFS and a
	// subscription can die outright, so a missed event must only ever cost the
	// poll interval, never a route.
	addrCh := n.subscribe()

	for {
		select {
		case <-n.dead:
			return
		case <-n.rescanCh:
			n.runImportCycle()
		case ev, ok := <-addrCh:
			if !ok {
				// The subscription ended. Stop selecting on a closed channel,
				// which would otherwise spin, and let the ticker resubscribe.
				n.server.logger.Warn("netlink address subscription ended; falling back to polling",
					slog.String("Topic", "netlink"))
				addrCh = nil
				continue
			}
			if !n.addrEventIsInteresting(ev) {
				continue
			}
			// One scan for a burst: a service coming up can add several
			// addresses at once, and each would otherwise take shared.mu twice.
			n.drainAddrEvents(addrCh)
			n.statsMu.Lock()
			n.stats.AddrEvents++
			n.statsMu.Unlock()
			n.runImportCycle()
		case <-ticker.C:
			if addrCh == nil {
				addrCh = n.subscribe()
			}
			n.tick()
		}
	}
}

// subscribe starts an address-event subscription, returning nil if it could not
// be established. A nil channel blocks forever in a select, which is what makes
// the poll-only fallback work without a special case.
func (n *netlinkClient) subscribe() chan netlink.AddrUpdate {
	if n.subscribeAddr == nil {
		// A client assembled without an event source polls, rather than
		// crashing its loop. The field was documented as always non-nil and was
		// not, which is exactly the kind of invariant that should be enforced
		// rather than asserted in a comment.
		return nil
	}
	ch := make(chan netlink.AddrUpdate, 64)
	if err := n.subscribeAddr(ch, n.dead); err != nil {
		n.server.logger.Warn("cannot subscribe to netlink address events; imports will poll only",
			slog.String("Topic", "netlink"),
			slog.Any("Error", err))
		return nil
	}
	n.server.logger.Debug("subscribed to netlink address events", slog.String("Topic", "netlink"))
	return ch
}

// addrEventIsInteresting reports whether an address change happened on an
// interface the import actually reads from.
//
// Every pod on a Kubernetes node brings a veth interface up and down with
// addresses attached, so without this the import would rescan - taking the
// server-wide shared.mu twice - for interfaces it will never read. The index
// set is refreshed by each scan, so a just-created interface may be missed
// until the next tick: the cost of a stale set is the poll interval, which is
// the behaviour this change improves on rather than one it regresses.
func (n *netlinkClient) addrEventIsInteresting(ev netlink.AddrUpdate) bool {
	set := n.importIfIndexes.Load()
	if set == nil {
		// Nothing scanned yet, so nothing is known to be uninteresting.
		return true
	}
	_, ok := (*set)[ev.LinkIndex]
	return ok
}

// drainAddrEvents consumes whatever else is already queued, without blocking.
func (n *netlinkClient) drainAddrEvents(ch chan netlink.AddrUpdate) {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// tick runs one import pass and records that the loop is alive.
//
// Ticks stops advancing once the loop exits, which is how an operator can see
// from metrics that the scan loop actually stopped after shutdown.
func (n *netlinkClient) tick() {
	n.statsMu.Lock()
	n.stats.Ticks++
	n.statsMu.Unlock()
	n.runImportCycle()
}

// refreshImportIfIndexes records which interface indexes the import reads from,
// so address events on unrelated interfaces can be discarded cheaply.
//
// Resolution failures are skipped rather than fatal: an interface that has just
// disappeared has no index, and the only consequence is that events for it are
// ignored, which is correct.
func (n *netlinkClient) refreshImportIfIndexes(names map[string]struct{}) {
	set := make(map[int]struct{}, len(names))
	for name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		set[iface.Index] = struct{}{}
	}
	n.importIfIndexes.Store(&set)
}

// pathForRoute builds a fresh path for one connected route.
//
// Every caller gets a newly allocated path, which matters because addPathList
// mutates what it is given: fixupApiPath rewrites the NLRI to the VPN family in
// place for a VRF. Reusing a path across an add and a later withdrawal would
// convert it twice, and the second conversion fails.
func (n *netlinkClient) pathForRoute(route *custom_net.ConnectedRoute, iface string) *table.Path {
	pathNlri, err := table.NewNlriFromAPI(route.Prefix)
	if err != nil {
		n.server.logger.Warn("failed to create nlri from netlink route",
			slog.String("Topic", "netlink"),
			slog.Any("Route", route),
			slog.Any("Error", err))
		return nil
	}

	pattr := make([]bgp.PathAttributeInterface, 0, 2)
	pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))

	family := bgp.RF_IPv4_UC
	if route.Prefix.IP.To4() == nil {
		family = bgp.RF_IPv6_UC
		// Unspecified nexthop; UpdatePathAttrs replaces it with the peer's
		// addresses, which for a netlink path is the RFC 2545 global plus
		// link-local pair.
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{pathNlri}, netip.MustParseAddr("::"))
		pattr = append(pattr, mpreach)
	} else {
		nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
		pattr = append(pattr, nexthop)
	}

	path := table.NewPath(family, table.NewNetlinkPeerInfo(iface), pathNlri, false, pattr, time.Now(), false)
	if path == nil {
		return nil
	}
	path.SetIsFromExternal(true)
	return path
}

// getStats returns a copy of the current import statistics
func (n *netlinkClient) getStats() netlinkImportStats {
	n.statsMu.RLock()
	defer n.statsMu.RUnlock()
	return n.stats
}

// stopLocked shuts down the netlink import client. If withdrawRoutes is true
// (keep_routes=false), every imported route is withdrawn from the RIB.
//
// Caller MUST hold n.server.shared.mu, which every caller already does because
// they run inside mgmtOperation.
//
// It deliberately does not wait for the scan goroutine to exit. The previous
// implementation blocked on <-n.done while holding the lock, which deadlocks the
// moment the loop needs that same lock to finish its pass. Instead the
// generation counter tells any in-flight scan to discard its results, so the
// loop is either fully before this point (its paths are in the snapshot below
// and get withdrawn) or fully after it (it publishes nothing).
func (n *netlinkClient) stopLocked(withdrawRoutes bool) {
	if n.stopped {
		return
	}
	n.stopped = true
	n.generation++
	close(n.dead)

	n.pathsMu.Lock()
	tracked := n.advertisedPaths
	n.advertisedPaths = make(map[string]map[string]*importedRoute)
	n.pathsMu.Unlock()

	if !withdrawRoutes {
		return
	}
	for vrfName, vrfPaths := range tracked {
		withdrawList := make([]*table.Path, 0, len(vrfPaths))
		for _, spec := range vrfPaths {
			if path := n.pathForRoute(spec.route, spec.iface); path != nil {
				withdrawList = append(withdrawList, path.Clone(true))
			}
		}
		if len(withdrawList) > 0 {
			n.applyLocked(vrfName, withdrawList, true)
		}
	}
}

// withdrawVrfLocked withdraws all imported routes for a specific VRF.
//
// Caller MUST hold n.server.shared.mu. The generation bump stops a scan that is
// already in flight from re-publishing the paths being withdrawn here; without
// it the tracking entry would be resurrected, and because the VRF's import is
// disabled by then nothing would ever clear it again.
func (n *netlinkClient) withdrawVrfLocked(vrfName string) {
	n.generation++

	n.pathsMu.Lock()
	vrfPaths, ok := n.advertisedPaths[vrfName]
	delete(n.advertisedPaths, vrfName)
	n.pathsMu.Unlock()

	if !ok {
		return
	}
	withdrawList := make([]*table.Path, 0, len(vrfPaths))
	for _, spec := range vrfPaths {
		if path := n.pathForRoute(spec.route, spec.iface); path != nil {
			withdrawList = append(withdrawList, path.Clone(true))
		}
	}
	if len(withdrawList) > 0 {
		n.applyLocked(vrfName, withdrawList, true)
	}
}
