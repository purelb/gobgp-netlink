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
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	go_netlink "github.com/vishvananda/netlink"
)

// fakeNetlink is an in-memory stand-in for the kernel routing tables, satisfying
// netlinkHandle.
//
// It models enough of the kernel's behaviour to make the export path testable:
// routes are keyed the way the kernel identifies them (table, destination and
// metric), RouteReplace is an upsert, and deleting an absent route returns ESRCH
// as the kernel does.
type fakeNetlink struct {
	mu sync.Mutex

	// routes is the simulated FIB, keyed by kernel route identity.
	routes map[fakeRouteKey]go_netlink.Route
	// links is the set of interfaces, by name. Only VRF links matter here.
	links map[string]go_netlink.Link
	// reachable lists nexthops RouteGet resolves, and the table it resolves them
	// in. A nexthop absent from this map is unreachable.
	reachable map[string]go_netlink.Route

	// Injectable failures, so error paths are reachable from tests.
	routeListErr    error
	routeReplaceErr error
	routeDelErr     error

	// Call counters, for asserting that something did NOT happen.
	replaceCalls int
	delCalls     int
	listCalls    int

	socketTimeout time.Duration
	closed        bool
}

type fakeRouteKey struct {
	table  int
	dst    string
	metric int
}

func newFakeNetlink() *fakeNetlink {
	return &fakeNetlink{
		routes:    make(map[fakeRouteKey]go_netlink.Route),
		links:     make(map[string]go_netlink.Link),
		reachable: make(map[string]go_netlink.Route),
	}
}

func fakeKey(r *go_netlink.Route) fakeRouteKey {
	dst := ""
	if r.Dst != nil {
		dst = r.Dst.String()
	}
	return fakeRouteKey{table: r.Table, dst: dst, metric: r.Priority}
}

// addRoute seeds the fake FIB, standing in for routes a previous run left behind.
func (f *fakeNetlink) addRoute(r go_netlink.Route) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[fakeKey(&r)] = r
}

// addLink registers an interface the fake can resolve by name.
func (f *fakeNetlink) addLink(name string, index int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	attrs := go_netlink.NewLinkAttrs()
	attrs.Name = name
	attrs.Index = index
	f.links[name] = &go_netlink.Dummy{LinkAttrs: attrs}
}

// setReachable makes a nexthop resolvable, in the given table and with the given
// route type. A nexthop absent from this map is unreachable.
func (f *fakeNetlink) setReachable(nh string, table int, routeType int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reachable[nh] = go_netlink.Route{Table: table, Type: routeType}
}

// routeFor returns the installed route for a destination in a table.
func (f *fakeNetlink) routeFor(table int, dst string) *go_netlink.Route {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, r := range f.routes {
		if k.table == table && k.dst == dst {
			return &r
		}
	}
	return nil
}

// routeCount reports how many routes the fake FIB currently holds.
func (f *fakeNetlink) routeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.routes)
}

// hasRoute reports whether a destination is present in a table, at any metric.
func (f *fakeNetlink) hasRoute(table int, dst string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k := range f.routes {
		if k.table == table && k.dst == dst {
			return true
		}
	}
	return false
}

func (f *fakeNetlink) counts() (replace, del, list int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.replaceCalls, f.delCalls, f.listCalls
}

// --- netlinkHandle implementation ---

func (f *fakeNetlink) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeNetlink) LinkByName(name string) (go_netlink.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[name]
	if !ok {
		return nil, go_netlink.LinkNotFoundError{}
	}
	return l, nil
}

func (f *fakeNetlink) LinkList() ([]go_netlink.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]go_netlink.Link, 0, len(f.links))
	for _, l := range f.links {
		out = append(out, l)
	}
	return out, nil
}

func (f *fakeNetlink) RouteDel(route *go_netlink.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCalls++
	if f.routeDelErr != nil {
		return f.routeDelErr
	}
	k := fakeKey(route)
	if _, ok := f.routes[k]; !ok {
		// The kernel reports ESRCH for a route that is not there.
		return syscall.ESRCH
	}
	delete(f.routes, k)
	return nil
}

func (f *fakeNetlink) RouteGet(destination net.IP) ([]go_netlink.Route, error) {
	return f.RouteGetWithOptions(destination, nil)
}

func (f *fakeNetlink) RouteGetWithOptions(destination net.IP, options *go_netlink.RouteGetOptions) ([]go_netlink.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.reachable[destination.String()]
	if !ok {
		return nil, fmt.Errorf("no route to %s", destination)
	}
	// Without a VRF option the kernel resolves in the main table, which is what
	// makes unqualified validation fail for VRF-scoped rules.
	if options == nil || options.VrfName == "" {
		return []go_netlink.Route{{Table: unix_RT_TABLE_MAIN, Type: r.Type}}, nil
	}
	return []go_netlink.Route{r}, nil
}

func (f *fakeNetlink) RouteList(link go_netlink.Link, family int) ([]go_netlink.Route, error) {
	return f.RouteListFiltered(family, &go_netlink.Route{Table: 0}, go_netlink.RT_FILTER_TABLE)
}

func (f *fakeNetlink) RouteListFiltered(family int, filter *go_netlink.Route, filterMask uint64) ([]go_netlink.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.routeListErr != nil {
		return nil, f.routeListErr
	}
	out := make([]go_netlink.Route, 0, len(f.routes))
	for k, r := range f.routes {
		if filter != nil && filterMask&go_netlink.RT_FILTER_TABLE != 0 && !sameTable(k.table, filter.Table) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// sameTable treats table 0 and RT_TABLE_MAIN as the same table, which is what
// the kernel does: RouteList(nil, ...) enumerates main, and routes there are
// reported with Table 254. Without this the fake would let a main-table
// assertion pass because it could not see the route at all, rather than because
// the code correctly left it alone.
func sameTable(a, b int) bool {
	norm := func(t int) int {
		if t == 0 {
			return unix_RT_TABLE_MAIN
		}
		return t
	}
	return norm(a) == norm(b)
}

func (f *fakeNetlink) RouteReplace(route *go_netlink.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaceCalls++
	if f.routeReplaceErr != nil {
		return f.routeReplaceErr
	}
	f.routes[fakeKey(route)] = *route
	return nil
}

func (f *fakeNetlink) SetSocketTimeout(to time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.socketTimeout = to
	return nil
}

// unix_RT_TABLE_MAIN is the main routing table id. Spelled out here to avoid
// pulling golang.org/x/sys/unix into a test file for one constant.
const unix_RT_TABLE_MAIN = 254
