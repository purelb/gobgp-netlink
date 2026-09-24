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
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

// Every configuration setting either names the code that acts on it, or says
// why nothing does.
//
// This is the check whose absence let four releases ship settings that were
// accepted, stored, reported and acted on by nothing. It is keyed by access
// path, not by Go type, and that is the point: the generated types are shared -
// one GracefulRestartConfig serves the global block, every neighbor and every
// peer group - so "some function reads GracefulRestartConfig.Enabled" is true
// the moment any one of them is read, and is exactly how the global
// graceful-restart block went a release acting on nothing while the check
// anyone would have written said it was live. Path keys make each instantiation
// answer for itself.
//
// A consumer is "file.go:Func" or "file.go:Recv.Method", relative to the
// repository root, optionally "@Ident". The test parses the file, finds the
// function, and requires its body to reference the leaf's Go field name - or
// Ident, for a consumer that copies the whole block. That is a name check, not
// a type check: it cannot prove the function reads *this* instantiation, which
// is what the path key and a human choosing the function are for. What it does
// prove is that the named function exists and still reads the field, so
// deleting the code that acts on a setting, or renaming it away, fails here.
//
// Peer-group leaves are not listed: a peer group acts through its members, so
// each must have a neighbor twin at the same path that is itself consumed.

// configLeafConsumers names the function that acts on each global and neighbor
// configuration leaf.
var configLeafConsumers = map[string]string{
	"Global.config.as":                                    "pkg/config/oc/default.go:getLocalAsForPeer",
	"Global.config.router-id":                             "pkg/server/fsm.go:buildopen",
	"Global.config.port":                                  "pkg/server/server.go:BgpServer.StartBgp",
	"Global.config.local-address-list[]":                  "pkg/server/server.go:BgpServer.StartBgp",
	"Global.config.bind-to-device":                        "pkg/server/server.go:BgpServer.passConnToPeer",
	"Global.config.graceful-restart-inherit-to-neighbors": "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",

	"Global.route-selection-options.config.always-compare-med":          "internal/pkg/table/destination.go:compareByMED",
	"Global.route-selection-options.config.ignore-as-path-length":       "internal/pkg/table/destination.go:compareByASPath",
	"Global.route-selection-options.config.external-compare-router-id":  "internal/pkg/table/destination.go:compareByRouterID",
	"Global.route-selection-options.config.disable-best-path-selection": "internal/pkg/table/table_manager.go:TableManager.GetBestPathList",

	"Global.confederation.config.enabled":          "pkg/server/peer.go:peer.handleUpdate",
	"Global.confederation.config.identifier":       "pkg/server/peer.go:peer.handleUpdate",
	"Global.confederation.config.member-as-list[]": "pkg/config/oc/util.go:Global.IsConfederationMember",

	"Global.use-multiple-paths.config.enabled":            "internal/pkg/table/destination.go:Update.GetChanges",
	"Global.use-multiple-paths.ebgp.config.maximum-paths": "pkg/server/server.go:BgpServer.StartBgp",
	"Global.use-multiple-paths.ibgp.config.maximum-paths": "pkg/server/server.go:BgpServer.StartBgp",

	// The global block acts only through inheritance: with
	// graceful-restart-inherit-to-neighbors set, defaulting copies it whole
	// to each neighbor that configures none of its own.
	"Global.graceful-restart.config.enabled":              "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper@GracefulRestart",
	"Global.graceful-restart.config.restart-time":         "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper@GracefulRestart",
	"Global.graceful-restart.config.stale-routes-time":    "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper@GracefulRestart",
	"Global.graceful-restart.config.helper-only":          "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper@GracefulRestart",
	"Global.graceful-restart.config.deferral-time":        "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper@GracefulRestart",
	"Global.graceful-restart.config.notification-enabled": "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper@GracefulRestart",

	// The global afi-safi list decides the RIB's families; only the name
	// reaches the daemon.
	"Global.afi-safis[].config.afi-safi-name": "pkg/server/server.go:BgpServer.StartBgp@AfiSafis",

	"Global.apply-policy.config.import-policy-list[]":  "pkg/config/config.go:assignGlobalpolicy",
	"Global.apply-policy.config.default-import-policy": "pkg/config/config.go:assignGlobalpolicy",
	"Global.apply-policy.config.export-policy-list[]":  "pkg/config/config.go:assignGlobalpolicy",
	"Global.apply-policy.config.default-export-policy": "pkg/config/config.go:assignGlobalpolicy",

	"Neighbor.config.peer-as":               "pkg/server/fsm.go:fsm.handleOpen",
	"Neighbor.config.local-as":              "pkg/server/fsm.go:buildopen",
	"Neighbor.config.auth-password":         "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.config.remove-private-as":     "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.config.send-community":        "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.config.peer-group":            "pkg/server/server.go:BgpServer.addNeighbor",
	"Neighbor.config.neighbor-address":      "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.config.admin-down":            "pkg/server/fsm.go:newFSM",
	"Neighbor.config.neighbor-interface":    "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.config.vrf":                   "pkg/server/peer.go:peer.toGlobalFamilies",
	"Neighbor.config.send-software-version": "pkg/server/fsm.go:capabilitiesFromConfig",

	"Neighbor.timers.config.connect-retry":              "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.timers.config.hold-time":                  "pkg/server/fsm.go:buildopen",
	"Neighbor.timers.config.keepalive-interval":         "pkg/server/fsm.go:fsm.stateChange",
	"Neighbor.timers.config.idle-hold-time-after-reset": "pkg/server/fsm.go:fsm.sendNotification",

	"Neighbor.transport.config.tcp-mss":        "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.transport.config.passive-mode":   "pkg/server/fsm.go:outgoingConnManager.run",
	"Neighbor.transport.config.local-address":  "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.transport.config.local-port":     "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.transport.config.remote-port":    "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.transport.config.bind-interface": "pkg/server/fsm.go:fsmHandler.connectLoop",
	"Neighbor.transport.config.ip-tos":         "pkg/server/fsm.go:fsmHandler.connectLoop",

	"Neighbor.ebgp-multihop.config.enabled":      "pkg/server/fsm.go:setPeerConnTTL",
	"Neighbor.ebgp-multihop.config.multihop-ttl": "pkg/server/fsm.go:setPeerConnTTL",

	"Neighbor.route-reflector.config.route-reflector-cluster-id": "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.route-reflector.config.route-reflector-client":     "pkg/server/peer.go:peer.isRouteReflectorClient",

	"Neighbor.as-path-options.config.allow-own-as":             "pkg/server/peer.go:peer.handleUpdate",
	"Neighbor.as-path-options.config.replace-peer-as":          "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.as-path-options.config.allow-as-path-loop-local": "pkg/server/peer.go:peer.allowAsPathLoopLocal",

	// The neighbor-level add-paths block is a config-file convenience:
	// defaulting copies it into each afi-safi, and it acts from there.
	"Neighbor.add-paths.config.receive":  "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.add-paths.config.send-max": "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",

	"Neighbor.afi-safis[].mp-graceful-restart.config.enabled":              "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.afi-safis[].config.afi-safi-name":                            "pkg/config/oc/util.go:extractFamilyFromConfigAfiSafi",
	"Neighbor.afi-safis[].prefix-limit.config.max-prefixes":                "pkg/server/peer.go:peer.isPrefixLimit",
	"Neighbor.afi-safis[].prefix-limit.config.shutdown-threshold-pct":      "pkg/server/peer.go:peer.isPrefixLimit",
	"Neighbor.afi-safis[].route-target-membership.config.deferral-time":    "pkg/server/server.go:BgpServer.handleFSMMessage",
	"Neighbor.afi-safis[].long-lived-graceful-restart.config.enabled":      "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.afi-safis[].long-lived-graceful-restart.config.restart-time": "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.afi-safis[].add-paths.config.receive":                        "pkg/config/oc/default.go:setDefaultNeighborConfigValuesWithViper",
	"Neighbor.afi-safis[].add-paths.config.send-max":                       "pkg/server/peer.go:peer.getAddPathSendMax",

	"Neighbor.graceful-restart.config.enabled":              "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.graceful-restart.config.restart-time":         "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.graceful-restart.config.stale-routes-time":    "pkg/server/server.go:BgpServer.handleFSMMessage",
	"Neighbor.graceful-restart.config.helper-only":          "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.graceful-restart.config.deferral-time":        "pkg/server/server.go:BgpServer.handleFSMMessage",
	"Neighbor.graceful-restart.config.notification-enabled": "pkg/server/fsm.go:capabilitiesFromConfig",
	"Neighbor.graceful-restart.config.long-lived-enabled":   "pkg/server/fsm.go:capabilitiesFromConfig",

	// Route-server clients only; refusePeerPolicy refuses it on any other
	// peer rather than store a policy that is never installed.
	"Neighbor.apply-policy.config.import-policy-list[]":  "internal/pkg/table/policy.go:RoutingPolicy.getAssignmentFromConfig",
	"Neighbor.apply-policy.config.default-import-policy": "internal/pkg/table/policy.go:RoutingPolicy.getAssignmentFromConfig",
	"Neighbor.apply-policy.config.export-policy-list[]":  "internal/pkg/table/policy.go:RoutingPolicy.getAssignmentFromConfig",
	"Neighbor.apply-policy.config.default-export-policy": "internal/pkg/table/policy.go:RoutingPolicy.getAssignmentFromConfig",

	"Neighbor.route-server.config.route-server-client": "pkg/server/peer.go:peer.isRouteServerClient",
	"Neighbor.route-server.config.secondary-route":     "pkg/server/peer.go:peer.isSecondaryRouteEnabled",

	"Neighbor.ttl-security.config.enabled": "pkg/server/fsm.go:setPeerConnTTL",
	"Neighbor.ttl-security.config.ttl-min": "pkg/server/fsm.go:setPeerConnTTL",

	"Neighbor.bfd.config.enabled":                     "pkg/server/bfd_server.go:bfdServer.AddPeer",
	"Neighbor.bfd.config.port":                        "pkg/server/bfd_peer.go:NewBfdPeer",
	"Neighbor.bfd.config.desired-minimum-tx-interval": "pkg/server/bfd_peer.go:NewBfdPeer",
	"Neighbor.bfd.config.required-minimum-receive":    "pkg/server/bfd_peer.go:NewBfdPeer",
	"Neighbor.bfd.config.detection-multiplier":        "pkg/server/bfd_peer.go:NewBfdPeer",

	// The one peer-group leaf with no neighbor twin.
	"PeerGroup.config.peer-group-name": "pkg/server/server.go:BgpServer.addPeerGroup",
}

// configLeavesNotConsumed is every configuration leaf nothing acts on, with the
// reason. Each is a by-design case or is refused on the way in; a setting that
// is accepted and silently ignored does not belong here - it belongs deleted.
var configLeavesNotConsumed = map[string]string{
	"Global.graceful-restart.config.long-lived-enabled": "refused by SetDefaultGlobalConfigValues: long-lived graceful " +
		"restart is never inherited from the global block",

	"Global.afi-safis[].config.enabled":                                  "every listed family is enabled; enabled = false is refused by validateGlobalAfiSafis",
	"Global.afi-safis[].mp-graceful-restart.config.enabled":              globalAfiSafiDropped,
	"Global.afi-safis[].prefix-limit.config.max-prefixes":                globalAfiSafiDropped,
	"Global.afi-safis[].prefix-limit.config.shutdown-threshold-pct":      globalAfiSafiDropped,
	"Global.afi-safis[].route-target-membership.config.deferral-time":    globalAfiSafiDropped,
	"Global.afi-safis[].long-lived-graceful-restart.config.enabled":      globalAfiSafiDropped,
	"Global.afi-safis[].long-lived-graceful-restart.config.restart-time": globalAfiSafiDropped,
	"Global.afi-safis[].add-paths.config.receive":                        globalAfiSafiDropped,
	"Global.afi-safis[].add-paths.config.send-max":                       globalAfiSafiDropped,

	"Neighbor.config.peer-type": "derived: defaulting overwrites it from peer-as and local-as, so a supplied value " +
		"never survives. The field carries the derived type, which is what the daemon reads and reports.",
	"Neighbor.config.description": "informational by design: copied to state and reported, and never on the wire",
	"Neighbor.afi-safis[].config.enabled": "every listed family is negotiated; enabled = false is refused in config " +
		"files, and over the API cannot be told from absent",
}

const globalAfiSafiDropped = "refused by validateGlobalAfiSafis: api.Global carries only the family names, " +
	"so every other global afi-safi setting was dropped on the way to the daemon"

type configLeaf struct {
	path  string // "Neighbor.timers.config.hold-time"
	field string // Go field name of the leaf, "HoldTime"
}

// configLeaves walks a generated config type and returns every leaf under a
// config container, by access path. State containers are skipped: they are
// what the daemon reports, not what it is told.
func configLeaves(root reflect.Type) []configLeaf {
	var out []configLeaf
	var walk func(tp reflect.Type, path string)
	walk = func(tp reflect.Type, path string) {
		for i := range tp.NumField() {
			f := tp.Field(i)
			tag := f.Tag.Get("mapstructure")
			if tag == "" || tag == "state" {
				continue
			}
			p := path + "." + tag
			ft := f.Type
			if ft.Kind() == reflect.Slice {
				ft = ft.Elem()
				p += "[]"
			}
			if ft.Kind() == reflect.Struct && ft.PkgPath() == tp.PkgPath() {
				walk(ft, p)
				continue
			}
			if strings.HasSuffix(path, ".config") {
				out = append(out, configLeaf{path: p, field: f.Name})
			}
		}
	}
	walk(root, root.Name())
	return out
}

var parsedFiles sync.Map // repo-relative path -> *ast.File

// funcReferences reports whether the named function in file reads ident as a
// selector - x.Ident - anywhere in its body. fn is "Func" or "Recv.Method".
func funcReferences(t *testing.T, file, fn, ident string) (found, readsIdent bool) {
	t.Helper()
	v, ok := parsedFiles.Load(file)
	if !ok {
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", file), nil, 0)
		require.NoError(t, err, "consumer file %s", file)
		parsedFiles.Store(file, f)
		v = f
	}
	recv, name := "", fn
	if i := strings.Index(fn, "."); i >= 0 {
		recv, name = fn[:i], fn[i+1:]
	}
	for _, d := range v.(*ast.File).Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name || fd.Body == nil {
			continue
		}
		if recv != "" {
			if fd.Recv == nil || len(fd.Recv.List) == 0 {
				continue
			}
			rt := fd.Recv.List[0].Type
			if st, ok := rt.(*ast.StarExpr); ok {
				rt = st.X
			}
			if id, ok := rt.(*ast.Ident); !ok || id.Name != recv {
				continue
			}
		} else if fd.Recv != nil {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if se, ok := n.(*ast.SelectorExpr); ok && se.Sel.Name == ident {
				readsIdent = true
			}
			return !readsIdent
		})
		return found, readsIdent
	}
	return false, false
}

func TestConformanceEveryConfigLeafHasAConsumer(t *testing.T) {
	leaves := map[string]configLeaf{}
	for _, root := range []reflect.Type{
		reflect.TypeOf(oc.Global{}), reflect.TypeOf(oc.Neighbor{}), reflect.TypeOf(oc.PeerGroup{}),
	} {
		for _, l := range configLeaves(root) {
			leaves[l.path] = l
		}
	}

	var paths []string
	for p := range leaves {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		l := leaves[p]
		consumer, consumed := configLeafConsumers[p]
		reason, excused := configLeavesNotConsumed[p]
		assert.False(t, consumed && excused, "%s is both consumed and excused", p)

		if strings.HasPrefix(p, "PeerGroup.") && !consumed && !excused {
			// A peer group acts through its members: its leaf must have a
			// neighbor twin that is itself accounted for.
			twin := "Neighbor." + strings.TrimPrefix(p, "PeerGroup.")
			_, twinLeaf := leaves[twin]
			_, twinConsumed := configLeafConsumers[twin]
			_, twinExcused := configLeavesNotConsumed[twin]
			assert.True(t, twinLeaf && (twinConsumed || twinExcused),
				"peer-group setting %s has no neighbor twin that acts on it. A peer group only acts through its "+
					"members; either the members read this setting, or it needs a consumer or a reason of its own.", p)
			continue
		}

		if !consumed && !excused {
			t.Errorf("configuration setting %s names no code that acts on it and no reason why nothing does. "+
				"Name the function in configLeafConsumers, or give the reason in configLeavesNotConsumed. "+
				"A setting accepted and acted on by nothing is the defect this test exists to stop: "+
				"delete it or refuse it rather than list it as not consumed.", p)
			continue
		}
		if excused {
			assert.NotEmpty(t, reason, "%s needs a reason, not an empty string", p)
			continue
		}

		fileFn, ident, _ := strings.Cut(consumer, "@")
		if ident == "" {
			ident = l.field
		}
		file, fn, ok := strings.Cut(fileFn, ":")
		require.True(t, ok, "consumer %q for %s is not file.go:Func", consumer, p)
		found, reads := funcReferences(t, file, fn, ident)
		if !assert.True(t, found, "%s: consumer %s not found in %s - renamed or deleted?", p, fn, file) {
			continue
		}
		assert.True(t, reads, "%s: %s no longer reads .%s, so nothing is known to act on this setting", p, fn, ident)
	}

	// And nothing listed that is not a real setting, so the maps cannot rot
	// into naming leaves that were removed.
	for p := range configLeafConsumers {
		_, ok := leaves[p]
		assert.True(t, ok, "configLeafConsumers names %s, which is not a configuration setting", p)
	}
	for p := range configLeavesNotConsumed {
		_, ok := leaves[p]
		assert.True(t, ok, "configLeavesNotConsumed names %s, which is not a configuration setting", p)
	}
}
