// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
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

package oc

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/osrg/gobgp/v4/internal/pkg/version"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
	"github.com/osrg/gobgp/v4/pkg/zebra"
	"github.com/spf13/viper"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
	DEFAULT_CONNECT_RETRY             = 120
)

var forcedOverwrittenConfig = []string{
	"neighbor.config.peer-as",
	"neighbor.timers.config.minimum-advertisement-interval",
}

// configuredFields records which fields a TOML neighbor actually set, keyed by
// the identifier ReadConfigFile registered it under. OverwriteNeighborConfigWithPeerGroup
// consults it to tell "the neighbor set this field" from "the field is at its
// zero value", which is what decides whether the peer group's value wins.
//
// It is written from the SIGHUP config-reload path and read on the Serve
// goroutine whenever a peer is added or updated, so it needs the lock: a reload
// racing an AddPeer is a data race on a plain map. -race does not currently
// catch it because no test reloads concurrently with an API call.
//
// Entries are also removed when a peer goes away. Without that, a peer deleted
// and re-added over gRPC picks up the presence recorded for whatever TOML
// neighbor last held its address.
var (
	configuredFieldsMu sync.RWMutex
	configuredFields   = map[string]any{}
)

func RegisterConfiguredFields(addr string, n any) {
	configuredFieldsMu.Lock()
	defer configuredFieldsMu.Unlock()
	configuredFields[addr] = n
}

// UnregisterConfiguredFields drops the presence recorded for a neighbor. Call it
// when the neighbor is deleted, so a later neighbor reusing the address does not
// inherit its field-presence.
func UnregisterConfiguredFields(addr string) {
	configuredFieldsMu.Lock()
	delete(configuredFields, addr)
	configuredFieldsMu.Unlock()
	forgetProvenance(addr)
}

func lookupConfiguredFields(addr string) (any, bool) {
	configuredFieldsMu.RLock()
	defer configuredFieldsMu.RUnlock()
	v, ok := configuredFields[addr]
	return v, ok
}

// MarkBlockConfigured builds the presence record for one configuration block,
// in the shape the TOML loader produces, so that overwriteConfig treats every
// field of the block as explicitly set and leaves it alone.
//
// This is how the gRPC path gets the field presence that only the config file
// had. proto3 gives presence per message, not per field, so the rule is
// block-level: sending a block means owning all of it, including the fields
// left at their zero value. A client that sends a partial block therefore stops
// inheriting the rest of it from the peer group - that is the deliberate
// trade, and it is what makes "enabled = false" expressible at all, which a
// zero-value test could never do.
func MarkBlockConfigured(block any) map[string]any {
	fields := map[string]any{}
	t := reflect.Indirect(reflect.ValueOf(block)).Type()
	for i := range t.NumField() {
		if tag := t.Field(i).Tag.Get("mapstructure"); tag != "" && tag != "-" {
			fields[tag] = true
		}
	}
	return map[string]any{"config": fields}
}

// BlockSource says where a neighbor's configuration block ended up coming
// from. GetRunningConfig and ListPeer both report the config as *resolved* -
// defaults applied, peer-group and global inheritance already folded in - so
// without this an operator cannot tell a value they set from one they got, and
// after an inheritance change that is exactly the question they need answered.
type BlockSource string

const (
	SourceNeighbor  BlockSource = "neighbor"
	SourcePeerGroup BlockSource = "peer-group"
	SourceGlobal    BlockSource = "global"
)

var (
	provenanceMu sync.RWMutex
	provenance   = map[string]map[string]BlockSource{}
)

func recordProvenance(key, block string, src BlockSource) {
	if key == "" {
		return
	}
	provenanceMu.Lock()
	defer provenanceMu.Unlock()
	if provenance[key] == nil {
		provenance[key] = map[string]BlockSource{}
	}
	provenance[key][block] = src
}

// NeighborProvenance returns where each block of a neighbor's config came from.
// Blocks that were left at their defaults are absent rather than listed, so the
// output names only what was actually inherited or set.
func NeighborProvenance(key string) map[string]BlockSource {
	provenanceMu.RLock()
	defer provenanceMu.RUnlock()
	out := make(map[string]BlockSource, len(provenance[key]))
	for k, v := range provenance[key] {
		out[k] = v
	}
	return out
}

func forgetProvenance(key string) {
	provenanceMu.Lock()
	defer provenanceMu.Unlock()
	delete(provenance, key)
}

// NeighborPresenceKey is the key configuredFields is written and read under.
// Both sides must derive it identically, so they share this one function.
//
// It has to cover every way a neighbor gets identified, because each of them
// has been a bug. An interface peer has no configured address, so it keys on
// the interface name - registering it under one and looking it up under the
// other meant interface peers never matched and the peer group won every field
// for them. A dynamic peer has no configured address either, only a state one,
// with the same consequence: it sets passive mode and the group's empty
// transport block took it straight back off again.
//
// Returns "" only for a neighbor with no identity at all, which is not
// registrable; the caller skips it rather than storing an entry nothing can
// look up.
func NeighborPresenceKey(n *Neighbor) string {
	if n.Config.NeighborAddress.IsValid() {
		return n.Config.NeighborAddress.String()
	}
	if n.Config.NeighborInterface != "" {
		return n.Config.NeighborInterface
	}
	if n.State.NeighborAddress.IsValid() {
		return n.State.NeighborAddress.String()
	}
	return ""
}

func defaultAfiSafi(typ AfiSafiType, enable bool) AfiSafi {
	return AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: typ,
			Enabled:     enable,
		},
		State: AfiSafiState{
			AfiSafiName: typ,
			Family:      bgp.AddressFamilyValueMap[string(typ)],
		},
	}
}

func SetDefaultNeighborConfigValues(n *Neighbor, pg *PeerGroup, g *Global) error {
	// Determines this function is called against the same Neighbor struct,
	// and if already called, returns immediately.
	if n.State.LocalAs != 0 {
		return nil
	}

	return setDefaultNeighborConfigValuesWithViper(nil, n, g, pg)
}

func setDefaultNeighborConfigValuesWithViper(v *viper.Viper, n *Neighbor, g *Global, pg *PeerGroup) error {
	if n == nil {
		return fmt.Errorf("neighbor config is nil")
	}
	if g == nil {
		return fmt.Errorf("global config is nil")
	}

	if v == nil {
		v = viper.New()
	}

	if pg != nil {
		if err := OverwriteNeighborConfigWithPeerGroup(n, pg); err != nil {
			return err
		}
	}

	// Global graceful restart, if the operator opted in. Deliberately outside
	// the block above: most neighbors have no peer group, and putting this
	// inside it would have skipped exactly those.
	//
	// Precedence is neighbor, then peer group, then global - so this only fills
	// a block that is still untouched after peer-group inheritance has run.
	// Presence is what decides "untouched": a neighbor that sent its own
	// graceful-restart block owns it, including an explicitly disabled one, and
	// must not have the global block put back on top.
	if g.Config.GracefulRestartInheritToNeighbors && !v.IsSet("neighbor.graceful-restart.config.enabled") {
		var none GracefulRestartConfig
		if n.GracefulRestart.Config == none {
			n.GracefulRestart.Config = g.GracefulRestart.Config
			recordProvenance(NeighborPresenceKey(n), "graceful-restart", SourceGlobal)
			// long-lived is not propagated. The per-family LLGR flag is never
			// derived from the neighbor-level one, so switching it on here
			// would advertise a long-lived capability carrying no families -
			// the same empty-capability defect that mp-graceful-restart had.
			n.GracefulRestart.Config.LongLivedEnabled = false
		}
	}

	if n.Config.LocalAs == 0 {
		n.Config.LocalAs = getLocalAsForPeer(g, n.Config.PeerAs)
	}
	n.State.LocalAs = n.Config.LocalAs

	n.Config.PeerType = getConfigPeerType(n.Config.PeerAs, n.Config.LocalAs)
	n.State.PeerType = n.Config.PeerType
	// Unconditional, unlike RemovePrivateAs below: which communities to send
	// applies to iBGP and eBGP alike. An empty value stays empty and means
	// "not configured".
	if err := validateSendCommunity(n.Config.SendCommunity); err != nil {
		return err
	}
	n.State.SendCommunity = n.Config.SendCommunity
	if n.Config.PeerType == PEER_TYPE_EXTERNAL {
		n.State.RemovePrivateAs = n.Config.RemovePrivateAs
		n.AsPathOptions.State.ReplacePeerAs = n.AsPathOptions.Config.ReplacePeerAs
	} else {
		if string(n.Config.RemovePrivateAs) != "" {
			return fmt.Errorf("can't set remove-private-as for iBGP peer")
		}
		if n.AsPathOptions.Config.ReplacePeerAs {
			return fmt.Errorf("can't set replace-peer-as for iBGP peer")
		}
	}

	if !n.State.NeighborAddress.IsValid() {
		n.State.NeighborAddress = n.Config.NeighborAddress
	}

	n.State.PeerAs = n.Config.PeerAs
	n.AsPathOptions.State.AllowOwnAs = n.AsPathOptions.Config.AllowOwnAs
	n.AsPathOptions.State.AllowAsPathLoopLocal = n.AsPathOptions.Config.AllowAsPathLoopLocal

	if !v.IsSet("neighbor.error-handling.config.treat-as-withdraw") {
		n.ErrorHandling.Config.TreatAsWithdraw = true
	}

	if !v.IsSet("neighbor.timers.config.connect-retry") && n.Timers.Config.ConnectRetry == 0 {
		n.Timers.Config.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
	}
	if !v.IsSet("neighbor.timers.config.hold-time") && n.Timers.Config.HoldTime == 0 {
		n.Timers.Config.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if !v.IsSet("neighbor.timers.config.keepalive-interval") && n.Timers.Config.KeepaliveInterval == 0 {
		n.Timers.Config.KeepaliveInterval = n.Timers.Config.HoldTime / 3
	}
	if !v.IsSet("neighbor.timers.config.idle-hold-time-after-reset") && n.Timers.Config.IdleHoldTimeAfterReset == 0 {
		n.Timers.Config.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}

	if n.Config.NeighborInterface != "" {
		if n.RouteServer.Config.RouteServerClient {
			return fmt.Errorf("configuring route server client as unnumbered peer is not supported")
		}
		addr, err := GetIPv6LinkLocalNeighborAddress(n.Config.NeighborInterface)
		if err != nil {
			return err
		}
		if addr != "" {
			n.State.NeighborAddress = netip.MustParseAddr(addr)
		}
	}

	if !n.Transport.Config.LocalAddress.IsValid() {
		if !n.State.NeighborAddress.IsValid() {
			return fmt.Errorf("no neighbor address/interface specified")
		}
		ipAddr, err := net.ResolveIPAddr("ip", n.State.NeighborAddress.String())
		if err != nil {
			return err
		}
		localAddress := "0.0.0.0"
		if ipAddr.IP.To4() == nil {
			localAddress = "::"
			if ipAddr.Zone != "" {
				localAddress, err = getIPv6LinkLocalAddress(ipAddr.Zone)
				if err != nil {
					return err
				}
			}
		}
		n.Transport.Config.LocalAddress = netip.MustParseAddr(localAddress)
	}

	if len(n.AfiSafis) == 0 {
		if n.Config.NeighborInterface != "" {
			n.AfiSafis = []AfiSafi{
				defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true),
				defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true),
			}
		} else if ipAddr, err := net.ResolveIPAddr("ip", n.State.NeighborAddress.String()); err != nil {
			return fmt.Errorf("invalid neighbor address: %s", n.State.NeighborAddress)
		} else if ipAddr.IP.To4() != nil {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)}
		} else {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)}
		}
		for i := range n.AfiSafis {
			// Derive per-family Graceful Restart here too. The explicit
			// afi-safi branch below has done this since the capability bug was
			// found, but this branch - a neighbor that lists no families at all,
			// which is the ordinary shape over the API - was left out, so those
			// peers still advertised a GR capability with an empty AFI/SAFI
			// list. There is no explicit per-family setting to respect on this
			// path, because the families are synthesised.
			n.AfiSafis[i].MpGracefulRestart.Config.Enabled = n.GracefulRestart.Config.Enabled
			n.AfiSafis[i].MpGracefulRestart.State.Enabled = n.AfiSafis[i].MpGracefulRestart.Config.Enabled
			n.AfiSafis[i].AddPaths.Config.Receive = n.AddPaths.Config.Receive
			n.AfiSafis[i].AddPaths.State.Receive = n.AddPaths.Config.Receive
			n.AfiSafis[i].AddPaths.Config.SendMax = n.AddPaths.Config.SendMax
			n.AfiSafis[i].AddPaths.State.SendMax = n.AddPaths.Config.SendMax
		}
	} else {
		afs, err := extractArray(v.Get("neighbor.afi-safis"))
		if err != nil {
			return err
		}
		for i := range n.AfiSafis {
			vv := viper.New()
			if len(afs) > i {
				vv.Set("afi-safi", afs[i])
			}
			rf, err := bgp.GetFamily(string(n.AfiSafis[i].Config.AfiSafiName))
			if err != nil {
				return err
			}
			n.AfiSafis[i].State.Family = rf
			n.AfiSafis[i].State.AfiSafiName = n.AfiSafis[i].Config.AfiSafiName
			if !vv.IsSet("afi-safi.config.enabled") {
				n.AfiSafis[i].Config.Enabled = true
			}
			// Derive per-family Graceful Restart from the neighbor's GR setting
			// unless it was stated explicitly.
			//
			// fsm.go only emits a GR capability tuple for families whose
			// mp-graceful-restart is enabled, so a neighbor with
			// graceful-restart enabled but nothing set per family advertised
			// the capability with an empty AFI/SAFI list - the peer negotiated
			// GR and then retained nothing, which is indistinguishable from
			// working until a restart actually happens.
			if !vv.IsSet("afi-safi.mp-graceful-restart.config.enabled") {
				n.AfiSafis[i].MpGracefulRestart.Config.Enabled = n.GracefulRestart.Config.Enabled
			}
			n.AfiSafis[i].MpGracefulRestart.State.Enabled = n.AfiSafis[i].MpGracefulRestart.Config.Enabled
			if !vv.IsSet("afi-safi.add-paths.config.receive") {
				if n.AddPaths.Config.Receive {
					n.AfiSafis[i].AddPaths.Config.Receive = n.AddPaths.Config.Receive
				}
			}
			n.AfiSafis[i].AddPaths.State.Receive = n.AfiSafis[i].AddPaths.Config.Receive
			if !vv.IsSet("afi-safi.add-paths.config.send-max") {
				if n.AddPaths.Config.SendMax != 0 {
					n.AfiSafis[i].AddPaths.Config.SendMax = n.AddPaths.Config.SendMax
				}
			}
			n.AfiSafis[i].AddPaths.State.SendMax = n.AfiSafis[i].AddPaths.Config.SendMax
		}
	}

	n.State.Description = n.Config.Description
	n.State.AdminDown = n.Config.AdminDown

	if n.GracefulRestart.Config.Enabled {
		if !v.IsSet("neighbor.graceful-restart.config.restart-time") && n.GracefulRestart.Config.RestartTime == 0 {
			// RFC 4724 4. Operation
			// A suggested default for the Restart Time is a value less than or
			// equal to the HOLDTIME carried in the OPEN.
			n.GracefulRestart.Config.RestartTime = uint16(n.Timers.Config.HoldTime)
		}
		if !v.IsSet("neighbor.graceful-restart.config.deferral-time") && n.GracefulRestart.Config.DeferralTime == 0 {
			// RFC 4724 4.1. Procedures for the Restarting Speaker
			// The value of this timer should be large
			// enough, so as to provide all the peers of the Restarting Speaker with
			// enough time to send all the routes to the Restarting Speaker
			n.GracefulRestart.Config.DeferralTime = uint16(360)
		}
	}

	if n.EbgpMultihop.Config.Enabled {
		if n.TtlSecurity.Config.Enabled {
			return fmt.Errorf("ebgp-multihop and ttl-security are mutually exclusive")
		}
		if n.EbgpMultihop.Config.MultihopTtl == 0 {
			n.EbgpMultihop.Config.MultihopTtl = 255
		}
	} else if n.TtlSecurity.Config.Enabled {
		if n.TtlSecurity.Config.TtlMin == 0 {
			n.TtlSecurity.Config.TtlMin = 255
		}
	}

	if n.RouteReflector.Config.RouteReflectorClient {
		clusterId, err := getConfigClusterId(g, n.RouteReflector.Config.RouteReflectorClusterId)
		if err != nil {
			return err
		}
		n.RouteReflector.State.RouteReflectorClusterId = clusterId
	}
	if n.Bfd.Config.Port == 0 {
		// RFC 5881: BFD control packets port
		n.Bfd.Config.Port = 3784
	}
	if n.Bfd.Config.DetectionMultiplier == 0 {
		n.Bfd.Config.DetectionMultiplier = 3
	}
	if n.Bfd.Config.DesiredMinimumTxInterval == 0 {
		n.Bfd.Config.DesiredMinimumTxInterval = 1000000 // 1s in microseconds
	}
	if n.Bfd.Config.RequiredMinimumReceive == 0 {
		n.Bfd.Config.RequiredMinimumReceive = 1000000 // 1s in microseconds
	}
	// After defaulting, so an omitted interval is checked as the value it will
	// actually run with rather than as zero.
	if err := n.Bfd.Config.Validate(); err != nil {
		return fmt.Errorf("neighbor %s: %w", n.State.NeighborAddress, err)
	}
	return nil
}

// SetPeerGroupStateValues fills State fields required for table.NewPeerGroupInfo.
func SetPeerGroupStateValues(pg *PeerGroup, g *Global) error {
	if pg.Config.LocalAs == 0 {
		pg.Config.LocalAs = getLocalAsForPeer(g, pg.Config.PeerAs)
	}
	pg.State.LocalAs = pg.Config.LocalAs
	pg.State.PeerAs = pg.Config.PeerAs

	pg.Config.PeerType = getConfigPeerType(pg.Config.PeerAs, pg.Config.LocalAs)
	pg.State.PeerType = pg.Config.PeerType
	if err := validateSendCommunity(pg.Config.SendCommunity); err != nil {
		return err
	}
	pg.State.SendCommunity = pg.Config.SendCommunity

	if pg.RouteReflector.Config.RouteReflectorClient {
		clusterId, err := getConfigClusterId(g, pg.RouteReflector.Config.RouteReflectorClusterId)
		if err != nil {
			return err
		}
		pg.RouteReflector.State.RouteReflectorClusterId = clusterId
	}

	return nil
}

func getLocalAsForPeer(g *Global, peerAs uint32) uint32 {
	if g.Confederation.Config.Enabled && !g.IsConfederation(peerAs) {
		return g.Confederation.Config.Identifier
	}
	return g.Config.As
}

func getConfigPeerType(peerAs, localAs uint32) PeerType {
	if peerAs != localAs {
		return PEER_TYPE_EXTERNAL
	}
	return PEER_TYPE_INTERNAL
}

func getConfigClusterId(g *Global, configClusterId netip.Addr) (netip.Addr, error) {
	if !configClusterId.IsValid() {
		return g.Config.RouterId, nil
	}
	if !configClusterId.Is4() {
		return netip.Addr{}, fmt.Errorf("route-reflector-cluster-id should be specified as IPv4 address")
	}
	return configClusterId, nil
}

func SetDefaultGlobalConfigValues(g *Global) error {
	if len(g.AfiSafis) == 0 {
		g.AfiSafis = []AfiSafi{}
		for k := range AfiSafiTypeToIntMap {
			g.AfiSafis = append(g.AfiSafis, defaultAfiSafi(k, true))
		}
	}

	if g.Config.Port == 0 {
		g.Config.Port = bgp.BGP_PORT
	}

	if len(g.Config.LocalAddressList) == 0 {
		g.Config.LocalAddressList = []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}
	}
	return nil
}

func setDefaultVrfConfigValues(v *Vrf) error {
	if v == nil {
		return fmt.Errorf("cannot set default values for nil vrf config")
	}

	if v.Config.Name == "" {
		return fmt.Errorf("specify vrf name")
	}

	_, err := bgp.ParseRouteDistinguisher(v.Config.Rd)
	if err != nil {
		return fmt.Errorf("invalid rd for vrf %s: %s", v.Config.Name, v.Config.Rd)
	}

	if len(v.Config.ImportRtList) == 0 {
		v.Config.ImportRtList = v.Config.BothRtList
	}
	for _, rtString := range v.Config.ImportRtList {
		_, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return fmt.Errorf("invalid import rt for vrf %s: %s", v.Config.Name, rtString)
		}
	}

	if len(v.Config.ExportRtList) == 0 {
		v.Config.ExportRtList = v.Config.BothRtList
	}
	for _, rtString := range v.Config.ExportRtList {
		_, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return fmt.Errorf("invalid export rt for vrf %s: %s", v.Config.Name, rtString)
		}
	}

	return nil
}

func SetDefaultConfigValues(b *BgpConfigSet) error {
	return setDefaultConfigValuesWithViper(nil, b)
}

func setDefaultPolicyConfigValuesWithViper(v *viper.Viper, p *PolicyDefinition) error {
	stmts, err := extractArray(v.Get("policy.statements"))
	if err != nil {
		return err
	}
	for i := range p.Statements {
		vv := viper.New()
		if len(stmts) > i {
			vv.Set("statement", stmts[i])
		}
		if !vv.IsSet("statement.actions.route-disposition") {
			p.Statements[i].Actions.RouteDisposition = ROUTE_DISPOSITION_NONE
		}
	}
	return nil
}

func setDefaultConfigValuesWithViper(v *viper.Viper, b *BgpConfigSet) error {
	if v == nil {
		v = viper.New()
	}

	if err := SetDefaultGlobalConfigValues(&b.Global); err != nil {
		return err
	}

	for idx, server := range b.BmpServers {
		if server.Config.SysName == "" {
			server.Config.SysName = "GoBGP"
		}
		if server.Config.SysDescr == "" {
			server.Config.SysDescr = version.Version()
		}
		if server.Config.Port == 0 {
			server.Config.Port = bmp.BMP_DEFAULT_PORT
		}
		if server.Config.RouteMonitoringPolicy == "" {
			server.Config.RouteMonitoringPolicy = BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY
		}
		// statistics-timeout is uint16 value and implicitly less than 65536
		if server.Config.StatisticsTimeout != 0 && server.Config.StatisticsTimeout < 15 {
			return fmt.Errorf("too small statistics-timeout value: %d", server.Config.StatisticsTimeout)
		}
		b.BmpServers[idx] = server
	}

	vrfNames := make(map[string]struct{})
	vrfIDs := make(map[uint32]struct{})
	for idx, vrf := range b.Vrfs {
		if err := setDefaultVrfConfigValues(&vrf); err != nil {
			return err
		}

		if _, ok := vrfNames[vrf.Config.Name]; ok {
			return fmt.Errorf("duplicated vrf name: %s", vrf.Config.Name)
		}
		vrfNames[vrf.Config.Name] = struct{}{}

		if vrf.Config.Id != 0 {
			if _, ok := vrfIDs[vrf.Config.Id]; ok {
				return fmt.Errorf("duplicated vrf id: %d", vrf.Config.Id)
			}
			vrfIDs[vrf.Config.Id] = struct{}{}
		}

		b.Vrfs[idx] = vrf
	}
	// Auto assign VRF identifier
	for idx, vrf := range b.Vrfs {
		if vrf.Config.Id == 0 {
			for id := uint32(1); id < math.MaxUint32; id++ {
				if _, ok := vrfIDs[id]; !ok {
					vrf.Config.Id = id
					vrfIDs[id] = struct{}{}
					break
				}
			}
		}
		b.Vrfs[idx] = vrf
	}

	if b.Zebra.Config.Url == "" {
		b.Zebra.Config.Url = "unix:/var/run/quagga/zserv.api"
	}
	if b.Zebra.Config.Version < zebra.MinZapiVer {
		b.Zebra.Config.Version = zebra.MinZapiVer
	} else if b.Zebra.Config.Version > zebra.MaxZapiVer {
		b.Zebra.Config.Version = zebra.MaxZapiVer
	}

	if !v.IsSet("zebra.config.nexthop-trigger-enable") && !b.Zebra.Config.NexthopTriggerEnable && b.Zebra.Config.Version > 2 {
		b.Zebra.Config.NexthopTriggerEnable = true
	}
	if b.Zebra.Config.NexthopTriggerDelay == 0 {
		b.Zebra.Config.NexthopTriggerDelay = 5
	}

	list, err := extractArray(v.Get("neighbors"))
	if err != nil {
		return err
	}

	for idx, n := range b.Neighbors {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("neighbor", list[idx])
		}

		pg, err := b.getPeerGroup(n.Config.PeerGroup)
		if err != nil {
			return nil
		}

		if pg != nil {
			// Derive the key from the neighbor itself rather than from viper.
			// The old code asserted the viper lookup to string, which panicked
			// on a neighbor carrying neither an address nor an interface, and it
			// registered interface peers under their interface name while
			// OverwriteNeighborConfigWithPeerGroup looked them up by address -
			// so interface peers never matched and the peer group won every
			// field for them. Using one helper in both places makes the two
			// halves impossible to drift apart.
			if key := NeighborPresenceKey(&n); key != "" {
				RegisterConfiguredFields(key, list[idx])
			}
		}

		if err := setDefaultNeighborConfigValuesWithViper(vv, &n, &b.Global, pg); err != nil {
			return err
		}
		b.Neighbors[idx] = n
	}

	for _, d := range b.DynamicNeighbors {
		if err := d.validate(b); err != nil {
			return err
		}
	}

	for idx, r := range b.RpkiServers {
		if r.Config.Port == 0 {
			b.RpkiServers[idx].Config.Port = rtr.RPKI_DEFAULT_PORT
		}
	}

	list, err = extractArray(v.Get("policy-definitions"))
	if err != nil {
		return err
	}

	for idx, p := range b.PolicyDefinitions {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("policy", list[idx])
		}
		if err := setDefaultPolicyConfigValuesWithViper(vv, &p); err != nil {
			return err
		}
		b.PolicyDefinitions[idx] = p
	}

	return nil
}

func OverwriteNeighborConfigWithPeerGroup(c *Neighbor, pg *PeerGroup) error {
	v := viper.New()

	val, ok := lookupConfiguredFields(NeighborPresenceKey(c))
	if ok {
		v.Set("neighbor", val)
	} else {
		v.Set("neighbor.config.peer-group", c.Config.PeerGroup)
	}

	// Record where each block ends up coming from, at the one point that knows.
	// A block the neighbor declared is the neighbor's; anything else that the
	// group actually carries is the group's.
	key := NeighborPresenceKey(c)
	for _, b := range []string{
		"timers", "transport", "error-handling", "logging-options", "ebgp-multihop",
		"route-reflector", "as-path-options", "add-paths", "graceful-restart",
		"apply-policy", "use-multiple-paths", "route-server", "ttl-security", "bfd",
	} {
		if v.IsSet("neighbor." + b + ".config") {
			recordProvenance(key, b, SourceNeighbor)
			continue
		}
		recordProvenance(key, b, SourcePeerGroup)
	}

	overwriteConfig(&c.Config, &pg.Config, "neighbor.config", v)
	overwriteConfig(&c.Timers.Config, &pg.Timers.Config, "neighbor.timers.config", v)
	overwriteConfig(&c.Transport.Config, &pg.Transport.Config, "neighbor.transport.config", v)
	overwriteConfig(&c.ErrorHandling.Config, &pg.ErrorHandling.Config, "neighbor.error-handling.config", v)
	overwriteConfig(&c.LoggingOptions.Config, &pg.LoggingOptions.Config, "neighbor.logging-options.config", v)
	overwriteConfig(&c.EbgpMultihop.Config, &pg.EbgpMultihop.Config, "neighbor.ebgp-multihop.config", v)
	overwriteConfig(&c.RouteReflector.Config, &pg.RouteReflector.Config, "neighbor.route-reflector.config", v)
	overwriteConfig(&c.AsPathOptions.Config, &pg.AsPathOptions.Config, "neighbor.as-path-options.config", v)
	overwriteConfig(&c.AddPaths.Config, &pg.AddPaths.Config, "neighbor.add-paths.config", v)
	overwriteConfig(&c.GracefulRestart.Config, &pg.GracefulRestart.Config, "neighbor.graceful-restart.config", v)
	overwriteConfig(&c.ApplyPolicy.Config, &pg.ApplyPolicy.Config, "neighbor.apply-policy.config", v)
	overwriteConfig(&c.UseMultiplePaths.Config, &pg.UseMultiplePaths.Config, "neighbor.use-multiple-paths.config", v)
	overwriteConfig(&c.RouteServer.Config, &pg.RouteServer.Config, "neighbor.route-server.config", v)
	overwriteConfig(&c.TtlSecurity.Config, &pg.TtlSecurity.Config, "neighbor.ttl-security.config", v)
	// BFD is per-field like everything else again. It was gated on the
	// neighbor's block being the zero value, because on the gRPC path there was
	// no field presence and a group with no bfd block erased a neighbor's
	// settings with its zeros.
	//
	// That gate could not express what its own comment claimed. BfdConfig{
	// Enabled: false } *is* the zero value, so a neighbor asking to opt out of
	// a group's BFD was read as having asked for nothing and inherited it
	// anyway; the documented opt-out only worked because a CRD happens to send
	// the port and the intervals too, which is what made the block non-empty.
	// Transposing it to the other blocks would have been worse - graceful
	// restart, route-server and ttl-security all carry their enable flag as the
	// zero-value-false field.
	//
	// The gRPC converters now record which blocks the client actually sent, so
	// presence is real on both paths and the heuristic is not needed.
	overwriteConfig(&c.Bfd.Config, &pg.Bfd.Config, "neighbor.bfd.config", v)

	if !v.IsSet("neighbor.afi-safis") {
		c.AfiSafis = append([]AfiSafi{}, pg.AfiSafis...)
	}

	return nil
}

// validateSendCommunity rejects a send-community value that is neither empty
// nor one of the four the OpenConfig enum defines. Empty means unconfigured.
//
// The TOML path rejects; the gRPC path in SendCommunityFromAPI coerces an
// out-of-range number to unconfigured instead. The asymmetry is deliberate: a
// bad string here is a human typo in a file, and silently meaning "no filtering"
// is the worst possible reading of it, whereas the API field was ignored
// entirely until now, so a client that has been pushing junk into it should keep
// working exactly as it did.
func validateSendCommunity(t CommunityType) error {
	if t == "" {
		return nil
	}
	if _, ok := CommunityTypeToIntMap[t]; !ok {
		return fmt.Errorf("invalid send-community %q: want standard, extended, both or none", t)
	}
	return nil
}

func overwriteConfig(c, pg any, tagPrefix string, v *viper.Viper) {
	nValue := reflect.Indirect(reflect.ValueOf(c))
	pgValue := reflect.Indirect(reflect.ValueOf(pg))
	pgType := reflect.Indirect(pgValue).Type()

	for i := range pgType.NumField() {
		field := pgType.Field(i).Name
		tag := tagPrefix + "." + pgType.Field(i).Tag.Get("mapstructure")
		if func() bool {
			return slices.Contains(forcedOverwrittenConfig, tag)
		}() || !v.IsSet(tag) {
			if nField := nValue.FieldByName(field); nField.IsValid() {
				nField.Set(pgValue.FieldByName(field))
			}
		}
	}
}
