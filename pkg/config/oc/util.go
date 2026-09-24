// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	tspb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"google.golang.org/protobuf/proto"
)

// Returns config file type by retrieving extension from the given path.
// If no corresponding type found, returns the given def as the default value.
func detectConfigFileType(path, def string) string {
	switch ext := filepath.Ext(path); ext {
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	default:
		return def
	}
}

// yaml is decoded as []interface{}
// but toml is decoded as []map[string]interface{}.
// currently, viper can't hide this difference.
// handle the difference here.
func extractArray(intf any) ([]any, error) {
	if intf != nil {
		list, ok := intf.([]any)
		if ok {
			return list, nil
		}
		l, ok := intf.([]map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid configuration: neither []interface{} nor []map[string]interface{}")
		}
		list = make([]any, 0, len(l))
		for _, m := range l {
			list = append(list, m)
		}
		return list, nil
	}
	return nil, nil
}

func getIPv6LinkLocalAddress(ifname string) (string, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return fmt.Sprintf("%s%%%s", ip.String(), ifname), nil
		}
	}
	return "", fmt.Errorf("no ipv6 link local address for %s", ifname)
}

func (b *BgpConfigSet) getPeerGroup(n string) (*PeerGroup, error) {
	if n == "" {
		return nil, nil
	}
	for _, pg := range b.PeerGroups {
		if n == pg.Config.PeerGroupName {
			return &pg, nil
		}
	}
	return nil, fmt.Errorf("no such peer-group: %s", n)
}

func (d *DynamicNeighbor) validate(b *BgpConfigSet) error {
	if d.Config.PeerGroup == "" {
		return fmt.Errorf("dynamic neighbor requires the peer group config")
	}

	if _, err := b.getPeerGroup(d.Config.PeerGroup); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(d.Config.Prefix.String()); err != nil {
		return fmt.Errorf("invalid dynamic neighbor prefix %s", d.Config.Prefix)
	}
	return nil
}

func (g *Global) IsConfederationMember(peerAS uint32) bool {
	return slices.Contains(g.Confederation.Config.MemberAsList, peerAS)
}

func (g *Global) IsConfederation(peerAS uint32) bool {
	if peerAS == g.Config.As {
		return true
	}
	return g.IsConfederationMember(peerAS)
}

func (n *Neighbor) IsEBGPPeer(g *Global) bool {
	return n.Config.PeerAs != n.Config.LocalAs
}

func (n *Neighbor) CreateRfMap() map[bgp.Family]bgp.BGPAddPathMode {
	rfMap := make(map[bgp.Family]bgp.BGPAddPathMode)
	for _, af := range n.AfiSafis {
		mode := bgp.BGP_ADD_PATH_NONE
		if af.AddPaths.State.Receive {
			mode |= bgp.BGP_ADD_PATH_RECEIVE
		}
		if af.AddPaths.State.SendMax > 0 {
			mode |= bgp.BGP_ADD_PATH_SEND
		}
		rfMap[af.State.Family] = mode
	}
	return rfMap
}

func (n *Neighbor) GetAfiSafi(family bgp.Family) *AfiSafi {
	for _, a := range n.AfiSafis {
		if string(a.Config.AfiSafiName) == family.String() {
			return &a
		}
	}
	return nil
}

func (n *Neighbor) ExtractNeighborAddress() (string, error) {
	addr := n.State.NeighborAddress
	if !addr.IsValid() {
		addr = n.Config.NeighborAddress
		if !addr.IsValid() {
			return "", fmt.Errorf("NeighborAddress is not configured")
		}
	}
	return addr.String(), nil
}

func (n *Neighbor) IsAddPathReceiveEnabled(family bgp.Family) bool {
	for _, af := range n.AfiSafis {
		if af.State.Family == family {
			return af.AddPaths.State.Receive
		}
	}
	return false
}

type AfiSafis []AfiSafi

func (c AfiSafis) ToRfList() ([]bgp.Family, error) {
	rfs := make([]bgp.Family, 0, len(c))
	for _, af := range c {
		rfs = append(rfs, af.State.Family)
	}
	return rfs, nil
}

func inSlice(n Neighbor, b []Neighbor) int {
	for i, nb := range b {
		if nb.State.NeighborAddress == n.State.NeighborAddress {
			return i
		}
	}
	return -1
}

func inVrfSlice(v Vrf, b []Vrf) int {
	for i, vb := range b {
		if vb.Config.Name == v.Config.Name {
			return i
		}
	}
	return -1
}

func existPeerGroup(n string, b []PeerGroup) int {
	for i, nb := range b {
		if nb.Config.PeerGroupName == n {
			return i
		}
	}
	return -1
}

func isAfiSafiChanged(x, y []AfiSafi) bool {
	if len(x) != len(y) {
		return true
	}
	m := make(map[string]AfiSafi)
	for i, e := range x {
		m[string(e.Config.AfiSafiName)] = x[i]
	}
	for _, e := range y {
		if v, ok := m[string(e.Config.AfiSafiName)]; !ok || !v.Config.Equal(&e.Config) || !v.AddPaths.Config.Equal(&e.AddPaths.Config) || !v.MpGracefulRestart.Config.Equal(&e.MpGracefulRestart.Config) {
			return true
		}
	}
	return false
}

func (n *Neighbor) NeedsResendOpenMessage(new *Neighbor) bool {
	// Three fields have no bearing on the OPEN message, so changing one must
	// not tear the session down - updateNeighbor applies them in place, and
	// soft-resets out where already-advertised routes were built under the old
	// setting. Before the first of these carve-outs, adopting send-community
	// flapped every session, which for a service-VIP DaemonSet means traffic
	// loss on every node. Through updatePeerGroup one edit to a group does it
	// to every member at once.
	//
	//   send-community    an egress attribute filter, applied per advertisement
	//   remove-private-as an egress AS_PATH rewrite, likewise
	//   description       copied to State and reported; never on the wire
	//
	// Everything else here does reach the wire or the socket and still resets:
	// peer-as is validated against the peer's OPEN, local-as is carried in
	// ours, auth-password is a TCP-MD5 socket option, send-software-version
	// emits a capability.
	//
	// Neutralise the fields on copies rather than enumerating the ones that do
	// matter: NeighborConfig is generated, so a field added by a future
	// regeneration must keep triggering a reset by default.
	lhs, rhs := n.Config, new.Config
	lhs.SendCommunity, rhs.SendCommunity = "", ""
	lhs.Description, rhs.Description = "", ""
	lhs.RemovePrivateAs, rhs.RemovePrivateAs = "", ""

	// route-server and route-reflector were in neither list: not here, and not
	// among the blocks updateNeighbor copies in place. So a change to either
	// was accepted, reported back as the old value - correctly, since the old
	// value was still the one in force - and did nothing at all.
	//
	// Both have to rebuild the session rather than apply in place, and for
	// different reasons.
	//
	// route-server sets peer.tableId at peer construction (peer.go:148), which
	// decides whether the peer's routes live in the global RIB or in its own.
	// Flipping it in place would leave the routes already installed in the
	// wrong table with nothing to move them.
	//
	// route-reflector does not touch tableId. RouteReflectorClient is stamped
	// into the peer's PeerInfo snapshot, and UpdatePathAttrs reads it from
	// there to decide whether ORIGINATOR_ID and CLUSTER_LIST survive
	// (path.go:339) and whether to add them (path.go:400). An in-place change
	// would leave the snapshot answering with the old value until the session
	// happened to flap - silent iBGP routing loops, which is the failure mode
	// route reflection's loop prevention exists to stop.
	//
	// deleteNeighbor/addNeighbor already does both correctly; only the
	// classification was missing.
	return !lhs.Equal(&rhs) ||
		!n.Transport.Config.Equal(&new.Transport.Config) ||
		!n.AddPaths.Config.Equal(&new.AddPaths.Config) ||
		!n.AsPathOptions.Config.Equal(&new.AsPathOptions.Config) ||
		!n.GracefulRestart.Config.Equal(&new.GracefulRestart.Config) ||
		isAfiSafiChanged(n.AfiSafis, new.AfiSafis) ||
		!n.EbgpMultihop.Config.Equal(&new.EbgpMultihop.Config) ||
		!n.RouteServer.Config.Equal(&new.RouteServer.Config) ||
		!n.RouteReflector.Config.Equal(&new.RouteReflector.Config) ||
		!n.TtlSecurity.Config.Equal(&new.TtlSecurity.Config)
}

// TODO: these regexp are duplicated in api
var _regexpPrefixMaskLengthRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func ParseMaskLength(prefix, mask string) (int, int, error) {
	p, err := netip.ParsePrefix(prefix)
	var rf bgp.Family
	if err != nil {
		p, err = bgp.ParseRTCPrefix(prefix)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid prefix: %s", prefix)
		}
		rf = bgp.RF_RTC_UC
	}
	if mask == "" {
		l := p.Bits()
		return l, l, nil
	}
	elems := _regexpPrefixMaskLengthRange.FindStringSubmatch(mask)
	if len(elems) != 3 {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	// we've already checked the range is sane by regexp
	min, _ := strconv.ParseUint(elems[1], 10, 8)
	max, _ := strconv.ParseUint(elems[2], 10, 8)
	if min > max {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	if rf == bgp.RF_RTC_UC {
		f := func(i uint64) bool {
			return i <= bgp.RouteTargetMembershipPrefixLen
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("rtc mask length range outside scope :%s", mask)
		}
	} else {
		f := func(i uint64) bool {
			return i <= uint64(p.Addr().BitLen())
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ip mask length range outside scope :%s", mask)
		}
	}
	return int(min), int(max), nil
}

// ToPrefix parses the ip-prefix or rtc-prefix field (mutually exclusive) into a netip.Prefix and family.
func (c *Prefix) ToPrefix() (netip.Prefix, bgp.Family, error) {
	if c.IpPrefix.IsValid() && c.RtcPrefix != "" {
		return netip.Prefix{}, 0, fmt.Errorf("ip-prefix and rtc-prefix are mutually exclusive")
	}
	switch {
	case c.IpPrefix.IsValid():
		rf := bgp.RF_IPv4_UC
		if c.IpPrefix.Addr().Is6() {
			rf = bgp.RF_IPv6_UC
		}
		return c.IpPrefix, rf, nil
	case c.RtcPrefix != "":
		pfx, err := bgp.ParseRTCPrefix(c.RtcPrefix)
		if err != nil {
			return netip.Prefix{}, 0, err
		}
		return pfx, bgp.RF_RTC_UC, nil
	default:
		return netip.Prefix{}, 0, fmt.Errorf("prefix requires ip-prefix or rtc-prefix")
	}
}

func extractFamilyFromConfigAfiSafi(c *AfiSafi) uint32 {
	if c == nil {
		return 0
	}
	// If address family value is already stored in AfiSafiState structure,
	// we prefer to use this value.
	if c.State.Family != 0 {
		return uint32(c.State.Family)
	}
	// In case that Neighbor structure came from CLI or gRPC, address family
	// value in AfiSafiState structure can be omitted.
	// Here extracts value from AfiSafiName field in AfiSafiConfig structure.
	if rf, err := bgp.GetFamily(string(c.Config.AfiSafiName)); err == nil {
		return uint32(rf)
	}
	// Ignores invalid address family name
	return 0
}

func newAfiSafiConfigFromConfigStruct(c *AfiSafi) *api.AfiSafiConfig {
	rf := extractFamilyFromConfigAfiSafi(c)
	family := bgp.Family(rf)
	return &api.AfiSafiConfig{
		Family:  &api.Family{Afi: api.Family_Afi(family.Afi()), Safi: api.Family_Safi(family.Safi())},
		Enabled: c.Config.Enabled,
	}
}

func newApplyPolicyFromConfigStruct(c *ApplyPolicy) *api.ApplyPolicy {
	f := func(t DefaultPolicyType) api.RouteAction {
		switch t {
		case DEFAULT_POLICY_TYPE_ACCEPT_ROUTE:
			return api.RouteAction_ROUTE_ACTION_ACCEPT
		case DEFAULT_POLICY_TYPE_REJECT_ROUTE:
			return api.RouteAction_ROUTE_ACTION_REJECT
		}
		return api.RouteAction_ROUTE_ACTION_UNSPECIFIED
	}
	applyPolicy := &api.ApplyPolicy{
		ImportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: f(c.Config.DefaultImportPolicy),
		},
		ExportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			DefaultAction: f(c.Config.DefaultExportPolicy),
		},
	}

	for _, pname := range c.Config.ImportPolicyList {
		applyPolicy.ImportPolicy.Policies = append(applyPolicy.ImportPolicy.Policies, &api.Policy{Name: pname})
	}
	for _, pname := range c.Config.ExportPolicyList {
		applyPolicy.ExportPolicy.Policies = append(applyPolicy.ExportPolicy.Policies, &api.Policy{Name: pname})
	}

	return applyPolicy
}

func newPrefixLimitFromConfigStruct(c *AfiSafi) *api.PrefixLimit {
	if c.PrefixLimit.Config.MaxPrefixes == 0 {
		return nil
	}
	return &api.PrefixLimit{
		Family:               &api.Family{Afi: api.Family_Afi(c.State.Family.Afi()), Safi: api.Family_Safi(c.State.Family.Safi())},
		MaxPrefixes:          c.PrefixLimit.Config.MaxPrefixes,
		ShutdownThresholdPct: uint32(c.PrefixLimit.Config.ShutdownThresholdPct),
	}
}

func newRouteTargetMembershipFromConfigStruct(c *RouteTargetMembership) *api.RouteTargetMembership {
	return &api.RouteTargetMembership{
		Config: &api.RouteTargetMembershipConfig{
			DeferralTime: uint32(c.Config.DeferralTime),
		},
	}
}

func newLongLivedGracefulRestartFromConfigStruct(c *LongLivedGracefulRestart) *api.LongLivedGracefulRestart {
	return &api.LongLivedGracefulRestart{
		Config: &api.LongLivedGracefulRestartConfig{
			Enabled:     c.Config.Enabled,
			RestartTime: c.Config.RestartTime,
		},
		State: &api.LongLivedGracefulRestartState{
			Enabled:                 c.State.Enabled,
			Received:                c.State.Received,
			Advertised:              c.State.Advertised,
			PeerRestartTime:         c.State.PeerRestartTime,
			PeerRestartTimerExpired: c.State.PeerRestartTimerExpired,
			Running:                 c.State.Running,
		},
	}
}

func newAddPathsFromConfigStruct(c *AddPaths) *api.AddPaths {
	return &api.AddPaths{
		Config: &api.AddPathsConfig{
			Receive: c.Config.Receive,
			SendMax: uint32(c.Config.SendMax),
		},
	}
}

func newMpGracefulRestartFromConfigStruct(c *MpGracefulRestart) *api.MpGracefulRestart {
	return &api.MpGracefulRestart{
		Config: &api.MpGracefulRestartConfig{
			Enabled: c.Config.Enabled,
		},
		State: &api.MpGracefulRestartState{
			Enabled:          c.State.Enabled,
			Received:         c.State.Received,
			Advertised:       c.State.Advertised,
			EndOfRibReceived: c.State.EndOfRibReceived,
			EndOfRibSent:     c.State.EndOfRibSent,
			Running:          c.State.Running,
		},
	}
}

func newAfiSafiFromConfigStruct(c *AfiSafi) *api.AfiSafi {
	return &api.AfiSafi{
		MpGracefulRestart:        newMpGracefulRestartFromConfigStruct(&c.MpGracefulRestart),
		Config:                   newAfiSafiConfigFromConfigStruct(c),
		ApplyPolicy:              newApplyPolicyFromConfigStruct(&c.ApplyPolicy),
		PrefixLimits:             newPrefixLimitFromConfigStruct(c),
		RouteTargetMembership:    newRouteTargetMembershipFromConfigStruct(&c.RouteTargetMembership),
		LongLivedGracefulRestart: newLongLivedGracefulRestartFromConfigStruct(&c.LongLivedGracefulRestart),
		AddPaths:                 newAddPathsFromConfigStruct(&c.AddPaths),
	}
}

// SendCommunityFromAPI converts an api send_community value to the internal
// CommunityType. A nil pointer means the field was not set, which is distinct
// from 0: 0 is COMMUNITY_TYPE_STANDARD. Without that distinction a peer that
// never configured the field would be read as asking for standard communities
// only, and gating on that would strip extended communities - route targets
// among them - from every existing session.
//
// An out-of-range value is treated as unset rather than rejected: the field was
// silently ignored entirely until now, so an existing client sending garbage
// into it should keep working exactly as it did.
func SendCommunityFromAPI(v *uint32) CommunityType {
	if v == nil {
		return ""
	}
	t, ok := IntToCommunityTypeMap[int(*v)]
	if !ok {
		return ""
	}
	return t
}

// SendCommunityToAPI is the inverse. An unset or unrecognised CommunityType
// returns nil so ListPeer reports absence rather than a fabricated 0, which
// would read as "standard".
func SendCommunityToAPI(t CommunityType) *uint32 {
	i, ok := CommunityTypeToIntMap[t]
	if !ok {
		return nil
	}
	v := uint32(i)
	return &v
}

func ProtoTimestamp(secs int64) *tspb.Timestamp {
	if secs == 0 {
		return nil
	}
	return tspb.New(time.Unix(secs, 0))
}

func toPeerType(t PeerType) api.PeerType {
	switch t {
	case PEER_TYPE_EXTERNAL:
		return api.PeerType_PEER_TYPE_EXTERNAL
	default:
		return api.PeerType_PEER_TYPE_INTERNAL
	}
}

// bfdSessionStateToAPI maps oc BfdSessionState string values to api.BfdSessionState.
// Do not cast BfdSessionState.ToInt() to the API enum: YANG-derived indices (0..3) are
// one less than protobuf values (BFD_SESSION_STATE_UP=1, etc.).
func bfdSessionStateToAPI(s BfdSessionState) api.BfdSessionState {
	switch s {
	case BFD_SESSION_STATE_UP:
		return api.BfdSessionState_BFD_SESSION_STATE_UP
	case BFD_SESSION_STATE_DOWN:
		return api.BfdSessionState_BFD_SESSION_STATE_DOWN
	case BFD_SESSION_STATE_ADMIN_DOWN:
		return api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN
	case BFD_SESSION_STATE_INIT:
		return api.BfdSessionState_BFD_SESSION_STATE_INIT
	default:
		return api.BfdSessionState_BFD_SESSION_STATE_UNSPECIFIED
	}
}

func bfdDiagnosticCodeToAPI(d BfdDiagnosticCode) api.BfdDiagnosticCode {
	i := d.ToInt()
	if i < 0 || i > int(api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_REVERSE_CONCATENATED_PATH_DOWN) {
		return api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC
	}
	return api.BfdDiagnosticCode(i)
}

// removePrivateToAPI maps the internal remove-private-as option to the API
// enum. It is a function rather than an inline switch in each converter because
// the peer path had one and the peer-group path had none: the group stored and
// applied the setting but never reported it, so a controller diffing desired
// against observed saw a permanent mismatch and re-issued UpdatePeerGroup
// forever - which loops updateNeighbor over every member.
func removePrivateToAPI(o RemovePrivateAsOption) api.RemovePrivate {
	switch o {
	case REMOVE_PRIVATE_AS_OPTION_ALL:
		return api.RemovePrivate_REMOVE_PRIVATE_ALL
	case REMOVE_PRIVATE_AS_OPTION_REPLACE:
		return api.RemovePrivate_REMOVE_PRIVATE_REPLACE
	}
	return api.RemovePrivate_REMOVE_PRIVATE_UNSPECIFIED
}

// addrOrEmpty reports an optional address. netip.Addr.String() renders the zero
// value as "invalid IP", which is worse than saying nothing.
func addrOrEmpty(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func NewPeerFromConfigStruct(pconf *Neighbor) *api.Peer {
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		if afiSafi := newAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	localAddress := pconf.Transport.Config.LocalAddress
	if pconf.Transport.State.LocalAddress.IsValid() {
		localAddress = pconf.Transport.State.LocalAddress
	}
	remoteCap, err := apiutil.MarshalCapabilities(pconf.State.RemoteCapabilityList)
	if err != nil {
		return nil
	}
	localCap, err := apiutil.MarshalCapabilities(pconf.State.LocalCapabilityList)
	if err != nil {
		return nil
	}
	removePrivate := removePrivateToAPI(pconf.Config.RemovePrivateAs)
	var admin_state api.PeerState_AdminState
	switch s.AdminState {
	case ADMIN_STATE_UP:
		admin_state = api.PeerState_ADMIN_STATE_UP
	case ADMIN_STATE_DOWN:
		admin_state = api.PeerState_ADMIN_STATE_DOWN
	case ADMIN_STATE_PFX_CT:
		admin_state = api.PeerState_ADMIN_STATE_PFX_CT
	}
	var sessionState api.PeerState_SessionState
	switch s.SessionState {
	case SESSION_STATE_IDLE:
		sessionState = api.PeerState_SESSION_STATE_IDLE
	case SESSION_STATE_CONNECT:
		sessionState = api.PeerState_SESSION_STATE_CONNECT
	case SESSION_STATE_ACTIVE:
		sessionState = api.PeerState_SESSION_STATE_ACTIVE
	case SESSION_STATE_OPENSENT:
		sessionState = api.PeerState_SESSION_STATE_OPENSENT
	case SESSION_STATE_OPENCONFIRM:
		sessionState = api.PeerState_SESSION_STATE_OPENCONFIRM
	case SESSION_STATE_ESTABLISHED:
		sessionState = api.PeerState_SESSION_STATE_ESTABLISHED
	}

	return &api.Peer{
		ApplyPolicy: newApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerConf{
			NeighborAddress:   pconf.Config.NeighborAddress.String(),
			PeerAsn:           pconf.Config.PeerAs,
			Type:              toPeerType(pconf.Config.PeerType),
			SendCommunity:     SendCommunityToAPI(pconf.Config.SendCommunity),
			PeerGroup:         pconf.Config.PeerGroup,
			NeighborInterface: pconf.Config.NeighborInterface,
			Vrf:               pconf.Config.Vrf,
			// Always reported, never nil on the read path: the resolved
			// configuration is a fact, and a client cannot tell "unset" from
			// "false" in a report anyway. Presence is for what a client sends.
			AllowOwnAsn:          proto.Uint32(uint32(pconf.AsPathOptions.Config.AllowOwnAs)),
			AllowAspathLoopLocal: proto.Bool(pconf.AsPathOptions.Config.AllowAsPathLoopLocal),
			RemovePrivate:        &removePrivate,
			ReplacePeerAsn:       proto.Bool(pconf.AsPathOptions.Config.ReplacePeerAs),
			AdminDown:            pconf.Config.AdminDown,
			LocalAsn:             proto.Uint32(pconf.Config.LocalAs),
			AuthPassword:         proto.String(pconf.Config.AuthPassword),
			Description:          proto.String(pconf.Config.Description),
			SendSoftwareVersion:  proto.Bool(pconf.Config.SendSoftwareVersion),
		},
		State: &api.PeerState{
			SessionState:  sessionState,
			AdminState:    admin_state,
			SendCommunity: SendCommunityToAPI(pconf.State.SendCommunity),
			// Computed here because this is the last point the password is
			// still present: ListPeer redacts Conf.AuthPassword before the peer
			// leaves the server, and PeerState.AuthPassword is never written by
			// anything, so bgp_peer_password_set read 0 for every peer whether
			// or not MD5 was configured. The flag only - PeerState.AuthPassword
			// stays unwritten, because unlike Conf it is not redacted anywhere
			// and would carry the key straight out through ListPeer and
			// `gobgp neighbor -j`.
			AuthPasswordSet: pconf.Config.AuthPassword != "",
			// Declared and reported by nothing. peer_group was worse than a
			// reporting gap - see default.go, where State.PeerGroup is now
			// populated because WatchEvent's peer-group filter reads it.
			Description:   pconf.State.Description,
			PeerGroup:     pconf.State.PeerGroup,
			RemovePrivate: removePrivate,
			Messages: &api.Messages{
				Received: &api.Message{
					Notification:   pconf.State.Messages.Received.Notification,
					Update:         pconf.State.Messages.Received.Update,
					Open:           pconf.State.Messages.Received.Open,
					Keepalive:      pconf.State.Messages.Received.Keepalive,
					Refresh:        pconf.State.Messages.Received.Refresh,
					Discarded:      pconf.State.Messages.Received.Discarded,
					Total:          pconf.State.Messages.Received.Total,
					WithdrawUpdate: uint64(pconf.State.Messages.Received.WithdrawUpdate),
					WithdrawPrefix: uint64(pconf.State.Messages.Received.WithdrawPrefix),
				},
				Sent: &api.Message{
					Notification: pconf.State.Messages.Sent.Notification,
					Update:       pconf.State.Messages.Sent.Update,
					Open:         pconf.State.Messages.Sent.Open,
					Keepalive:    pconf.State.Messages.Sent.Keepalive,
					Refresh:      pconf.State.Messages.Sent.Refresh,
					Discarded:    pconf.State.Messages.Sent.Discarded,
					Total:        pconf.State.Messages.Sent.Total,
					// The Received literal above has carried these since it was
					// written; this one did not, so even once the counters are
					// incremented the sent side would still report zero.
					WithdrawUpdate: uint64(pconf.State.Messages.Sent.WithdrawUpdate),
					WithdrawPrefix: uint64(pconf.State.Messages.Sent.WithdrawPrefix),
				},
			},
			PeerAsn:         s.PeerAs,
			LocalAsn:        s.LocalAs,
			Type:            toPeerType(s.PeerType),
			NeighborAddress: pconf.State.NeighborAddress.String(),
			// Output only. There is no receive queue to measure - inbound
			// messages are delivered by callback - so Queues.input is removed
			// from the proto rather than reported as a permanent zero.
			Queues:    &api.Queues{Output: s.Queues.Output},
			OutQ:      s.Queues.Output,
			RemoteCap: remoteCap,
			LocalCap:  localCap,
			RouterId:  s.RemoteRouterId.String(),
			Flops:     s.Flops,
			// Next hops used for netlink-imported routes on this session,
			// resolved when it came up. Declared since the netlink work landed
			// and never written, because nothing populated PeerInfo either.
			Ipv4Nexthop:          addrOrEmpty(s.Ipv4Nexthop),
			Ipv6Nexthop:          addrOrEmpty(s.Ipv6Nexthop),
			Ipv6LinkLocalNexthop: addrOrEmpty(s.Ipv6LinkLocalNexthop),
			BfdState: &api.BfdPeerState{
				SessionState:                 bfdSessionStateToAPI(pconf.Bfd.State.SessionState),
				RemoteSessionState:           bfdSessionStateToAPI(pconf.Bfd.State.RemoteSessionState),
				LastFailureTime:              pconf.Bfd.State.LastFailureTime,
				FailureTransitions:           pconf.Bfd.State.FailureTransitions,
				LocalDiscriminator:           pconf.Bfd.State.LocalDiscriminator,
				RemoteDiscriminator:          pconf.Bfd.State.RemoteDiscriminator,
				LocalDiagnosticCode:          bfdDiagnosticCodeToAPI(pconf.Bfd.State.LocalDiagnosticCode),
				RemoteDiagnosticCode:         bfdDiagnosticCodeToAPI(pconf.Bfd.State.RemoteDiagnosticCode),
				RemoteMinimumReceiveInterval: pconf.Bfd.State.RemoteMinimumReceiveInterval,
				BfdAsync: &api.BfdAsyncCounters{
					TransmittedPackets: pconf.Bfd.State.BfdAsync.TransmittedPackets,
					ReceivedPackets:    pconf.Bfd.State.BfdAsync.ReceivedPackets,
				},
			},
		},
		EbgpMultihop: &api.EbgpMultihop{
			Enabled:     pconf.EbgpMultihop.Config.Enabled,
			MultihopTtl: uint32(pconf.EbgpMultihop.Config.MultihopTtl),
		},
		TtlSecurity: &api.TtlSecurity{
			Enabled: pconf.TtlSecurity.Config.Enabled,
			TtlMin:  uint32(pconf.TtlSecurity.Config.TtlMin),
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           uint64(timer.Config.ConnectRetry),
				HoldTime:               uint64(timer.Config.HoldTime),
				KeepaliveInterval:      uint64(timer.Config.KeepaliveInterval),
				IdleHoldTimeAfterReset: uint64(timer.Config.IdleHoldTimeAfterReset),
			},
			State: &api.TimersState{
				KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
				NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
				Uptime:             ProtoTimestamp(timer.State.Uptime),
				Downtime:           ProtoTimestamp(timer.State.Downtime),
				// Declared since the model was generated and reported by
				// nothing, so a client asking for the timers in effect got two
				// of the four. Neither has a negotiated form - the negotiated
				// hold time is the separate field above - so the configured
				// value is the operative one.
				ConnectRetry: uint64(timer.Config.ConnectRetry),
				HoldTime:     uint64(timer.Config.HoldTime),
			},
		},
		RouteReflector: &api.RouteReflector{
			RouteReflectorClient:    pconf.RouteReflector.Config.RouteReflectorClient,
			RouteReflectorClusterId: pconf.RouteReflector.State.RouteReflectorClusterId.String(),
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
			SecondaryRoute:    pconf.RouteServer.Config.SecondaryRoute,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             pconf.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(pconf.GracefulRestart.Config.RestartTime),
			HelperOnly:          pconf.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(pconf.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: pconf.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    pconf.GracefulRestart.Config.LongLivedEnabled,
			StaleRoutesTime:     uint32(pconf.GracefulRestart.Config.StaleRoutesTime),
			LocalRestarting:     pconf.GracefulRestart.State.LocalRestarting,
			PeerRestartTime:     uint32(pconf.GracefulRestart.State.PeerRestartTime),
			PeerRestarting:      pconf.GracefulRestart.State.PeerRestarting,
		},
		Transport: &api.Transport{
			RemotePort:    uint32(pconf.Transport.Config.RemotePort),
			LocalPort:     uint32(pconf.Transport.Config.LocalPort),
			LocalAddress:  localAddress.String(),
			PassiveMode:   pconf.Transport.Config.PassiveMode,
			MtuDiscovery:  pconf.Transport.Config.MtuDiscovery,
			BindInterface: pconf.Transport.Config.BindInterface,
			TcpMss:        uint32(pconf.Transport.Config.TcpMss),
			IpTos:         uint32(pconf.Transport.Config.IpTos),
		},
		AfiSafis: afiSafis,
		Bfd: &api.BfdPeerConfig{
			Enabled:                  pconf.Bfd.Config.Enabled,
			Port:                     uint32(pconf.Bfd.Config.Port),
			DesiredMinimumTxInterval: pconf.Bfd.Config.DesiredMinimumTxInterval,
			RequiredMinimumReceive:   pconf.Bfd.Config.RequiredMinimumReceive,
			DetectionMultiplier:      uint32(pconf.Bfd.Config.DetectionMultiplier),
		},
	}
}

func NewTcpAoKeychainsFromConfigStruct(chains []Keychain) ([]*api.TcpAoKeychain, error) {
	result := make([]*api.TcpAoKeychain, 0, len(chains))
	names := make(map[string]struct{}, len(chains))
	for i := range chains {
		chain, err := newTcpAoKeychainFromConfigStruct(&chains[i])
		if err != nil {
			return nil, err
		}
		if _, ok := names[chain.Name]; ok {
			return nil, fmt.Errorf("duplicate TCP-AO keychain %q", chain.Name)
		}
		names[chain.Name] = struct{}{}
		result = append(result, chain)
	}
	return result, nil
}

func newTcpAoKeychainFromConfigStruct(chain *Keychain) (*api.TcpAoKeychain, error) {
	name := chain.Config.Name
	if name == "" {
		return nil, fmt.Errorf("TCP-AO keychain name is required")
	}
	result := &api.TcpAoKeychain{
		Name: name,
		Keys: make([]*api.TcpAoKey, 0, len(chain.Keys)),
	}
	for i, key := range chain.Keys {
		masterKey, err := readTcpAoMasterKey(key.Config.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("TCP-AO keychain %q key %d: %w", name, i, err)
		}
		algorithm, err := tcpAoAlgorithmToAPI(key.Config.CryptoAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("TCP-AO keychain %q key %d: %w", name, i, err)
		}
		result.Keys = append(result.Keys, &api.TcpAoKey{
			SendId:            uint32(key.Config.KeyId),
			ReceiveId:         uint32(key.Config.ReceiveId),
			Algorithm:         algorithm,
			ExcludeTcpOptions: key.Config.ExcludeTcpOptions,
			MasterKey:         masterKey,
		})
	}
	return result, nil
}

func tcpAoAlgorithmToAPI(algorithm CryptoType) (api.TcpAoAlgorithm, error) {
	switch algorithm {
	case CRYPTO_TYPE_HMAC_SHA_1_96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, nil
	case CRYPTO_TYPE_AES_128_CMAC_96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, nil
	case CRYPTO_TYPE_HMAC_SHA_256_96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96, nil
	case CRYPTO_TYPE_HMAC_SHA_256_128:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128, nil
	default:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

func readTcpAoMasterKey(secretKey string) ([]byte, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("secret-key is required")
	}
	masterKey, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return nil, fmt.Errorf("secret-key must be base64 encoded: %w", err)
	}
	return masterKey, nil
}

func NewPeerGroupFromConfigStruct(pconf *PeerGroup) *api.PeerGroup {
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		if afiSafi := newAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafi.AddPaths.Config.Receive = pconf.AddPaths.Config.Receive
			afiSafi.AddPaths.Config.SendMax = uint32(pconf.AddPaths.Config.SendMax)
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	return &api.PeerGroup{
		ApplyPolicy: newApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerGroupConf{
			PeerAsn:              pconf.Config.PeerAs,
			LocalAsn:             pconf.Config.LocalAs,
			Type:                 toPeerType(pconf.Config.PeerType),
			AuthPassword:         pconf.Config.AuthPassword,
			SendCommunity:        SendCommunityToAPI(pconf.Config.SendCommunity),
			RemovePrivate:        removePrivateToAPI(pconf.Config.RemovePrivateAs),
			Description:          pconf.Config.Description,
			PeerGroupName:        pconf.Config.PeerGroupName,
			SendSoftwareVersion:  pconf.Config.SendSoftwareVersion,
			AllowOwnAsn:          uint32(pconf.AsPathOptions.Config.AllowOwnAs),
			ReplacePeerAsn:       pconf.AsPathOptions.Config.ReplacePeerAs,
			AllowAspathLoopLocal: pconf.AsPathOptions.Config.AllowAsPathLoopLocal,
		},
		Info: &api.PeerGroupState{
			PeerAsn:       s.PeerAs,
			Type:          toPeerType(s.PeerType),
			SendCommunity: SendCommunityToAPI(s.SendCommunity),
			TotalPaths:    s.TotalPaths,
			TotalPrefixes: s.TotalPrefixes,
			// Declared and reported by nothing, so a client reading a peer
			// group back got five of eleven fields. The values are all in
			// pconf.State already.
			//
			// auth_password is deliberately left out and removed from the
			// proto instead: ListPeer redacts the neighbor's copy, so
			// reporting the group's here would hand out the key ListPeer
			// exists to withhold.
			LocalAsn:      s.LocalAs,
			Description:   s.Description,
			PeerGroupName: s.PeerGroupName,
			RemovePrivate: removePrivateToAPI(s.RemovePrivateAs),
		},
		EbgpMultihop: &api.EbgpMultihop{
			Enabled:     pconf.EbgpMultihop.Config.Enabled,
			MultihopTtl: uint32(pconf.EbgpMultihop.Config.MultihopTtl),
		},
		TtlSecurity: &api.TtlSecurity{
			Enabled: pconf.TtlSecurity.Config.Enabled,
			TtlMin:  uint32(pconf.TtlSecurity.Config.TtlMin),
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           uint64(timer.Config.ConnectRetry),
				HoldTime:               uint64(timer.Config.HoldTime),
				KeepaliveInterval:      uint64(timer.Config.KeepaliveInterval),
				IdleHoldTimeAfterReset: uint64(timer.Config.IdleHoldTimeAfterReset),
			},
			State: &api.TimersState{
				KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
				NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
				Uptime:             ProtoTimestamp(timer.State.Uptime),
				Downtime:           ProtoTimestamp(timer.State.Downtime),
				// Declared since the model was generated and reported by
				// nothing, so a client asking for the timers in effect got two
				// of the four. Neither has a negotiated form - the negotiated
				// hold time is the separate field above - so the configured
				// value is the operative one.
				ConnectRetry: uint64(timer.Config.ConnectRetry),
				HoldTime:     uint64(timer.Config.HoldTime),
			},
		},
		RouteReflector: &api.RouteReflector{
			RouteReflectorClient:    pconf.RouteReflector.Config.RouteReflectorClient,
			RouteReflectorClusterId: pconf.RouteReflector.Config.RouteReflectorClusterId.String(),
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
			SecondaryRoute:    pconf.RouteServer.Config.SecondaryRoute,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             pconf.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(pconf.GracefulRestart.Config.RestartTime),
			HelperOnly:          pconf.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(pconf.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: pconf.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    pconf.GracefulRestart.Config.LongLivedEnabled,
			StaleRoutesTime:     uint32(pconf.GracefulRestart.Config.StaleRoutesTime),
			LocalRestarting:     pconf.GracefulRestart.State.LocalRestarting,
		},
		Transport: &api.Transport{
			RemotePort:    uint32(pconf.Transport.Config.RemotePort),
			LocalAddress:  pconf.Transport.Config.LocalAddress.String(),
			PassiveMode:   pconf.Transport.Config.PassiveMode,
			MtuDiscovery:  pconf.Transport.Config.MtuDiscovery,
			BindInterface: pconf.Transport.Config.BindInterface,
			TcpMss:        uint32(pconf.Transport.Config.TcpMss),
			IpTos:         uint32(pconf.Transport.Config.IpTos),
		},
		AfiSafis: afiSafis,
		Bfd: &api.BfdPeerConfig{
			Enabled:                  pconf.Bfd.Config.Enabled,
			Port:                     uint32(pconf.Bfd.Config.Port),
			DesiredMinimumTxInterval: pconf.Bfd.Config.DesiredMinimumTxInterval,
			RequiredMinimumReceive:   pconf.Bfd.Config.RequiredMinimumReceive,
			DetectionMultiplier:      uint32(pconf.Bfd.Config.DetectionMultiplier),
		},
	}
}

func NewGlobalFromConfigStruct(c *Global) *api.Global {
	families := make([]uint32, 0, len(c.AfiSafis))
	for _, f := range c.AfiSafis {
		families = append(families, uint32(AfiSafiTypeToIntMap[f.Config.AfiSafiName]))
	}

	l := make([]string, 0, len(c.Config.LocalAddressList))
	for _, addr := range c.Config.LocalAddressList {
		l = append(l, addr.String())
	}

	return &api.Global{
		Asn:              c.Config.As,
		RouterId:         c.Config.RouterId.String(),
		ListenPort:       c.Config.Port,
		ListenAddresses:  l,
		Families:         families,
		UseMultiplePaths: c.UseMultiplePaths.Config.Enabled,
		BindToDevice:     c.Config.BindToDevice,

		GracefulRestartInheritToNeighbors: c.Config.GracefulRestartInheritToNeighbors,

		// The config file reaches StartBgp through this struct, so a limit
		// not carried here never reaches the daemon at all.
		EbgpMaximumPaths: c.UseMultiplePaths.Ebgp.Config.MaximumPaths,
		IbgpMaximumPaths: c.UseMultiplePaths.Ibgp.Config.MaximumPaths,

		RouteSelectionOptions: &api.RouteSelectionOptionsConfig{
			AlwaysCompareMed:         c.RouteSelectionOptions.Config.AlwaysCompareMed,
			IgnoreAsPathLength:       c.RouteSelectionOptions.Config.IgnoreAsPathLength,
			ExternalCompareRouterId:  c.RouteSelectionOptions.Config.ExternalCompareRouterId,
			AdvertiseInactiveRoutes:  c.RouteSelectionOptions.Config.AdvertiseInactiveRoutes,
			EnableAigp:               c.RouteSelectionOptions.Config.EnableAigp,
			IgnoreNextHopIgpMetric:   c.RouteSelectionOptions.Config.IgnoreNextHopIgpMetric,
			DisableBestPathSelection: c.RouteSelectionOptions.Config.DisableBestPathSelection,
		},
		DefaultRouteDistance: &api.DefaultRouteDistance{
			ExternalRouteDistance: uint32(c.DefaultRouteDistance.Config.ExternalRouteDistance),
			InternalRouteDistance: uint32(c.DefaultRouteDistance.Config.InternalRouteDistance),
		},
		Confederation: &api.Confederation{
			Enabled:      c.Confederation.Config.Enabled,
			Identifier:   c.Confederation.Config.Identifier,
			MemberAsList: c.Confederation.Config.MemberAsList,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             c.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(c.GracefulRestart.Config.RestartTime),
			StaleRoutesTime:     uint32(c.GracefulRestart.Config.StaleRoutesTime),
			HelperOnly:          c.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(c.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: c.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    c.GracefulRestart.Config.LongLivedEnabled,
		},
	}
}

func newAPIPrefixFromConfigStruct(c Prefix) (*api.Prefix, error) {
	prefix := c.RtcPrefix
	if c.IpPrefix.IsValid() {
		prefix = c.IpPrefix.String()
	}
	min, max, err := ParseMaskLength(prefix, c.MasklengthRange)
	if err != nil {
		return nil, err
	}
	ipPrefix := ""
	if c.IpPrefix.IsValid() {
		ipPrefix = c.IpPrefix.String()
	}
	return &api.Prefix{
		IpPrefix:      ipPrefix,
		RtcPrefix:     c.RtcPrefix,
		MaskLengthMin: uint32(min),
		MaskLengthMax: uint32(max),
	}, nil
}

func NewAPIDefinedSetsFromConfigStruct(t *DefinedSets) ([]*api.DefinedSet, error) {
	definedSets := make([]*api.DefinedSet, 0)

	for _, ps := range t.PrefixSets {
		prefixes := make([]*api.Prefix, 0)
		for _, p := range ps.PrefixList {
			ap, err := newAPIPrefixFromConfigStruct(p)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, ap)
		}
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        ps.PrefixSetName,
			Prefixes:    prefixes,
		})
	}

	for _, ns := range t.NeighborSets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        ns.NeighborSetName,
			List:        ns.NeighborInfoList,
		})
	}

	bs := t.BgpDefinedSets
	for _, cs := range bs.CommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
			Name:        cs.CommunitySetName,
			List:        cs.CommunityList,
		})
	}

	for _, es := range bs.ExtCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY,
			Name:        es.ExtCommunitySetName,
			List:        es.ExtCommunityList,
		})
	}

	for _, ls := range bs.LargeCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY,
			Name:        ls.LargeCommunitySetName,
			List:        ls.LargeCommunityList,
		})
	}

	for _, as := range bs.AsPathSets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_AS_PATH,
			Name:        as.AsPathSetName,
			List:        as.AsPathList,
		})
	}

	return definedSets, nil
}

// BFD timing floor. The plan's CFS arithmetic: under limits.cpu 500m, Go gives
// GOMAXPROCS=2 and the quota exhausts after ~25ms, leaving a ~75ms worst-case
// freeze. Against a 900ms detection time that stall is 8% of the budget; at
// 300ms detection it is 25%, and at 150ms it is 50% and no longer viable.
//
// So 300ms x 3 is the fastest profile that survives a scheduling stall on a
// CPU-limited node. Anything faster needs requests.cpu == limits.cpu, which is
// a deployment decision this daemon cannot verify, so the knob is bounded here
// rather than shipped open.
const (
	BfdMinIntervalMicros      = 300000
	BfdMinDetectionMultiplier = 3
)

// Validate rejects BFD timings below the supported profile.
//
// The units are the trap this exists to catch. The YANG declares these in
// microseconds and the generated Go drops the `units` comment, so `300` written
// by someone thinking in milliseconds is 300us - roughly 3,300 packets a second
// per peer. The error says so explicitly rather than reporting a bare bound.
func (c *BfdConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.DetectionMultiplier < BfdMinDetectionMultiplier {
		return fmt.Errorf("bfd detection-multiplier %d is below the minimum of %d: "+
			"a lower multiplier expires the session on a single lost packet",
			c.DetectionMultiplier, BfdMinDetectionMultiplier)
	}
	for _, f := range []struct {
		name  string
		value uint32
	}{
		{"desired-minimum-tx-interval", c.DesiredMinimumTxInterval},
		{"required-minimum-receive", c.RequiredMinimumReceive},
	} {
		if f.value < BfdMinIntervalMicros {
			return fmt.Errorf("bfd %s is %d microseconds (%v), below the minimum of %d (%v); "+
				"note these intervals are in MICROSECONDS, so 300ms is %d, not 300",
				f.name, f.value, time.Duration(f.value)*time.Microsecond,
				BfdMinIntervalMicros, time.Duration(BfdMinIntervalMicros)*time.Microsecond,
				BfdMinIntervalMicros)
		}
	}
	return nil
}
