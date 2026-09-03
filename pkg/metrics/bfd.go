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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// BFD is the subsystem an operator depends on for sub-second failure detection,
// and until now it had no Prometheus surface at all - the one liveness-critical
// path in a daemon that meters its own route-dampening counter.
//
// The gap was not that the counters did not exist. bfdServer already maintained
// every one of these, correctly, on the receive path; they were simply
// unreachable, because BgpServer.GetBfdServerStats had no caller and api.BfdState
// is referenced by no RPC. The collector runs in-process, so it can read them
// directly, the same way netlinkCollector reads NetlinkStats.
//
// bfd_unknown_peer_total is the one to watch. It counts control packets that
// arrived for an address the BFD server has no peer for, which is what happens
// when a link-local neighbor is configured without its zone: the kernel reports
// the source as fe80::1%eth0, the configured key is fe80::1, netip.Addr equality
// includes the zone, and the lookup misses. Transmit still works if the peer has
// a bind-interface, so BGP stays up and healthy-looking while BFD never leaves
// DOWN. Nothing else in the daemon reports it above DEBUG.
var (
	bfdReceivedPacketTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "bfd", "received_packet_total"),
		"BFD control packets received and matched to a peer.", nil, nil)
	bfdReceivedDropTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "bfd", "received_drop_total"),
		"BFD control packets dropped because the peer's receive queue was full. "+
			"The queue is one packet deep, so this advancing means the peer's event "+
			"loop stalled longer than one transmit interval.", nil, nil)
	bfdReceivedErrorTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "bfd", "received_error_total"),
		"Errors reading from the BFD server socket.", nil, nil)
	bfdInvalidPacketTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "bfd", "invalid_packet_total"),
		"Received datagrams that could not be decoded as a BFD control packet.", nil, nil)
	bfdUnknownPeerTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "bfd", "unknown_peer_total"),
		"BFD control packets received from an address with no configured peer. "+
			"Advancing while a peer is configured but stuck DOWN indicates an address "+
			"mismatch, typically a link-local neighbor configured without its zone.", nil, nil)
)

// Per-peer BFD series. These live here rather than in metrics.go so the whole
// BFD surface is in one file, but they are emitted from the bgpCollector's
// ListPeer loop, which already carries the api.Peer these read from.
var (
	bfdPeerStateLabels = []string{"peer", "session_state", "remote_session_state"}

	bgpPeerBfdEnabledDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "bfd_enabled"),
		"Whether BFD is configured for this peer (1) or not (0).",
		peerLabels, nil)
	bgpPeerBfdStateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "bfd_state"),
		"Current BFD session state for this peer, as a label. Always 1; read the "+
			"session_state label. Alert on bfd_enabled == 1 without a matching "+
			"bfd_state{session_state=\"BFD_SESSION_STATE_UP\"}.",
		bfdPeerStateLabels, nil)
	bgpPeerBfdTransmittedPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "bfd_transmitted_packets_total"),
		"BFD control packets sent to this peer.", peerLabels, nil)
	bgpPeerBfdReceivedPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "bfd_received_packets_total"),
		"BFD control packets received from this peer. Flat while "+
			"bfd_transmitted_packets_total advances means our packets are leaving but "+
			"theirs are not being matched to this peer.", peerLabels, nil)
	bgpPeerBfdFailureTransitionsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "bfd_failure_transitions_total"),
		"Times this BFD session has gone from up to down.", peerLabels, nil)
)

type bfdCollector struct {
	server *server.BgpServer
}

// NewBfdCollector exposes the BFD server's receive-path counters to Prometheus.
func NewBfdCollector(s *server.BgpServer) prometheus.Collector {
	return &bfdCollector{server: s}
}

func (c *bfdCollector) Describe(out chan<- *prometheus.Desc) {
	out <- bfdReceivedPacketTotalDesc
	out <- bfdReceivedDropTotalDesc
	out <- bfdReceivedErrorTotalDesc
	out <- bfdInvalidPacketTotalDesc
	out <- bfdUnknownPeerTotalDesc
}

func (c *bfdCollector) Collect(out chan<- prometheus.Metric) {
	s := c.server.GetBfdServerStats()
	if s == nil {
		// Defensive only: NewBgpServer always constructs a bfdServer, so this is
		// unreachable for a server built the normal way. Emitting nothing beats
		// panicking if that ever changes.
		return
	}

	// These are emitted even when no peer has BFD enabled. The server object
	// always exists, so zeroes here honestly mean "nothing received"; whether BFD
	// is meant to be running is answered by bgp_peer_bfd_enabled, not by these.

	counter := func(d *prometheus.Desc, v uint64) {
		out <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}

	counter(bfdReceivedPacketTotalDesc, s.GetReceivedPacket())
	counter(bfdReceivedDropTotalDesc, s.GetReceivedDrop())
	counter(bfdReceivedErrorTotalDesc, s.GetReceivedError())
	counter(bfdInvalidPacketTotalDesc, s.GetInvalidPacket())
	counter(bfdUnknownPeerTotalDesc, s.GetUnknownPeer())
}

// describePeerBfd advertises the per-peer BFD series. Called from the
// bgpCollector's Describe.
func describePeerBfd(out chan<- *prometheus.Desc) {
	out <- bgpPeerBfdEnabledDesc
	out <- bgpPeerBfdStateDesc
	out <- bgpPeerBfdTransmittedPacketsDesc
	out <- bgpPeerBfdReceivedPacketsDesc
	out <- bgpPeerBfdFailureTransitionsDesc
}

// collectPeerBfd emits the per-peer BFD series for one peer. Called from the
// bgpCollector's ListPeer loop.
//
// bfd_enabled is emitted for every peer, including those with BFD off, so that
// "configured but never coming up" is expressible as a query rather than as an
// absence of series.
func collectPeerBfd(out chan<- prometheus.Metric, p *api.Peer, peerAddr string) {
	enabled := 0.0
	if p.GetBfd().GetEnabled() {
		enabled = 1.0
	}
	out <- prometheus.MustNewConstMetric(
		bgpPeerBfdEnabledDesc, prometheus.GaugeValue, enabled, peerAddr)

	if !p.GetBfd().GetEnabled() {
		return
	}

	state := p.GetState().GetBfdState()
	out <- prometheus.MustNewConstMetric(
		bgpPeerBfdStateDesc, prometheus.GaugeValue, 1.0,
		peerAddr,
		state.GetSessionState().String(),
		state.GetRemoteSessionState().String(),
	)

	async := state.GetBfdAsync()
	out <- prometheus.MustNewConstMetric(
		bgpPeerBfdTransmittedPacketsDesc, prometheus.CounterValue,
		float64(async.GetTransmittedPackets()), peerAddr)
	out <- prometheus.MustNewConstMetric(
		bgpPeerBfdReceivedPacketsDesc, prometheus.CounterValue,
		float64(async.GetReceivedPackets()), peerAddr)
	out <- prometheus.MustNewConstMetric(
		bgpPeerBfdFailureTransitionsDesc, prometheus.CounterValue,
		float64(state.GetFailureTransitions()), peerAddr)
}
