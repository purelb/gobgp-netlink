package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

type fsmTimingsCollector struct {
	timingHistograms, waitHistograms []prometheus.Histogram
}

type FSMTimingsCollector interface {
	server.FSMTimingHook
	prometheus.Collector
}

var (
	fsmOperationInfixes = [server.FSMOperationTypeCount]string{
		"mgmt_op",
		"accept",
		"event",
		"message",
	}

	fsmOperationDescriptions = [server.FSMOperationTypeCount]string{
		"management operation",
		"TCP accept",
		"event",
		"BGP message",
	}
)

func NewFSMTimingsCollector() FSMTimingsCollector {
	const namespace = "fsm_loop"
	c := &fsmTimingsCollector{
		timingHistograms: make([]prometheus.Histogram, server.FSMOperationTypeCount),
		waitHistograms:   make([]prometheus.Histogram, server.FSMOperationTypeCount),
	}

	fsmHistograms := make([]prometheus.Histogram, server.FSMOperationTypeCount)
	for i := range fsmHistograms {
		c.timingHistograms[i] = prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    prometheus.BuildFQName(namespace, fsmOperationInfixes[i], "timing_sec"),
			Help:    fmt.Sprintf("Histogram of %s timings", fsmOperationDescriptions[i]),
			Buckets: prometheus.DefBuckets,
		})
		c.waitHistograms[i] = prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    prometheus.BuildFQName(namespace, fsmOperationInfixes[i], "wait_sec"),
			Help:    fmt.Sprintf("Histogram of %s channel delays", fsmOperationDescriptions[i]),
			Buckets: prometheus.DefBuckets,
		})
	}
	return c
}

func (f *fsmTimingsCollector) Observe(op server.FSMOperation, tOp, tWait time.Duration) {
	f.timingHistograms[op].Observe(tOp.Seconds())
	if tWait != 0 {
		f.waitHistograms[op].Observe(tWait.Seconds())
	}
}

func (f *fsmTimingsCollector) Describe(descs chan<- *prometheus.Desc) {
	for _, histogramList := range [][]prometheus.Histogram{f.timingHistograms, f.waitHistograms} {
		for _, h := range histogramList {
			h.Describe(descs)
		}
	}
}

func (f *fsmTimingsCollector) Collect(metrics chan<- prometheus.Metric) {
	for _, histogramList := range [][]prometheus.Histogram{f.timingHistograms, f.waitHistograms} {
		for _, h := range histogramList {
			h.Collect(metrics)
		}
	}
}

type bgpCollector struct {
	server *server.BgpServer
	// advertisedRoutes controls whether ListPeer is asked for the advertised
	// count. Computing it runs getPossibleBest and filterpath over every
	// destination with the export policy applied, per peer per family, which is
	// O(peers x families x |RIB|) - and it happens under the BGP write lock.
	advertisedRoutes bool
}

const (
	// Global namespace of the metrics
	namespace = "bgp"
)

var (
	// Labels appended to the metrics
	peerLabels         = []string{"peer"}
	peerRouterIdLabels = []string{"peer", "router_id"}
	peerStateLabels    = []string{"peer", "session_state", "admin_state"}
	rfLabels           = []string{"peer", "route_family"}

	bgpReceivedUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "update_total"),
		"Number of received BGP UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpReceivedNotificationTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "notification_total"),
		"Number of received BGP NOTIFICATION messages from peer",
		peerLabels, nil,
	)
	bgpReceivedOpenTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "open_total"),
		"Number of received BGP OPEN messages from peer",
		peerLabels, nil,
	)
	bgpReceivedRefreshTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "refresh_total"),
		"Number of received BGP REFRESH messages from peer",
		peerLabels, nil,
	)
	bgpReceivedKeepaliveTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "keepalive_total"),
		"Number of received BGP KEEPALIVE messages from peer",
		peerLabels, nil,
	)
	bgpReceivedWithdrawUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "withdraw_update_total"),
		"Number of received BGP WITHDRAW-UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpReceivedWithdrawPrefixTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "withdraw_prefix_total"),
		"Number of received BGP WITHDRAW-PREFIX messages from peer",
		peerLabels, nil,
	)
	bgpReceivedDiscardedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "discarded_total"),
		"Number of discarded BGP messages from peer",
		peerLabels, nil,
	)
	bgpReceivedMessageTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "message_total"),
		"Number of received BGP messages from peer",
		peerLabels, nil,
	)

	bgpSentUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "update_total"),
		"Number of sent BGP UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpSentNotificationTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "notification_total"),
		"Number of sent BGP NOTIFICATION messages from peer",
		peerLabels, nil,
	)
	bgpSentOpenTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "open_total"),
		"Number of sent BGP OPEN messages from peer",
		peerLabels, nil,
	)
	bgpSentRefreshTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "refresh_total"),
		"Number of sent BGP REFRESH messages from peer",
		peerLabels, nil,
	)
	bgpSentKeepaliveTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "keepalive_total"),
		"Number of sent BGP KEEPALIVE messages from peer",
		peerLabels, nil,
	)
	bgpSentWithdrawUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "withdraw_update_total"),
		"Number of sent BGP WITHDRAW-UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpSentWithdrawPrefixTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "withdraw_prefix_total"),
		"Number of sent BGP WITHDRAW-PREFIX messages from peer",
		peerLabels, nil,
	)
	bgpSentDiscardedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "discarded_total"),
		"Number of discarded BGP messages to peer", peerLabels,
		nil,
	)
	bgpSentMessageTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "message_total"),
		"Number of sent BGP messages from peer", peerLabels,
		nil,
	)

	bgpPeerOutQueueDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "out_queue_count"),
		"Length of the outgoing message queue",
		peerLabels, nil,
	)
	bgpPeerFlopsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "flop_count"),
		"Number of flops with the peer",
		peerLabels, nil,
	)
	// Renamed from bgp_peer_uptime. TimersState.uptime is a
	// google.protobuf.Timestamp and this always emitted the absolute epoch
	// second, while the help text said "for how long the peer has been in its
	// current state" - so every consumer reasonably wrote time() - uptime, and
	// a peer that had never established emitted 0 and read as 56 years up. The
	// name now says what the value is.
	bgpPeerEstablishedTimestampDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "established_timestamp_seconds"),
		"Unix timestamp at which the session was most recently established. "+
			"Not removed when the session goes down, so gate on bgp_peer_state "+
			"rather than reading this alone.",
		peerLabels, nil,
	)
	bgpPeerSendCommunityFlagDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "send_community"),
		"BGP community with the peer",
		peerLabels, nil,
	)
	bgpPeerRemovePrivateAsFlagDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "remove_private_as"),
		"Do we remove private ASNs from the paths sent to the peer",
		peerLabels, nil,
	)
	bgpPeerPasswordSetFlagDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "password_set"),
		"Whether the GoBGP peer has been configured (1) for authentication or not (0)",
		peerLabels, nil,
	)
	bgpPeerTypeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "type"),
		"Type of the BGP peer, internal (0) or external (1)",
		peerLabels, nil,
	)
	bgpPeerAsnDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "asn"),
		"What is the AS number of the peer",
		peerRouterIdLabels, nil,
	)
	bgpPeerLocalAsnDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "local_asn"),
		"What is the AS number presented to the peer by this router",
		peerRouterIdLabels, nil,
	)
	bgpPeerStateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "state"),
		"State of the BGP session with peer and its administrative state",
		peerStateLabels, nil,
	)

	bgpRoutesReceivedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "routes", "received"),
		"Number of routes received from peer",
		rfLabels, nil,
	)
	bgpRoutesAcceptedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "routes", "accepted"),
		"Number of routes accepted from peer",
		rfLabels, nil,
	)
	bgpRoutesAdvertisedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "routes", "advertised"),
		"Number of routes advertised to peer",
		rfLabels, nil,
	)
)

// BgpCollectorOption configures the collector. Options rather than parameters
// so that out-of-tree callers of NewBgpCollector keep compiling.
type BgpCollectorOption func(*bgpCollector)

// WithAdvertisedRoutes enables or disables collection of bgp_routes_advertised.
// It is on by default: the metric surface stays as it was, and the cost is
// bounded by the caching collector rather than by dropping the metric. Turning
// it off drops the series entirely, which is the point on a very large RIB.
func WithAdvertisedRoutes(enabled bool) BgpCollectorOption {
	return func(c *bgpCollector) { c.advertisedRoutes = enabled }
}

func NewBgpCollector(server *server.BgpServer, opts ...BgpCollectorOption) prometheus.Collector {
	c := &bgpCollector{server: server, advertisedRoutes: true}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *bgpCollector) Describe(out chan<- *prometheus.Desc) {
	out <- bgpReceivedUpdateTotalDesc
	out <- bgpReceivedNotificationTotalDesc
	out <- bgpReceivedOpenTotalDesc
	out <- bgpReceivedRefreshTotalDesc
	out <- bgpReceivedKeepaliveTotalDesc
	out <- bgpReceivedWithdrawUpdateTotalDesc
	out <- bgpReceivedWithdrawPrefixTotalDesc
	out <- bgpReceivedDiscardedTotalDesc
	out <- bgpReceivedMessageTotalDesc

	out <- bgpSentUpdateTotalDesc
	out <- bgpSentNotificationTotalDesc
	out <- bgpSentOpenTotalDesc
	out <- bgpSentRefreshTotalDesc
	out <- bgpSentKeepaliveTotalDesc
	out <- bgpSentWithdrawUpdateTotalDesc
	out <- bgpSentWithdrawPrefixTotalDesc
	out <- bgpSentDiscardedTotalDesc
	out <- bgpSentMessageTotalDesc

	out <- bgpPeerOutQueueDesc
	out <- bgpPeerFlopsDesc
	out <- bgpPeerEstablishedTimestampDesc
	out <- bgpPeerSendCommunityFlagDesc
	out <- bgpPeerRemovePrivateAsFlagDesc
	out <- bgpPeerPasswordSetFlagDesc
	out <- bgpPeerTypeDesc
	out <- bgpPeerAsnDesc
	out <- bgpPeerLocalAsnDesc
	out <- bgpPeerStateDesc
	describePeerBfd(out)

	out <- bgpRoutesReceivedDesc
	out <- bgpRoutesAcceptedDesc
	out <- bgpRoutesAdvertisedDesc
}

func (c *bgpCollector) Collect(out chan<- prometheus.Metric) {
	bgpServer, err := c.server.GetBgp(context.Background(), &api.GetBgpRequest{})
	if err != nil {
		out <- prometheus.NewInvalidMetric(prometheus.NewDesc("error", "error during metric collection", nil, nil), err)
		return
	}

	req := &api.ListPeerRequest{EnableAdvertised: c.advertisedRoutes}
	err = c.server.ListPeer(context.Background(), req, func(p *api.Peer) {
		peerState := p.GetState()
		peerAddr := peerState.GetNeighborAddress()
		peerTimers := p.GetTimers()
		msg := peerState.GetMessages()

		// Counters only: monotonic totals that reset when gobgpd restarts.
		send := func(desc *prometheus.Desc, cnt uint64) {
			out <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(cnt), peerAddr)
		}
		// Everything that is not a running total. Queue depths go down, enums
		// and flags are neither cumulative nor ordered, and a timestamp is a
		// point in time. Typed as counters they invited rate() over values
		// where it means nothing: rate(bgp_peer_out_queue_count[5m]) was
		// simply wrong.
		sendGauge := func(desc *prometheus.Desc, v float64) {
			out <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, peerAddr)
		}

		// Statistics about BGP announcements we've received from our peers
		send(bgpReceivedUpdateTotalDesc, msg.Received.Update)
		send(bgpReceivedNotificationTotalDesc, msg.Received.Notification)
		send(bgpReceivedOpenTotalDesc, msg.Received.Open)
		send(bgpReceivedRefreshTotalDesc, msg.Received.Refresh)
		send(bgpReceivedKeepaliveTotalDesc, msg.Received.Keepalive)
		send(bgpReceivedWithdrawUpdateTotalDesc, msg.Received.WithdrawUpdate)
		send(bgpReceivedWithdrawPrefixTotalDesc, msg.Received.WithdrawPrefix)
		send(bgpReceivedDiscardedTotalDesc, msg.Received.Discarded)
		send(bgpReceivedMessageTotalDesc, msg.Received.Total)

		// Statistics about BGP announcements we've sent to our peers
		send(bgpSentUpdateTotalDesc, msg.Sent.Update)
		send(bgpSentNotificationTotalDesc, msg.Sent.Notification)
		send(bgpSentOpenTotalDesc, msg.Sent.Open)
		send(bgpSentRefreshTotalDesc, msg.Sent.Refresh)
		send(bgpSentKeepaliveTotalDesc, msg.Sent.Keepalive)
		send(bgpSentWithdrawUpdateTotalDesc, msg.Sent.WithdrawUpdate)
		send(bgpSentWithdrawPrefixTotalDesc, msg.Sent.WithdrawPrefix)
		send(bgpSentDiscardedTotalDesc, msg.Sent.Discarded)
		send(bgpSentMessageTotalDesc, msg.Sent.Total)

		// The outbound queue message size. A depth, so it falls as well as rises.
		sendGauge(bgpPeerOutQueueDesc, float64(peerState.GetOutQ()))
		// The number of neighbor flops. An absolute count that resets with
		// gobgpd, which is also why it has no _total suffix.
		sendGauge(bgpPeerFlopsDesc, float64(peerState.GetFlops()))
		// Whether BGP community is being sent. An enum.
		sendGauge(bgpPeerSendCommunityFlagDesc, float64(peerState.GetSendCommunity()))
		// Whether BGP Private AS is being removed (1) or not (0). An enum.
		sendGauge(bgpPeerRemovePrivateAsFlagDesc, float64(peerState.GetRemovePrivate()))
		// Peer Type (0) for internal, (1) for external. An enum.
		sendGauge(bgpPeerTypeDesc, float64(peerState.GetType()))

		// Whether authentication password is being set (1) or not (0). A flag.
		//
		// Reads the flag, not the password. PeerState.AuthPassword is declared
		// but never written, and ListPeer redacts Conf.AuthPassword before the
		// peer gets here, so the old GetAuthPassword() != "" test reported 0
		// for every peer, always - including MD5-authenticated ones. Any panel
		// built on it read as 100% unauthenticated forever.
		passwordSetFlag := 0.0
		if peerState.GetAuthPasswordSet() {
			passwordSetFlag = 1
		}
		sendGauge(bgpPeerPasswordSetFlagDesc, passwordSetFlag)

		// Uptime is a Unix timestamp, not a duration - see the help text. A
		// peer that has never established has no uptime at all: ProtoTimestamp
		// returns nil for zero, and emitting that as 0 made time() - uptime
		// read as 56 years rather than as unknown. Absent is the honest answer.
		if uptime := peerTimers.GetState().GetUptime(); uptime != nil {
			sendGauge(bgpPeerEstablishedTimestampDesc, float64(uptime.GetSeconds()))
		}

		// Remote peer router ID and ASN
		out <- prometheus.MustNewConstMetric(
			bgpPeerAsnDesc,
			prometheus.GaugeValue,
			float64(peerState.GetPeerAsn()),
			peerAddr,
			peerState.GetRouterId(),
		)

		// Local router ID and ASN advertised to peer
		out <- prometheus.MustNewConstMetric(
			bgpPeerLocalAsnDesc,
			prometheus.GaugeValue,
			float64(peerState.GetLocalAsn()),
			peerAddr,
			bgpServer.Global.RouterId,
		)

		// Session and administrative state of the peer
		out <- prometheus.MustNewConstMetric(
			bgpPeerStateDesc,
			prometheus.GaugeValue,
			1.0,
			peerAddr,
			peerState.GetSessionState().String(),
			peerState.GetAdminState().String(),
		)

		// BFD liveness for this peer. See pkg/metrics/bfd.go.
		collectPeerBfd(out, p, peerAddr)

		for _, afiSafi := range p.GetAfiSafis() {
			if !afiSafi.GetConfig().GetEnabled() {
				continue
			}
			afiState := afiSafi.GetState()
			family := bgp.NewFamily(
				uint16(afiState.GetFamily().GetAfi()),
				uint8(afiState.GetFamily().GetSafi()),
			).String()
			labelValues := []string{peerAddr, family}
			out <- prometheus.MustNewConstMetric(
				bgpRoutesReceivedDesc,
				prometheus.GaugeValue,
				float64(afiState.GetReceived()),
				labelValues...,
			)
			out <- prometheus.MustNewConstMetric(
				bgpRoutesAcceptedDesc,
				prometheus.GaugeValue,
				float64(afiState.GetAccepted()),
				labelValues...,
			)
			// Absent rather than zero when it was not collected: a flat zero
			// would read as "advertising nothing", which is a different and
			// alarming thing to say.
			if c.advertisedRoutes {
				out <- prometheus.MustNewConstMetric(
					bgpRoutesAdvertisedDesc,
					prometheus.GaugeValue,
					float64(afiState.GetAdvertised()),
					labelValues...,
				)
			}
		}
	})
	if err != nil {
		out <- prometheus.NewInvalidMetric(prometheus.NewDesc("error", "error during metric collection", nil, nil), err)
	}
}
