package metrics

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

type fsmTimingsCollector struct {
	// Indexed by server.FSMOperation. queueWaitHistograms holds a nil for any
	// operation with no queue; every read of these slices must tolerate that.
	workHistograms, lockWaitHistograms, queueWaitHistograms []prometheus.Histogram
}

type FSMTimingsCollector interface {
	server.FSMTimingHook
	prometheus.Collector
}

// 10us to 10s. Per-UPDATE message handling is tens of microseconds and a
// stalled loop is seconds, so this spans six decades. prometheus.DefBuckets
// floors at 5ms, which put every observation of every series into the first
// bucket and made histogram_quantile(q, ...) return 0.005*q - a function of q
// alone, independent of the data. Any floor above ~10us does the same to the
// message path.
var fsmLoopBuckets = []float64{
	1e-5, 3e-5, 1e-4, 3e-4, 1e-3, 3e-3, 1e-2, 3e-2, 0.1, 0.3, 1, 3, 10,
}

// fsmOperation names one timed operation.
//
// namespace is separate because only some of these happen in the Serve loop.
// handleFSMMessage runs on per-peer goroutines, so putting it under fsm_loop
// would claim a location that is not true - and would invite adding its _sum to
// the loop utilisation query, where it can exceed wall-clock time because it
// aggregates N concurrent goroutines.
//
// hasQueue is false where the path is synchronous. Reporting a fabricated zero
// queue wait is worse than reporting nothing: it reads as "never queued".
type fsmOperation struct {
	namespace   string
	infix       string
	description string
	hasQueue    bool
}

var fsmOperations = []fsmOperation{
	server.FSMMgmtOp:      {"fsm_loop", "mgmt_op", "management operation", true},
	server.FSMAccept:      {"fsm_loop", "accept", "TCP accept", true},
	server.FSMROAEvent:    {"fsm_loop", "roa_event", "ROA event", true},
	server.FSMMessage:     {"bgp", "message_handling", "BGP message handling", false},
	server.FSMStateChange: {"bgp", "state_change_handling", "peer state change handling", false},
}

// A short table silently zero-fills, which would register a metric with an
// empty subsystem and the help text "Histogram of  work". Fail the build
// instead.
var _ = [1]struct{}{}[len(fsmOperations)-int(server.FSMOperationTypeCount)]

func NewFSMTimingsCollector() FSMTimingsCollector {
	c := &fsmTimingsCollector{
		workHistograms:      make([]prometheus.Histogram, server.FSMOperationTypeCount),
		lockWaitHistograms:  make([]prometheus.Histogram, server.FSMOperationTypeCount),
		queueWaitHistograms: make([]prometheus.Histogram, server.FSMOperationTypeCount),
	}

	histogram := func(op fsmOperation, suffix, what string) prometheus.Histogram {
		return prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    prometheus.BuildFQName(op.namespace, op.infix, suffix),
			Help:    fmt.Sprintf("Histogram of %s %s", op.description, what),
			Buckets: fsmLoopBuckets,
		})
	}

	for i, op := range fsmOperations {
		c.workHistograms[i] = histogram(op, "work_seconds", "time spent holding the lock and doing the work")
		c.lockWaitHistograms[i] = histogram(op, "lock_wait_seconds", "time blocked acquiring the BGP lock")
		if op.hasQueue {
			c.queueWaitHistograms[i] = histogram(op, "queue_wait_seconds", "time spent queued before being received")
		}
	}
	return c
}

func (f *fsmTimingsCollector) Observe(op server.FSMOperation, t server.FSMTiming) {
	// FSMTimingHook is exported, so an out-of-tree caller can reach this with
	// anything. Indexing on it would take the daemon down.
	if int(op) >= len(f.workHistograms) {
		return
	}
	f.workHistograms[op].Observe(t.Work.Seconds())
	f.lockWaitHistograms[op].Observe(t.LockWait.Seconds())
	if t.HasQueue {
		if h := f.queueWaitHistograms[op]; h != nil {
			h.Observe(t.QueueWait.Seconds())
		}
	}
}

// eachHistogram calls fn for every histogram that exists, skipping the nil
// slots left for operations with no queue.
//
// The nil check is load-bearing in Describe: Registry.Register runs Describe in
// a goroutine with no recover, so a nil here kills the daemon at startup rather
// than failing a scrape. Collect is wrapped in safeCollect and would only
// degrade to a 500, but both are written the same way so neither can rot.
func (f *fsmTimingsCollector) eachHistogram(fn func(prometheus.Histogram)) {
	for _, list := range [][]prometheus.Histogram{f.workHistograms, f.lockWaitHistograms, f.queueWaitHistograms} {
		for _, h := range list {
			if h != nil {
				fn(h)
			}
		}
	}
}

func (f *fsmTimingsCollector) Describe(descs chan<- *prometheus.Desc) {
	f.eachHistogram(func(h prometheus.Histogram) { h.Describe(descs) })
}

func (f *fsmTimingsCollector) Collect(metrics chan<- prometheus.Metric) {
	f.eachHistogram(func(h prometheus.Histogram) { h.Collect(metrics) })
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
		"Configured send-community for the peer: standard=0, extended=1, both=2, none=3. Absent when not configured. Reports configuration, not effect: it is ignored for route-server clients and for families where communities are protocol payload (VPN, EVPN, FlowSpec, MUP, VPLS).",
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
		// Which community types are sent to this peer: standard=0, extended=1,
		// both=2, none=3. An enum, not a bitmask.
		//
		// The series is absent when send-community is not configured. It has to
		// be: 0 means *standard*, so emitting the getter's nil-to-zero would
		// report every unconfigured peer as filtering down to standard
		// communities only. Before send-community was wired up this gauge read 0
		// for every peer always, because nothing wrote PeerState.SendCommunity -
		// so a dashboard moving from a constant 0 to no-data is the metric
		// starting to tell the truth, not a regression.
		if sc := peerState.SendCommunity; sc != nil {
			sendGauge(bgpPeerSendCommunityFlagDesc, float64(*sc))
		}
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
