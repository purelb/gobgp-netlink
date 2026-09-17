package metrics

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func TestMetrics(test *testing.T) {
	assert := assert.New(test)
	s := server.NewBgpServer()

	registry := prometheus.NewRegistry()
	registry.MustRegister(NewBgpCollector(s))

	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
	assert.NoError(err)

	t := server.NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}

	watchCtx, watchCancel := context.WithCancel(context.Background())
	stateCh := make(chan struct{})
	err = s.WatchEvent(watchCtx, server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if peer.Type == apiutil.PEER_EVENT_STATE && peer.Peer.State.SessionState == bgp.BGP_FSM_ESTABLISHED {
				watchCancel()
				close(stateCh)
			}
		},
	}, server.WatchPeer())

	assert.NoError(err)

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.NoError(err)
	<-stateCh

	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}

	nlri1 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.1.0.0",
		PrefixLen: 24,
	}}}

	attrs := []*api.Attribute{
		{
			Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
				Origin: 0,
			}},
		},
		{
			Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
				NextHop: "10.0.0.1",
			}},
		},
	}
	apiPath := &api.Path{
		Family: family,
		Nlri:   nlri1,
		Pattrs: attrs,
	}

	ctx, cancel := context.WithCancel(context.Background())
	goroutineCh := make(chan any)
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(goroutineCh)
				return
			default:
				family := bgp.NewFamily(uint16(apiPath.Family.Afi), uint8(apiPath.Family.Safi))
				nlri, err := apiutil.GetNativeNlri(apiPath)
				if err != nil {
					test.Errorf("invalid nlri: %v", err)
				}
				pattrs, err := apiutil.GetNativePathAttributes(apiPath)
				if err != nil {
					test.Errorf("invalid path attributes: %v", err)
				}
				_, err = t.AddPath(apiutil.AddPathRequest{
					Paths: []*apiutil.Path{
						{
							Family: family,
							Nlri:   nlri,
							Attrs:  pattrs,
						},
					},
				})

				assert.NoError(err)
				err = t.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{{
					Family: family,
					Nlri:   nlri,
					Attrs:  pattrs,
				}}})
				assert.NoError(err)
			}
		}
	}()

	for range 100 {
		metrics, err := registry.Gather()
		assert.NoError(err)
		assert.NotEmpty(metrics)
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-goroutineCh
}

// These metrics reported nonsense for a year while a test asserted only that
// the sample count was 1. The assertions here are on values, and each one is
// chosen to fail against the old code by a wide margin rather than a whisker.
//
// The ordering matters and is the reason the old shape could not have caught
// it: the loop has to be parked and idle *before* the operation is submitted.
// StartBgp blocks on its errCh until the operation has been handled, so a sleep
// after it is outside the measured window entirely.
func TestFSMLoopMetrics(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	fsmCollector := NewFSMTimingsCollector()
	registry := prometheus.NewRegistry()
	// Register, not MustRegister: Describe runs inside this call, in a
	// goroutine with no recover, so a nil histogram would take the process
	// down here rather than fail a scrape.
	require.NoError(registry.Register(fsmCollector))

	s := server.NewBgpServer(server.TimingHookOption(fsmCollector))
	go s.Serve()

	sum := func(name string) (float64, uint64) {
		families, err := registry.Gather()
		require.NoError(err)
		f := getMetric(families, name)
		require.NotNil(f, "%s must be registered", name)
		return f.Metric[0].Histogram.GetSampleSum(), f.Metric[0].Histogram.GetSampleCount()
	}

	// Wait for the Serve goroutine to record the observation.
	//
	// StartBgp cannot be used as a barrier for this. handleMGMTOp sends the
	// result on op.errCh as its last statement, which releases the caller,
	// and only then does the Serve loop unlock and call Observe - so a Gather
	// immediately after StartBgp returns can legitimately see nothing. That is
	// correct behaviour on the daemon's side and a race in the test, which is
	// how it reached CI passing locally and failing there.
	awaitCount := func(name string, want uint64) (float64, uint64) {
		t.Helper()
		var gotSum float64
		var gotCount uint64
		for range 400 {
			gotSum, gotCount = sum(name)
			if gotCount >= want {
				return gotSum, gotCount
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("%s reached count %d, want %d after 2s", name, gotCount, want)
		return gotSum, gotCount
	}

	_, count := sum("fsm_loop_mgmt_op_work_seconds")
	assert.Equal(uint64(0), count, "nothing observed before any operation")

	// Park the loop in its select for a known interval. Against the old code
	// this whole second landed in work_seconds and came back out of
	// queue_wait_seconds as a negative.
	const idle = time.Second
	time.Sleep(idle)

	require.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 2, RouterId: "2.2.2.2", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	workSum, workCount := awaitCount("fsm_loop_mgmt_op_work_seconds", 1)
	assert.Equal(uint64(1), workCount, "StartBgp is one management operation")
	assert.Less(workSum, 0.1,
		"work must exclude the idle wait; the old code reported the full %s", idle)

	queueSum, queueCount := awaitCount("fsm_loop_mgmt_op_queue_wait_seconds", 1)
	assert.Equal(uint64(1), queueCount)
	assert.Greater(queueSum, 0.0, "a real queue wait, not the negative the old code produced")
	assert.Less(queueSum, 0.01,
		"an unbuffered handoff is microseconds; anything near %s means idle time leaked back in", idle)

	// Observed, and on an uncontended lock it is small. The value that matters
	// operationally is the one under contention, which the lab test covers.
	_, lockCount := awaitCount("fsm_loop_mgmt_op_lock_wait_seconds", 1)
	assert.Equal(uint64(1), lockCount, "lock wait is always observed, even when zero")
}

// The queue wait series exists only for operations that actually have a queue.
// A synchronous path reporting a zero queue wait would read as "never queued",
// which is a claim, not an absence.
func TestFSMTimingsCollectorOmitsQueueWaitForSynchronousPaths(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	registry := prometheus.NewRegistry()
	require.NoError(registry.Register(NewFSMTimingsCollector()))

	families, err := registry.Gather()
	require.NoError(err, "a nil histogram in Describe or Collect shows up here")

	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}

	for _, want := range []string{
		"fsm_loop_mgmt_op_work_seconds",
		"fsm_loop_mgmt_op_lock_wait_seconds",
		"fsm_loop_mgmt_op_queue_wait_seconds",
		"fsm_loop_accept_queue_wait_seconds",
		"fsm_loop_roa_event_queue_wait_seconds",
		"bgp_message_handling_work_seconds",
		"bgp_message_handling_lock_wait_seconds",
		"bgp_state_change_handling_work_seconds",
	} {
		assert.True(names[want], "%s must be registered", want)
	}

	for _, gone := range []string{
		// handleFSMMessage is called synchronously; there is no queue.
		"bgp_message_handling_queue_wait_seconds",
		"bgp_state_change_handling_queue_wait_seconds",
		// Renamed: these were the released v1.2.0 names.
		"fsm_loop_mgmt_op_timing_sec",
		"fsm_loop_mgmt_op_wait_sec",
		"fsm_loop_event_timing_sec",
		"fsm_loop_message_timing_sec",
	} {
		assert.False(names[gone], "%s must not be registered", gone)
	}
}

// Observe is reachable through an exported interface, so an out-of-range
// operation must not index past the end of the slice and kill the daemon.
func TestFSMTimingsCollectorIgnoresUnknownOperation(t *testing.T) {
	c := NewFSMTimingsCollector()
	assert.NotPanics(t, func() {
		c.Observe(server.FSMOperationTypeCount, server.FSMTiming{Work: time.Second})
		c.Observe(server.FSMOperation(1<<20), server.FSMTiming{Work: time.Second})
	})
}

func getMetric(metrics []*dto.MetricFamily, metricName string) *dto.MetricFamily {
	for _, m := range metrics {
		if m.GetName() == metricName {
			return m
		}
	}
	return nil
}

// gatherPeerBfd runs collectPeerBfd and returns the emitted series keyed by
// metric name, with label values appended.
func gatherPeerBfd(t *testing.T, p *api.Peer, addr string) map[string][]string {
	t.Helper()
	ch := make(chan prometheus.Metric, 16)
	collectPeerBfd(ch, p, addr)
	close(ch)

	got := map[string][]string{}
	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))
		// Key on fqName only. Desc.String() also contains the help text, and one
		// help string names another metric, which silently aliased two series.
		name := descFqName(m.Desc().String())
		val := pb.GetGauge().GetValue()
		if pb.Counter != nil {
			val = pb.GetCounter().GetValue()
		}
		entry := []string{}
		for _, l := range pb.GetLabel() {
			entry = append(entry, l.GetName()+"="+l.GetValue())
		}
		entry = append(entry, "value="+strconv.FormatFloat(val, 'f', -1, 64))
		got[strings.TrimPrefix(name, "bgp_peer_")] = entry
	}
	return got
}

var descFqNameRe = regexp.MustCompile(`fqName: "([^"]+)"`)

func descFqName(desc string) string {
	if m := descFqNameRe.FindStringSubmatch(desc); m != nil {
		return m[1]
	}
	return desc
}

// TestBfdMetricsExposeTheSilentFailure pins the series that make a BFD session
// that is configured, transmitting, and never coming up visible to an alert.
//
// That state was reached on hardware by configuring a link-local neighbor
// without its zone: the receive lookup could not match the zoned address the
// kernel reported, so BGP stayed up and healthy while BFD never left DOWN. The
// only evidence in the whole daemon was a DEBUG log line.
func TestBfdMetricsExposeTheSilentFailure(t *testing.T) {
	peer := &api.Peer{
		Bfd: &api.BfdPeerConfig{Enabled: true},
		State: &api.PeerState{
			NeighborAddress: "fe80::1",
			BfdState: &api.BfdPeerState{
				SessionState:       api.BfdSessionState_BFD_SESSION_STATE_DOWN,
				FailureTransitions: 2,
				BfdAsync: &api.BfdAsyncCounters{
					TransmittedPackets: 63,
					ReceivedPackets:    0,
				},
			},
		},
	}

	got := gatherPeerBfd(t, peer, "fe80::1")

	assert.Contains(t, got["bfd_enabled"], "value=1",
		"a configured peer must report enabled even while its session is down")
	assert.Contains(t, got["bfd_state"], "session_state=BFD_SESSION_STATE_DOWN")
	// The diagnostic signature: our packets leave, none come back.
	assert.Contains(t, got["bfd_transmitted_packets_total"], "value=63")
	assert.Contains(t, got["bfd_received_packets_total"], "value=0")
	assert.Contains(t, got["bfd_failure_transitions_total"], "value=2")
}

// TestBfdEnabledEmittedForPeersWithoutBfd: the enabled gauge must exist for
// every peer, so "configured but down" is a query rather than the absence of a
// series, which cannot be alerted on.
func TestBfdEnabledEmittedForPeersWithoutBfd(t *testing.T) {
	peer := &api.Peer{State: &api.PeerState{NeighborAddress: "10.0.0.1"}}
	got := gatherPeerBfd(t, peer, "10.0.0.1")

	assert.Contains(t, got["bfd_enabled"], "value=0")
	assert.NotContains(t, got, "bfd_state",
		"a peer without BFD must not report a session state")
}

// TestBfdServerMetricsAlwaysPresent: the server-level counters exist from
// startup, so an alert on unknown_peer can be written before anything has gone
// wrong. A series that only appears once it is non-zero cannot be alerted on.
//
// unknown_peer in particular is the counter that identifies a peer-address
// mismatch, and it was previously unreachable entirely: GetBfdServerStats had no
// caller and api.BfdState was named by no RPC.
func TestBfdServerMetricsAlwaysPresent(t *testing.T) {
	s := server.NewBgpServer()
	registry := prometheus.NewRegistry()
	registry.MustRegister(NewBfdCollector(s))

	families, err := registry.Gather()
	require.NoError(t, err)

	names := make([]string, 0, len(families))
	for _, f := range families {
		names = append(names, f.GetName())
	}
	assert.Contains(t, names, "bgp_bfd_unknown_peer_total")
	assert.Contains(t, names, "bgp_bfd_received_drop_total")
}

// bgp_routes_advertised is the expensive series: producing it runs
// getPossibleBest and filterpath over every destination with the export policy
// applied, per peer per family, and it happens under the BGP write lock.
// WithAdvertisedRoutes(false) has to drop it entirely rather than report zero,
// which would read as "advertising nothing" - a different and alarming claim.
// The other two route families must be unaffected.
func TestAdvertisedRoutesCanBeDisabled(t *testing.T) {
	assert := assert.New(t)

	s := server.NewBgpServer()
	go s.Serve()
	assert.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 2},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	names := func(c prometheus.Collector) map[string]bool {
		reg := prometheus.NewRegistry()
		reg.MustRegister(c)
		families, err := reg.Gather()
		assert.NoError(err)
		got := map[string]bool{}
		for _, f := range families {
			got[f.GetName()] = true
		}
		return got
	}

	on := names(NewBgpCollector(s))
	assert.True(on["bgp_routes_advertised"], "collected by default")

	off := names(NewBgpCollector(s, WithAdvertisedRoutes(false)))
	assert.False(off["bgp_routes_advertised"], "absent, not zero, when disabled")
	assert.True(off["bgp_routes_received"], "the cheap families are unaffected")
	assert.True(off["bgp_routes_accepted"])
}

// Seven per-peer metrics were declared as counters and are not: a queue depth
// falls as well as rises, a flop count resets with the daemon, three are enums,
// one is a flag and one is a timestamp. Typed as counters they invited rate()
// over values where it means nothing. The 18 message totals really are
// counters and must stay that way.
func TestPeerMetricTypes(t *testing.T) {
	assert := assert.New(t)

	s := server.NewBgpServer()
	go s.Serve()
	assert.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	// send-community is set because bgp_peer_send_community is deliberately
	// absent when it is not - see TestSendCommunityAbsentUntilConfigured. This
	// test is about metric *types*, so the peer has to be configured for the
	// series to exist at all.
	both := uint32(2)
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 2, SendCommunity: &both},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewBgpCollector(s))
	families, err := reg.Gather()
	assert.NoError(err)

	kind := map[string]dto.MetricType{}
	for _, f := range families {
		kind[f.GetName()] = f.GetType()
	}

	for _, name := range []string{
		"bgp_peer_out_queue_count",
		"bgp_peer_flop_count",
		"bgp_peer_send_community",
		"bgp_peer_remove_private_as",
		"bgp_peer_type",
		"bgp_peer_password_set",
	} {
		got, ok := kind[name]
		assert.True(ok, "%s must be emitted", name)
		assert.Equal(dto.MetricType_GAUGE, got, "%s is not a counter", name)
	}

	for _, name := range []string{
		"bgp_received_update_total",
		"bgp_sent_update_total",
		"bgp_received_message_total",
		"bgp_sent_message_total",
	} {
		assert.Equal(dto.MetricType_COUNTER, kind[name], "%s is a real counter", name)
	}

	// The old name must be gone, not merely joined by the new one.
	_, stale := kind["bgp_peer_uptime"]
	assert.False(stale, "bgp_peer_uptime was renamed and must not still be emitted")
}

// A peer that has never established has no establishment time. Emitting 0 made
// time() - established read as roughly 56 years, which is why k8gobgp's
// equivalent metric is deliberately absent in the same situation.
func TestEstablishedTimestampAbsentUntilEstablished(t *testing.T) {
	assert := assert.New(t)

	s := server.NewBgpServer()
	go s.Serve()
	assert.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	// Passive and never connected, so it cannot have established.
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 2},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewBgpCollector(s))
	families, err := reg.Gather()
	assert.NoError(err)

	for _, f := range families {
		if f.GetName() == "bgp_peer_established_timestamp_seconds" {
			t.Fatalf("emitted for a peer that never established: %v", f.GetMetric())
		}
	}
}

// Timers.State.Uptime is written when the session reaches ESTABLISHED and is
// never cleared - only Downtime is reset. So the establishment timestamp goes
// *stale* after a session drops rather than disappearing, and an alert that
// reads it alone will think the peer is still up.
//
// That is the documented behaviour, not a bug to fix here: the value is a
// genuine record of when the session last came up. But it is exactly the kind
// of thing that gets "tidied" later into absent-when-down, which would break
// every consumer that gates on bgp_peer_state instead. Pinned so the change
// has to be deliberate.
func TestEstablishedTimestampSurvivesTheSessionGoingDown(t *testing.T) {
	assert := assert.New(t)

	s := server.NewBgpServer()
	go s.Serve()
	assert.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: 10279},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	peer := server.NewBgpServer()
	go peer.Serve()
	assert.NoError(peer.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 2, RouterId: "2.2.2.2", ListenPort: -1},
	}))

	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 2},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	watchCtx, watchCancel := context.WithCancel(context.Background())
	established := make(chan struct{})
	var once sync.Once
	assert.NoError(s.WatchEvent(watchCtx, server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(p *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if p.Type == apiutil.PEER_EVENT_STATE && p.Peer.State.SessionState == bgp.BGP_FSM_ESTABLISHED {
				once.Do(func() { close(established) })
			}
		},
	}, server.WatchPeer()))

	assert.NoError(peer.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 1},
		Transport: &api.Transport{RemotePort: 10279},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
	}}))

	select {
	case <-established:
	case <-time.After(30 * time.Second):
		t.Fatal("the session never established, so there is nothing to go stale")
	}
	watchCancel()

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewBgpCollector(s))

	value := func() (float64, bool) {
		families, err := reg.Gather()
		assert.NoError(err)
		for _, f := range families {
			if f.GetName() == "bgp_peer_established_timestamp_seconds" {
				return f.GetMetric()[0].GetGauge().GetValue(), true
			}
		}
		return 0, false
	}

	up, ok := value()
	assert.True(ok, "present once established")
	assert.Greater(up, float64(1_700_000_000), "an absolute Unix timestamp, not a duration")

	// Drop the session from the far side and wait for this one to notice.
	peer.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	var down bool
	for range 100 {
		names := map[string]string{}
		families, err := reg.Gather()
		assert.NoError(err)
		for _, f := range families {
			if f.GetName() == "bgp_peer_state" {
				for _, lp := range f.GetMetric()[0].GetLabel() {
					names[lp.GetName()] = lp.GetValue()
				}
			}
		}
		if names["session_state"] != "SESSION_STATE_ESTABLISHED" {
			down = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	assert.True(down, "the session did not go down, so the assertion below proves nothing")

	after, ok := value()
	assert.True(ok, "still emitted after the session drops - gate on bgp_peer_state, not on absence")
	assert.Equal(up, after, "and it still reports when the session last came up")
}

// bgp_peer_send_community read a constant 0 for every peer before
// send-community was wired up, because nothing ever wrote
// PeerState.SendCommunity. 0 is COMMUNITY_TYPE_STANDARD, so the only honest
// thing the gauge can do for an unconfigured peer is not exist - emitting the
// getter's nil-to-zero would report every peer in the fleet as filtering down
// to standard communities.
func TestSendCommunityAbsentUntilConfigured(t *testing.T) {
	assert := assert.New(t)

	s := server.NewBgpServer()
	go s.Serve()
	assert.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{}) //nolint:errcheck

	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 2},
		Transport: &api.Transport{PassiveMode: true},
	}}))
	// COMMUNITY_TYPE_STANDARD, the zero value: this peer is the one that proves
	// the gauge distinguishes "configured as standard" from "not configured".
	standard := uint32(0)
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 2, SendCommunity: &standard},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewBgpCollector(s))
	families, err := reg.Gather()
	assert.NoError(err)

	got := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "bgp_peer_send_community" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "peer" {
					got[l.GetValue()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	assert.Equal(map[string]float64{"127.0.0.2": 0}, got,
		"only the configured peer gets a series, and its value is 0 for standard")
}
