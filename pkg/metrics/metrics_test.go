package metrics

import (
	"context"
	"regexp"
	"strconv"
	"strings"
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

func TestFSMLoopMetrics(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	fsmCollector := NewFSMTimingsCollector()
	registry := prometheus.NewRegistry()
	err := registry.Register(fsmCollector)
	assert.NoError(err)

	s := server.NewBgpServer(server.TimingHookOption(fsmCollector))
	go s.Serve()

	const metricName = "fsm_loop_mgmt_op_timing_sec"
	metrics, err := registry.Gather()
	require.NoError(err)
	hist := getMetric(metrics, metricName)
	require.NotNil(hist)
	assert.Equal(uint64(0), *hist.Metric[0].Histogram.SampleCount)

	err = s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// wait to ensure we started BGP
	time.Sleep(1 * time.Second)

	// StartBgp counts as single management operation
	metrics, err = registry.Gather()
	require.NoError(err)
	hist = getMetric(metrics, metricName)
	require.NotNil(hist)
	assert.Equal(uint64(1), *hist.Metric[0].Histogram.SampleCount)
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
				RemoteSessionState: api.BfdSessionState_BFD_SESSION_STATE_DOWN,
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
