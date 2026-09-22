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
	"context"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

// These inputs each used to reach a Must* call or an unbounded make() and take
// the process down. None of them needs a malformed packet or a peer: four lines
// of gRPC from anything that can reach the API was enough, and the API is
// unauthenticated unless a client CA is configured.
//
// They run against a started server because the panics were on the management
// path. A panic here fails the whole package rather than one test, which is the
// point: there is no recover() in the control path, so these are process kills.
func newPanicTestServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "10.0.0.1", ListenPort: -1},
	}))
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	return s
}

// DeletePeer identified by interface is a documented form - the request carries
// an Interface field and deleteNeighbor reads NeighborInterface - but the
// address was parsed with MustParseAddr before anything looked at the
// interface, so the supported call killed the daemon. No bad input required.
func TestDeletePeerByInterfaceDoesNotPanic(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.DeletePeer(context.Background(), &api.DeletePeerRequest{Interface: "eth0"})
	// The peer does not exist, so this errors either way. What matters is which
	// error: reaching interface resolution at all proves the ordering is right.
	// "NeighborAddress is not configured" is ExtractNeighborAddress refusing an
	// interface peer, which is what used to happen before the interface branch
	// could run, and it is the exact string this test exists to keep out.
	require.Error(t, err)
	// "NeighborAddress is not configured" is ExtractNeighborAddress refusing an
	// interface peer, which is what used to happen before the interface branch
	// could run. Anything else means the interface path was taken, and which
	// error it is depends on the host: absent interface, or present with no
	// IPv6 link-local. Both are fine; the first version of this test asserted
	// on the specific message and so passed locally and failed on CI.
	assert.NotContains(t, err.Error(), "NeighborAddress is not configured",
		"an interface peer has no address; the interface must be resolved first")
}

// The condition that made the first version of the test above pass locally and
// fail on CI: an interface that exists and carries no IPv6 link-local address.
// GetIPv6LinkLocalNeighborAddress returns ("", nil) for it - not an error - so
// the empty string reached the parser and was reported as an invalid address,
// blaming the caller for something it did not supply.
//
// "lo" has that shape on essentially any host, which is why it is used here
// rather than a name that depends on the machine.
func TestDeletePeerByInterfaceWithoutLinkLocalIsExplicit(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.DeletePeer(context.Background(), &api.DeletePeerRequest{Interface: "lo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IPv6 link-local address",
		"the error must name what is actually wrong with the interface")
	assert.NotContains(t, err.Error(), "invalid neighbor address",
		"the caller supplied an interface, not an address; blaming the address misdirects")
}

func TestDeletePeerWithMalformedAddressReturnsError(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "not-an-address"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid neighbor address")
}

func TestDeletePeerWithNeitherAddressNorInterfaceReturnsError(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.DeletePeer(context.Background(), &api.DeletePeerRequest{})
	require.Error(t, err)
}

// StartBgp's listen_addresses went to MustParseAddr with no validation anywhere
// upstream.
func TestStartBgpWithMalformedListenAddressReturnsError(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn: 65000, RouterId: "10.0.0.1", ListenPort: -1,
			ListenAddresses: []string{"1.2.3.4", "not-an-address"},
		},
	})
	require.Error(t, err)
}

// AddBmp/DeleteBmp validated the monitoring policy and defaulted the port, but
// never looked at the address.
func TestBmpWithMalformedAddressReturnsError(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.AddBmp(context.Background(), &api.AddBmpRequest{Address: "not-an-address", Port: 11019})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bmp server address")

	err = s.DeleteBmp(context.Background(), &api.DeleteBmpRequest{Address: "not-an-address", Port: 11019})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bmp server address")
}

// ttl-security ttl-min and ebgp-multihop multihop-ttl arrive as uint32 and are
// stored as uint8. Truncating 257 to 1 means "accept from any hop count", so
// GTSM reported itself enabled while doing nothing.
func TestTtlValuesOutOfRangeAreRejectedNotTruncated(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:        &api.PeerConf{NeighborAddress: "198.51.100.30", PeerAsn: 65001},
		TtlSecurity: &api.TtlSecurity{Enabled: true, TtlMin: 257},
	}})
	require.Error(t, err, "257 truncates to 1, which disables the protection it claims to enable")
	assert.Contains(t, err.Error(), "ttl-min")

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:         &api.PeerConf{NeighborAddress: "198.51.100.31", PeerAsn: 65001},
		EbgpMultihop: &api.EbgpMultihop{Enabled: true, MultihopTtl: 300},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multihop-ttl")
}

// WatchEvent's batch_size was handed straight to make() as a capacity, so a
// client asking for the uint32 maximum requested ~34GB of pointers from one
// RPC. It fires on the watcher goroutine, and the initial replay happens at
// registration, so it landed before the call returned and nowhere a gRPC
// interceptor could have caught it.
//
// This is ListPathRequest's sibling field, not the same one: ListPath takes a
// uint64 but only ever compares against it, which is why that one is harmless
// and this one was not.
//
// Tested on the clamp directly. An end-to-end watch test was written first and
// discarded: it passed with the cap reverted, because driving the watch
// machinery from a test does not reliably reach the allocation. A test that
// cannot fail is worse than no test.
func TestClampWatchBatchSize(t *testing.T) {
	assert.Equal(t, maxWatchEventBatchSize, clampWatchBatchSize(math.MaxUint32),
		"the uint32 maximum must be capped, not preallocated")
	assert.Equal(t, maxWatchEventBatchSize, clampWatchBatchSize(math.MaxUint64))
	assert.Equal(t, maxWatchEventBatchSize, clampWatchBatchSize(maxWatchEventBatchSize+1))

	// Values at or below the cap pass through, so batching still behaves.
	assert.Equal(t, maxWatchEventBatchSize, clampWatchBatchSize(maxWatchEventBatchSize))
	assert.Equal(t, 10, clampWatchBatchSize(10))
	assert.Equal(t, 0, clampWatchBatchSize(0), "0 means unbatched and must stay 0")
}

// A filter peer address that cannot be parsed used to panic on the watcher
// goroutine at the next update. It must be refused where the client can see it.
func TestWatchEventMalformedFilterAddressReturnsError(t *testing.T) {
	s := newPanicTestServer(t)

	srv := &server{bgpServer: s}
	err := srv.watchEvent(context.Background(), &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_TYPE_ADJIN, PeerAddress: "not-an-address"},
			},
		},
	}, func(*api.WatchEventResponse, time.Time) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid filter peer address")
}

// AddRpki stored the address without parsing it, so the panic surfaced later on
// any ListRpki - a read call, unrelated to the one that planted it.
func TestRpkiMalformedAddressRejectedAtWriteTime(t *testing.T) {
	s := newPanicTestServer(t)

	err := s.AddRpki(context.Background(), &api.AddRpkiRequest{Address: "not-an-address", Port: 323})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rpki server address")

	// And the read path stays walkable.
	require.NoError(t, s.ListRpki(context.Background(), &api.ListRpkiRequest{}, func(*api.Rpki) {}))
}

// The recover barrier in handleMGMTOp is only safe if it sends on errCh.
// mgmtOperation parks on "return <-ch" with no timeout, so a recover that
// returns without sending converts a crash into a caller blocked forever plus
// a leaked goroutine - quieter than a crash and harder to diagnose. This
// asserts the error comes back, which is the part that is easy to get wrong.
//
// "We catch panics" is unverifiable without injecting one, so this injects one.
func TestMgmtOperationPanicReturnsErrorAndDoesNotHang(t *testing.T) {
	s := newPanicTestServer(t)

	done := make(chan error, 1)
	go func() {
		done <- s.mgmtOperation(func() error {
			panic("injected panic for the recovery barrier test")
		}, false)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "the panic must surface as an error, not be swallowed")
		assert.Contains(t, err.Error(), "internal error")
		assert.Contains(t, err.Error(), "injected panic")
	case <-time.After(10 * time.Second):
		t.Fatal("mgmtOperation never returned: the barrier recovered without sending on errCh")
	}

	// And the server is still usable afterwards - a recovered operation must
	// not leave the Serve loop wedged or the lock held.
	assert.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(*api.Peer) {}))
}

// D1, the defect this release exists for: a neighbor added over the API with
// graceful restart enabled and a peer group named came up with graceful restart
// OFF, silently, because the peer group won every field - including a group
// that never configured graceful restart, whose block is all zeros.
//
// This is the end-to-end proof through AddPeer/ListPeer. The per-block matrix
// lives in pkg/config/oc, where the function under test is.
func TestGracefulRestartSurvivesPeerGroupMembership(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001},
	}}))

	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "198.51.100.40",
			PeerAsn:         65001,
			PeerGroup:       "edge",
		},
		GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 120},
	}}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	require.NotNil(t, got.GracefulRestart)

	assert.True(t, got.GracefulRestart.Enabled,
		"the peer group never configured graceful restart; its zero value must not erase the neighbor's")
	assert.EqualValues(t, 120, got.GracefulRestart.RestartTime)
}

// The converse: a neighbor that sends no graceful-restart block still inherits
// the group's. Without this, the fix could have been "never inherit anything".
func TestGracefulRestartStillInheritsFromPeerGroup(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf:            &api.PeerGroupConf{PeerGroupName: "edge2", PeerAsn: 65001},
		GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 90},
	}}))

	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "198.51.100.41",
			PeerAsn:         65001,
			PeerGroup:       "edge2",
		},
		// No GracefulRestart block: inherit.
	}}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	require.NotNil(t, got.GracefulRestart)

	assert.True(t, got.GracefulRestart.Enabled, "a neighbor that sent no block must inherit the group's")
}

// The running config and ListPeer both report the *resolved* configuration, so
// a value the operator set and a value the peer inherited look identical. After
// an inheritance change that is the first question anyone asks, and nothing
// could answer it.
func TestRunningConfigReportsInheritance(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf:            &api.PeerGroupConf{PeerGroupName: "edge3", PeerAsn: 65001},
		GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 90},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: "198.51.100.50", PeerAsn: 65001, PeerGroup: "edge3"},
		// Sends no graceful-restart block, so it inherits the group's.
	}}))

	t.Run("off by default, so existing output is unchanged", func(t *testing.T) {
		rsp, err := s.GetRunningConfig(ctx, &api.GetRunningConfigRequest{
			Format: api.ConfigFormat_CONFIG_FORMAT_TOML,
		})
		require.NoError(t, err)
		assert.NotContains(t, rsp.Config, "inherited configuration blocks")
	})

	t.Run("reports the block and where it came from", func(t *testing.T) {
		rsp, err := s.GetRunningConfig(ctx, &api.GetRunningConfigRequest{
			Format:            api.ConfigFormat_CONFIG_FORMAT_TOML,
			IncludeProvenance: true,
		})
		require.NoError(t, err)
		assert.Contains(t, rsp.Config, "198.51.100.50: graceful-restart <- peer-group",
			"a block taken from the peer group must say so")
	})

	t.Run("the report is comments, so TOML stays loadable", func(t *testing.T) {
		rsp, err := s.GetRunningConfig(ctx, &api.GetRunningConfigRequest{
			Format:            api.ConfigFormat_CONFIG_FORMAT_TOML,
			IncludeProvenance: true,
		})
		require.NoError(t, err)
		for line := range strings.SplitSeq(rsp.Config[strings.Index(rsp.Config, "# inherited"):], "\n") {
			if line == "" {
				continue
			}
			assert.True(t, strings.HasPrefix(line, "#"),
				"every appended line must be a comment, or the output stops being a config file: %q", line)
		}
	})
}

// The global source was recorded and never tested, so nothing proved it was
// ever reported. A peer-group case passing says nothing about the global one:
// they are recorded at different points in the resolution.
func TestRunningConfigReportsGlobalInheritance(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn: 65000, RouterId: "10.0.0.1", ListenPort: -1,
			GracefulRestart:                   &api.GracefulRestart{Enabled: true, RestartTime: 300},
			GracefulRestartInheritToNeighbors: true,
		},
	}))
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	ctx := context.Background()
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: "198.51.100.60", PeerAsn: 65001},
		// No peer group and no graceful-restart block: the global one applies.
	}}))

	rsp, err := s.GetRunningConfig(ctx, &api.GetRunningConfigRequest{
		Format: api.ConfigFormat_CONFIG_FORMAT_TOML, IncludeProvenance: true,
	})
	require.NoError(t, err)
	assert.Contains(t, rsp.Config, "198.51.100.60: graceful-restart <- global",
		"a block taken from the global configuration must say so, not just peer-group ones")
}

// bmpPeerStats re-parses the peer's addresses out of api.Peer, where they are
// strings, and used MustParseAddr to do it. The caller filters to ESTABLISHED
// peers, which is what has kept it from firing - but a statistics message
// should not be able to stop the daemon, and a peer with an empty router id is
// not a reason to lose BGP on the node.
func TestBmpPeerStatsSkipsUnparseableAddresses(t *testing.T) {
	established := func(addr, routerID string) *api.Peer {
		return &api.Peer{State: &api.PeerState{
			NeighborAddress: addr,
			RouterId:        routerID,
			PeerAsn:         65001,
		}}
	}

	assert.Nil(t, bmpPeerStats(0, 0, 0, established("", "10.0.0.1")),
		"an empty neighbor address must be skipped, not fatal")
	assert.Nil(t, bmpPeerStats(0, 0, 0, established("10.0.0.2", "")),
		"an empty router id must be skipped, not fatal")
	assert.Nil(t, bmpPeerStats(0, 0, 0, established("not-an-address", "10.0.0.1")))

	// A peer with no message counters at all - the pointer chain this used to
	// dereference unguarded.
	assert.NotNil(t, bmpPeerStats(0, 0, 0, established("10.0.0.2", "10.0.0.1")),
		"a well-formed peer must still produce a message, counters or not")
}

// A grouped neighbor's as-path options were silently replaced by the peer
// group's zero values - the graceful-restart defect, in the one block whose
// fields are scalars on api.PeerConf rather than a sub-message. There was no
// presence signal for them, so the group won every time.
func TestAsPathOptionsSurvivePeerGroupMembership(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "asgrp", PeerAsn: 65001},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress:      "198.51.100.70",
			PeerAsn:              65001,
			PeerGroup:            "asgrp",
			AllowOwnAsn:          proto.Uint32(3),
			ReplacePeerAsn:       proto.Bool(true),
			AllowAspathLoopLocal: proto.Bool(true),
		},
	}}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)

	assert.EqualValues(t, 3, got.Conf.GetAllowOwnAsn(),
		"the peer group configured no as-path options; its zeros must not erase the neighbor's")
	assert.True(t, got.Conf.GetReplacePeerAsn())
	assert.True(t, got.Conf.GetAllowAspathLoopLocal())
}

// The converse, so the fix cannot be "never inherit": a neighbor that states
// none of them still takes the group's.
func TestAsPathOptionsStillInheritFromPeerGroup(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{
			PeerGroupName: "asgrp2", PeerAsn: 65001,
			AllowOwnAsn: 5, ReplacePeerAsn: true,
		},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "198.51.100.71", PeerAsn: 65001, PeerGroup: "asgrp2",
			// None of the three stated.
		},
	}}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	assert.EqualValues(t, 5, got.Conf.GetAllowOwnAsn(), "a neighbor that stated nothing must inherit")
	assert.True(t, got.Conf.GetReplacePeerAsn())
}

// And the opt-out that only explicit presence can express: false against a
// group that says true. false is the zero value, so nothing else can say it.
func TestAsPathOptionsExplicitFalseOptsOut(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{
			PeerGroupName: "asgrp3", PeerAsn: 65001,
			ReplacePeerAsn: true, AllowOwnAsn: 7,
		},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "198.51.100.72", PeerAsn: 65001, PeerGroup: "asgrp3",
			ReplacePeerAsn: proto.Bool(false),
		},
	}}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	assert.False(t, got.Conf.GetReplacePeerAsn(),
		"an explicitly false as-path option must not be turned back on by the group")
	assert.EqualValues(t, 0, got.Conf.GetAllowOwnAsn(),
		"and stating one field of the block claims the block, as everywhere else")
}

// The same defect, one block over, and the half a controller actually sees.
//
// Graceful restart above is a sub-message, so proto3 message presence answered
// "did the client send this block". The NeighborConfig fields are bare scalars
// on api.PeerConf, which every request carries, so there was no signal at all
// and the peer group won all of them - including a peer group that never
// configured them and supplied zeros.
//
// The consequence is not only the lost setting. ListPeer reports the group's
// value, so a controller diffing desired against observed never converges: it
// re-issues UpdatePeer every reconcile, for ever, taking the server-wide
// mgmtOperation lock each time and masking genuine edits behind the churn.
// That is why this asserts the readback rather than the internal config.
func TestNeighborConfigFieldsSurvivePeerGroupMembership(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	// A group that sets none of these. Its zeros are what used to land on the
	// member.
	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001},
	}}))

	const addr = "198.51.100.41"
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress:     addr,
			PeerAsn:             65001,
			PeerGroup:           "edge",
			Description:         proto.String("Spine uplink 1"),
			LocalAsn:            proto.Uint32(65002),
			AuthPassword:        proto.String("correct-horse-battery-staple"),
			RouteFlapDamping:    proto.Bool(true),
			SendSoftwareVersion: proto.Bool(true),
			RemovePrivate:       api.RemovePrivate_REMOVE_PRIVATE_REPLACE.Enum(),
			SendCommunity:       proto.Uint32(1),
		},
	}}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	require.NotNil(t, got.Conf)

	assert.Equal(t, "Spine uplink 1", got.Conf.GetDescription())
	assert.EqualValues(t, 65002, got.Conf.GetLocalAsn())
	assert.True(t, got.Conf.GetRouteFlapDamping())
	assert.True(t, got.Conf.GetSendSoftwareVersion())
	assert.Equal(t, api.RemovePrivate_REMOVE_PRIVATE_REPLACE, got.Conf.GetRemovePrivate())
	assert.EqualValues(t, 1, got.Conf.GetSendCommunity())

	// The password cannot be asserted directly: ListPeer blanks
	// Conf.AuthPassword on the way out, so both "kept" and "erased" read back
	// empty. PeerState.AuthPasswordSet is derived before the redaction and is
	// the only observable difference - and the difference matters, because the
	// erasure took MD5 off while leaving the session up.
	require.NotNil(t, got.State)
	assert.True(t, got.State.AuthPasswordSet,
		"the neighbor's MD5 key must survive peer-group membership")
	assert.Empty(t, got.Conf.GetAuthPassword(), "and must still not cross the wire")
}

// The configuration file was not exempt, which is the part the report of this
// defect did not reach.
//
// ReadConfigFile records real per-field presence and resolves the neighbor
// against its group correctly. But addNeighbors then hands the *resolved*
// neighbor to AddPeer as an api.Peer, and inheritance runs a second time
// inside the server - against whatever presence the API path recorded. With no
// presence for the config block that second pass copied the group's values
// over settings the operator had written in TOML and that had already been
// applied once, correctly.
//
// So a TOML neighbor overriding its peer group's description or local-as came
// up with the group's, and the config file it was started from said otherwise.
// Pinned end to end, because neither half is wrong on its own.
func TestTOMLNeighborOverrideSurvivesTheSecondInheritancePass(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	pg := &oc.PeerGroup{}
	pg.Config.PeerGroupName = "edge"
	pg.Config.PeerAs = 65001
	pg.Config.Description = "Spine fabric"
	pg.Config.LocalAs = 65001

	n := &oc.Neighbor{}
	n.Config.NeighborAddress = netip.MustParseAddr("198.51.100.42")
	n.Config.PeerGroup = "edge"
	n.Config.PeerAs = 65001
	n.Config.Description = "TOML override"
	n.Config.LocalAs = 65002

	// What the TOML loader registers: the decoded map for this neighbor, whose
	// "config" level is flat.
	key := oc.NeighborPresenceKey(n)
	oc.RegisterConfiguredFields(key, map[string]any{"config": map[string]any{
		"description": true,
		"local-as":    true,
	}})
	t.Cleanup(func() { oc.UnregisterConfiguredFields(key) })

	require.NoError(t, oc.SetDefaultNeighborConfigValues(n, pg, &oc.Global{}))
	require.Equal(t, "TOML override", n.Config.Description, "the config read itself was never wrong")

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pg),
	}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(n),
	}))

	var got *api.Peer
	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
	require.NotNil(t, got)
	assert.Equal(t, "TOML override", got.Conf.GetDescription(),
		"the peer group overwrote a value the configuration file set explicitly")
	assert.EqualValues(t, 65002, got.Conf.GetLocalAsn())
}
