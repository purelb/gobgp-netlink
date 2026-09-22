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
	"fmt"
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

// A peer group keeps a copy of each member's resolved configuration, and
// updatePeerGroup re-resolves every member from that copy when the group
// changes. Only addNeighbor ever refreshed it.
//
// So any field that reaches a live peer without a session reset - everything
// outside NeedsResendOpenMessage: send-community, timers, BFD, apply-policy -
// was applied to the FSM and left stale in the member copy. The next touch of
// the peer group, for any reason at all, re-resolved from the stale copy and
// silently put the old value back:
//
//	AddPeer(send-community standard) -> UpdatePeer(both) -> UpdatePeerGroup()
//	  reports standard again, with no error and no log
//
// The one field gobgp had already excluded from a session reset was the one
// field that silently reverted. Measured the same way for hold-time, so this
// is not specific to send-community - it is every field on that path.
func TestUpdatesSurviveALaterPeerGroupUpdate(t *testing.T) {
	setup := func(t *testing.T, addr string, peer *api.Peer) *BgpServer {
		t.Helper()
		s := newPanicTestServer(t)
		ctx := context.Background()
		require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001},
		}}))
		require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}))
		return s
	}
	// Touch the peer group for an unrelated reason. Nothing here concerns the
	// member's own settings.
	touchGroup := func(t *testing.T, s *BgpServer) {
		t.Helper()
		_, err := s.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
			PeerGroup: &api.PeerGroup{Conf: &api.PeerGroupConf{
				PeerGroupName: "edge", PeerAsn: 65001, Description: "unrelated edit",
			}},
		})
		require.NoError(t, err)
	}
	read := func(t *testing.T, s *BgpServer) *api.Peer {
		t.Helper()
		var got *api.Peer
		require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{},
			func(p *api.Peer) { got = p }))
		require.NotNil(t, got)
		return got
	}

	t.Run("send-community", func(t *testing.T) {
		const addr = "198.51.100.43"
		conf := func(sc uint32) *api.PeerConf {
			return &api.PeerConf{
				NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge",
				SendCommunity: proto.Uint32(sc),
			}
		}
		s := setup(t, addr, &api.Peer{Conf: conf(0)}) // standard
		_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{
			Peer: &api.Peer{Conf: conf(2)}, // both
		})
		require.NoError(t, err)
		require.EqualValues(t, 2, read(t, s).Conf.GetSendCommunity(), "the update must apply")

		touchGroup(t, s)
		assert.EqualValues(t, 2, read(t, s).Conf.GetSendCommunity(),
			"touching the peer group reverted send-community to its AddPeer value")
	})

	t.Run("timers", func(t *testing.T) {
		const addr = "198.51.100.44"
		peer := func(hold uint64) *api.Peer {
			return &api.Peer{
				Conf:   &api.PeerConf{NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge"},
				Timers: &api.Timers{Config: &api.TimersConfig{HoldTime: hold, KeepaliveInterval: hold / 3}},
			}
		}
		s := setup(t, addr, peer(90))
		_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peer(180)})
		require.NoError(t, err)
		require.EqualValues(t, 180, read(t, s).Timers.Config.HoldTime, "the update must apply")

		touchGroup(t, s)
		assert.EqualValues(t, 180, read(t, s).Timers.Config.HoldTime,
			"touching the peer group reverted hold-time to its AddPeer value")
	})
}

// Editing a peer group did nothing to the peers already in it.
//
// updatePeerGroup re-resolves every member against the new group, but the
// member copy it starts from has already been resolved once, and
// SetDefaultNeighborConfigValues began with
//
//	if n.State.LocalAs != 0 { return nil }
//
// as a guard against being run twice over the same struct. State.LocalAs is set
// by the first resolution, so for a member the guard always fired: inheritance
// never re-ran, the member was compared against itself, and UpdatePeerGroup
// returned success having changed nothing. Description, timers, graceful
// restart - nothing reached an existing member. A peer group was a template
// applied once at AddPeer and inert from then on.
//
// The guard could not simply be removed before now. Re-running inheritance
// needs presence to tell a member's own value from one it inherited, and until
// the API path recorded presence there was nothing to tell them apart with - so
// re-resolving would have overwritten every member's own settings with the
// group's. The guard suppressed propagation, but it also suppressed that. Now
// that presence is recorded on both paths, re-resolution is correct and the
// guard is what stands in the way.
//
// Both halves are asserted here because a fix that only propagates is as wrong
// as one that never did.
func TestPeerGroupChangesReachExistingMembers(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()
	const inherits = "198.51.100.70" // states nothing of its own
	const owns = "198.51.100.71"     // states all three

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf:            &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001, Description: "v1"},
		Timers:          &api.Timers{Config: &api.TimersConfig{HoldTime: 90, KeepaliveInterval: 30}},
		GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 100},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: inherits, PeerAsn: 65001, PeerGroup: "edge"},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: owns, PeerAsn: 65001, PeerGroup: "edge",
			Description: proto.String("mine"),
		},
		Timers:          &api.Timers{Config: &api.TimersConfig{HoldTime: 30, KeepaliveInterval: 10}},
		GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 42},
	}}))

	type resolved struct {
		description string
		holdTime    uint64
		restartTime uint32
	}
	read := func(t *testing.T) map[string]resolved {
		t.Helper()
		out := map[string]resolved{}
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
			r := resolved{description: p.Conf.GetDescription()}
			if p.Timers != nil && p.Timers.Config != nil {
				r.holdTime = p.Timers.Config.HoldTime
			}
			if p.GracefulRestart != nil {
				r.restartTime = p.GracefulRestart.RestartTime
			}
			out[p.Conf.NeighborAddress] = r
		}))
		return out
	}

	before := read(t)
	require.Equal(t, resolved{"v1", 90, 100}, before[inherits], "inherited at AddPeer")
	require.Equal(t, resolved{"mine", 30, 42}, before[owns], "its own at AddPeer")

	_, err := s.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf:            &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001, Description: "v2"},
		Timers:          &api.Timers{Config: &api.TimersConfig{HoldTime: 240, KeepaliveInterval: 80}},
		GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 200},
	}})
	require.NoError(t, err)

	after := read(t)
	assert.Equal(t, resolved{"v2", 240, 200}, after[inherits],
		"a member that stated nothing of its own must follow the group it belongs to")
	assert.Equal(t, resolved{"mine", 30, 42}, after[owns],
		"a member that stated its own settings must not lose them when the group changes")
}

// A change to a field that never reaches the OPEN message must apply without
// dropping the session, and a change that does reach it must still drop it.
//
// The reset path deletes and re-adds the neighbor, which constructs a fresh
// *peer, so pointer identity is the direct observable for "was this session
// rebuilt". Read through mgmtOperation because neighborMap belongs to the
// Serve goroutine.
func TestCarvedOutFieldsApplyWithoutResettingTheSession(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()
	const addr = "198.51.100.45"

	identity := func(t *testing.T) *peer {
		t.Helper()
		var p *peer
		require.NoError(t, s.mgmtOperation(func() error {
			p = s.neighborMap[netip.MustParseAddr(addr)]
			return nil
		}, false))
		require.NotNil(t, p)
		return p
	}
	description := func(t *testing.T) string {
		t.Helper()
		var got *api.Peer
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
		require.NotNil(t, got)
		return got.Conf.GetDescription()
	}
	update := func(t *testing.T, conf *api.PeerConf) {
		t.Helper()
		_, err := s.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: &api.Peer{Conf: conf}})
		require.NoError(t, err)
	}

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001},
	}}))
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge",
			Description: proto.String("before"),
		},
	}}))
	before := identity(t)
	require.Equal(t, "before", description(t))

	t.Run("description alone keeps the session", func(t *testing.T) {
		update(t, &api.PeerConf{
			NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge",
			Description: proto.String("after"),
		})
		assert.Same(t, before, identity(t),
			"a description change tore the session down; it never reaches the wire")
		assert.Equal(t, "after", description(t),
			"carved out of the reset means updateNeighbor has to apply it in place")
	})

	t.Run("remove-private-as alone keeps the session", func(t *testing.T) {
		// An egress AS_PATH rewrite, applied per advertisement from
		// State.RemovePrivateAs - so it has to reach State as well as Config,
		// and already-advertised routes have to be re-sent under the new
		// setting. eBGP only; SetDefaultNeighborConfigValues rejects it on an
		// iBGP peer, and this peer is 65000 -> 65001.
		update(t, &api.PeerConf{
			NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge",
			Description:   proto.String("after"),
			RemovePrivate: api.RemovePrivate_REMOVE_PRIVATE_ALL.Enum(),
		})
		assert.Same(t, before, identity(t),
			"stripping private ASNs changes what is advertised, not what is negotiated")

		var got *api.Peer
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { got = p }))
		require.NotNil(t, got)
		assert.Equal(t, api.RemovePrivate_REMOVE_PRIVATE_ALL, got.Conf.GetRemovePrivate(),
			"carved out of the reset means updateNeighbor has to apply it in place")
	})

	t.Run("a change that reaches the OPEN still resets", func(t *testing.T) {
		// The control. Without it, a carve-out that swallowed everything would
		// pass the case above.
		update(t, &api.PeerConf{
			NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge",
			Description:   proto.String("after"),
			RemovePrivate: api.RemovePrivate_REMOVE_PRIVATE_ALL.Enum(),
			LocalAsn:      proto.Uint32(65042),
		})
		assert.NotSame(t, before, identity(t),
			"local-as is carried in this speaker's OPEN; the session must be rebuilt")
	})
}

// And the same through the peer group, which is where it multiplies: one edit
// to a group runs updateNeighbor for every member, so before the carve-out
// renaming a peer group dropped every session under it at once.
func TestPeerGroupDescriptionChangeDoesNotResetMembers(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()
	addrs := []string{"198.51.100.46", "198.51.100.47", "198.51.100.48"}

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001, Description: "Spine fabric"},
	}}))
	for _, a := range addrs {
		// No description of their own, so they inherit the group's - the shape
		// where a group edit actually changes the member's resolved config.
		require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
			Conf: &api.PeerConf{NeighborAddress: a, PeerAsn: 65001, PeerGroup: "edge"},
		}}))
	}

	identities := func(t *testing.T) map[string]*peer {
		t.Helper()
		out := map[string]*peer{}
		require.NoError(t, s.mgmtOperation(func() error {
			for _, a := range addrs {
				out[a] = s.neighborMap[netip.MustParseAddr(a)]
			}
			return nil
		}, false))
		return out
	}
	before := identities(t)
	for _, a := range addrs {
		require.NotNil(t, before[a])
	}

	_, err := s.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001, Description: "Spine fabric (renamed)"},
	}})
	require.NoError(t, err)

	after := identities(t)
	for _, a := range addrs {
		assert.Same(t, before[a], after[a],
			"renaming the peer group dropped member %s; a description reaches no peer", a)
	}

	require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		assert.Equal(t, "Spine fabric (renamed)", p.Conf.GetDescription(),
			"the inherited description still has to be applied, not merely not-reset")
	}))
}

// A session reset must not cost a grouped neighbor the settings it owns.
//
// updateNeighbor rebuilds the session for any change that reaches the OPEN
// message, and it does that by calling deleteNeighbor and addNeighbor.
// deleteNeighbor drops the field-presence recorded for the neighbor - correct
// when a peer is genuinely being deleted, so a later peer reusing the address
// does not inherit it - and addNeighbor then resolves the configuration again.
// With the presence already gone, that second resolve handed the peer group
// every field the member owned: its MD5 key, its local AS, graceful restart,
// ebgp-multihop, passive mode.
//
// It did not self-heal, because every attempt to put the value back is itself
// a change that resets the session. And through updatePeerGroup one edit does
// it to every member of the group at once.
//
// v1.3.3 survived this by accident: SetDefaultNeighborConfigValues skipped any
// neighbor it had already resolved, so addNeighbor's second resolve did
// nothing. Removing that short-circuit is what makes peer-group edits reach
// existing members, and it is what exposed this - the presence has to be kept
// deliberately now rather than protected by a guard that also broke
// propagation.
func TestSessionResetKeepsTheFieldsAMemberOwns(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()
	const addr = "198.51.100.120"

	// A group that sets its own values for everything the member overrides, so
	// "the member kept its own" and "the group had nothing to give" cannot be
	// confused.
	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf:            &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001, AuthPassword: "grouppw"},
		GracefulRestart: &api.GracefulRestart{Enabled: false},
		EbgpMultihop:    &api.EbgpMultihop{Enabled: false},
		Transport:       &api.Transport{PassiveMode: false},
	}}))

	member := func(localAs uint32) *api.Peer {
		return &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: addr, PeerAsn: 65001, PeerGroup: "edge",
				AuthPassword: proto.String("memberpw"),
				LocalAsn:     proto.Uint32(localAs),
			},
			GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 120},
			EbgpMultihop:    &api.EbgpMultihop{Enabled: true, MultihopTtl: 5},
			Transport:       &api.Transport{PassiveMode: true},
		}
	}
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: member(65042)}))

	// Read the resolved configuration the FSM holds. ListPeer blanks the
	// password on the way out, and the password is the setting whose loss is
	// worst: the session stays up, unauthenticated or authenticated with a key
	// the operator did not choose.
	type owned struct {
		authPassword string
		localAs      uint32
		gr           bool
		multihop     bool
		multihopTTL  uint8
		passive      bool
	}
	read := func(t *testing.T) owned {
		t.Helper()
		var got owned
		require.NoError(t, s.mgmtOperation(func() error {
			c := s.neighborMap[netip.MustParseAddr(addr)].fsm.pConf.ReadOnly()
			got = owned{
				authPassword: c.Config.AuthPassword,
				localAs:      c.Config.LocalAs,
				gr:           c.GracefulRestart.Config.Enabled,
				multihop:     c.EbgpMultihop.Config.Enabled,
				multihopTTL:  c.EbgpMultihop.Config.MultihopTtl,
				passive:      c.Transport.Config.PassiveMode,
			}
			return nil
		}, false))
		return got
	}

	require.Equal(t, owned{"memberpw", 65042, true, true, 5, true}, read(t),
		"the member's own settings at AddPeer")

	// Change local-as. It is carried in this speaker's OPEN, so the session is
	// rebuilt - which is the path under test, not the change itself.
	p := member(65043)
	_, err := s.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: p})
	require.NoError(t, err)

	assert.Equal(t, owned{"memberpw", 65043, true, true, 5, true}, read(t),
		"rebuilding the session handed the peer group the fields this member owns")
}

// A grouped neighbor's address families were always the peer group's.
//
// Inheritance replaces the afi-safi list wholesale unless "neighbor.afi-safis"
// is set, and nothing ever set it - the presence table had an entry for every
// block except this one. It was also excused from the coverage guard, on the
// grounds that a list is not a block, which is precisely why nobody noticed.
//
// A neighbor asking for IPv6 in a group configured for IPv4 got IPv4, with no
// error: the families it asked for simply were not negotiated.
func TestNeighborKeepsItsOwnAfiSafis(t *testing.T) {
	s := newPanicTestServer(t)
	ctx := context.Background()

	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "edge", PeerAsn: 65001},
		AfiSafis: []*api.AfiSafi{{Config: &api.AfiSafiConfig{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Enabled: true,
		}}},
	}}))

	families := func(t *testing.T, addr string) []string {
		t.Helper()
		var out []string
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
			if p.Conf.NeighborAddress != addr {
				return
			}
			for _, af := range p.AfiSafis {
				out = append(out, fmt.Sprintf("%v/%v", af.Config.Family.Afi, af.Config.Family.Safi))
			}
		}))
		return out
	}

	// States its own family: IPv6, where the group says IPv4.
	const own = "198.51.100.130"
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: own, PeerAsn: 65001, PeerGroup: "edge"},
		AfiSafis: []*api.AfiSafi{{Config: &api.AfiSafiConfig{
			Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, Enabled: true,
		}}},
	}}))
	assert.Equal(t, []string{"AFI_IP6/SAFI_UNICAST"}, families(t, own),
		"the neighbor asked for IPv6 and the peer group replaced it with its own families")

	// States nothing: still inherits, which is the half that must not regress.
	const inherits = "198.51.100.131"
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: inherits, PeerAsn: 65001, PeerGroup: "edge"},
	}}))
	assert.Equal(t, []string{"AFI_IP/SAFI_UNICAST"}, families(t, inherits),
		"a neighbor that stated no families must still take the group's")
}
