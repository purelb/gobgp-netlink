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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
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
	assert.NotContains(t, err.Error(), "NeighborAddress is not configured",
		"an interface peer has no address; the interface must be resolved first")
	assert.NotContains(t, err.Error(), "invalid neighbor address")
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
