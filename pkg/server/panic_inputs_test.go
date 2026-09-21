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
	"testing"

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
