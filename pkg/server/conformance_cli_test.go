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

// API conformance: over a real gRPC connection.
//
// The other conformance layers call BgpServer in-process, which is fast and
// covers the logic but never serialises a protobuf message. That matters for
// this API specifically: send_community uses explicit presence, and the whole
// point of that change was to keep "absent" distinguishable from "0". A value
// that survives an in-process call has not been tested against the encoding.
//
// So this layer stands a gRPC server up on a loopback socket and drives it as
// an external client, which is how k8gobgp - and every bug report - reaches it.
package server

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/osrg/gobgp/v4/api"
)

// grpcTestServer starts a BgpServer with its real gRPC API on a unix socket and
// returns a client speaking to it, so requests are actually serialised.
func grpcTestServer(t *testing.T, asn uint32) (*BgpServer, api.GoBgpServiceClient) {
	t.Helper()

	dir, err := os.MkdirTemp("", "gobgp-conformance-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) }) //nolint:errcheck
	addr := "unix://" + dir + "/gobgp.sock"

	s := NewBgpServer(GrpcListenAddress(addr))
	go s.Serve()
	t.Cleanup(s.Stop)

	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: asn, RouterId: "1.1.1.1", ListenPort: -1},
	}))

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck

	return s, api.NewGoBgpServiceClient(conn)
}

// Explicit presence has to survive the wire, not just a Go function call. 0 is
// COMMUNITY_TYPE_STANDARD, so conflating it with absent would report every
// unconfigured peer as filtering down to standard communities only - which is
// the failure the optional keyword was added to prevent.
func TestConformanceGRPCPresenceOverTheWire(t *testing.T) {
	_, c := grpcTestServer(t, 65000)
	ctx := context.Background()

	for _, tt := range []struct {
		addr string
		send *uint32
		want string
	}{
		{"10.70.0.1", nil, "absent"},
		{"10.70.0.2", u32p(0), "0"},
		{"10.70.0.3", u32p(1), "1"},
		{"10.70.0.4", u32p(2), "2"},
		{"10.70.0.5", u32p(3), "3"},
		{"10.70.0.6", u32p(99), "absent"}, // out of range coerces to unset
	} {
		_, err := c.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
			Conf:      &api.PeerConf{NeighborAddress: tt.addr, PeerAsn: 65001, SendCommunity: tt.send},
			Transport: &api.Transport{PassiveMode: true},
		}})
		require.NoError(t, err, "AddPeer %s", tt.addr)

		st, err := c.ListPeer(ctx, &api.ListPeerRequest{Address: tt.addr})
		require.NoError(t, err)
		r, err := st.Recv()
		require.NoError(t, err, "ListPeer %s", tt.addr)

		assert.Equal(t, tt.want, showU32(r.Peer.Conf.SendCommunity), "%s Conf", tt.addr)
		assert.Equal(t, tt.want, showU32(r.Peer.State.SendCommunity), "%s State", tt.addr)
	}
}

// The running-config dump has to survive the wire too, and must not leak the
// secret it redacts.
func TestConformanceGRPCRunningConfig(t *testing.T) {
	_, c := grpcTestServer(t, 65000)
	ctx := context.Background()

	_, err := c.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "10.71.0.1", PeerAsn: 65001, AuthPassword: "WIRESECRET"},
		Transport: &api.Transport{PassiveMode: true},
	}})
	require.NoError(t, err)

	rsp, err := c.GetRunningConfig(ctx, &api.GetRunningConfigRequest{})
	require.NoError(t, err)
	assert.Contains(t, rsp.Config, "10.71.0.1", "the API-added peer must appear")
	assert.NotContains(t, rsp.Config, "WIRESECRET", "secrets must not cross the wire")
	assert.Contains(t, rsp.Config, redactedMarker)

	toml, err := c.GetRunningConfig(ctx, &api.GetRunningConfigRequest{
		Format: api.ConfigFormat_CONFIG_FORMAT_TOML,
	})
	require.NoError(t, err)
	assert.Contains(t, toml.Config, "router-id", "TOML must use config-file keys")
	assert.NotContains(t, toml.Config, "RouterId")
}

func u32p(v uint32) *uint32 { return &v }

func showU32(p *uint32) string {
	if p == nil {
		return "absent"
	}
	return string(rune('0' + *p))
}
