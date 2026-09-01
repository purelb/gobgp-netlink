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

	api "github.com/osrg/gobgp/v4/api"

	"github.com/stretchr/testify/assert"
)

// TestListPeerRedactsAuthPassword has two halves and both matter.
//
// ListPeer returned the TCP-MD5 key in clear to any client that can reach the
// gRPC socket. But the same converter, NewPeerFromConfigStruct, is what
// InitialConfig uses to build AddPeer requests, and grpc_server reads
// Conf.AuthPassword back out of those - so redacting in the converter would
// silently disable MD5 for every TOML-configured session. The redaction has to
// be at the read site, and the key has to survive internally.
func TestListPeerRedactsAuthPassword(t *testing.T) {
	assert := assert.New(t)

	s := NewBgpServer()
	go s.Serve()
	assert.NoError(s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	const secret = "correct-horse-battery-staple"
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
			AuthPassword:    secret,
		},
	}}))

	// Half one: the read API must not disclose it.
	var seen int
	assert.NoError(s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		seen++
		if assert.NotNil(p.Conf) {
			assert.Empty(p.Conf.AuthPassword, "ListPeer must not return the TCP-MD5 key")
		}
	}))
	assert.Equal(1, seen)

	// Half two: the daemon must still hold it, or MD5 silently stops working.
	assert.NoError(s.mgmtOperation(func() error {
		for _, peer := range s.neighborMap {
			peer.fsm.lock.Lock()
			pw := peer.fsm.pConf.Config.AuthPassword
			peer.fsm.lock.Unlock()
			assert.Equal(secret, pw, "the key must survive redaction of the read path")
		}
		return nil
	}, false))
}
