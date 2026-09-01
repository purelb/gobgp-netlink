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

package oc

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfigStructConvertersKeepAuthPassword pins the reason ListPeer redacts
// at the read site instead of here.
//
// These converters look like read-path helpers and are the obvious place to
// strip a secret, but InitialConfig also uses them to build AddPeer and
// AddPeerGroup requests, and grpc_server reads Conf.AuthPassword back out of
// those to populate pconf. Redacting here would therefore silently disable
// TCP-MD5 for every TOML-configured session - the session would still come up,
// just unauthenticated, which is worse than failing.
func TestConfigStructConvertersKeepAuthPassword(t *testing.T) {
	const secret = "correct-horse-battery-staple"

	n := &Neighbor{}
	n.Config.NeighborAddress = netip.MustParseAddr("10.0.0.1")
	n.Config.PeerAs = 65001
	n.Config.AuthPassword = secret
	assert.Equal(t, secret, NewPeerFromConfigStruct(n).Conf.AuthPassword,
		"InitialConfig feeds this into AddPeer; redacting here disables MD5")

	pg := &PeerGroup{}
	pg.Config.PeerGroupName = "g1"
	pg.Config.PeerAs = 65001
	pg.Config.AuthPassword = secret
	assert.Equal(t, secret, NewPeerGroupFromConfigStruct(pg).Conf.AuthPassword,
		"InitialConfig feeds this into AddPeerGroup; redacting here disables MD5")
}
