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
	assert.Equal(t, secret, NewPeerFromConfigStruct(n).Conf.GetAuthPassword(),
		"InitialConfig feeds this into AddPeer; redacting here disables MD5")

	pg := &PeerGroup{}
	pg.Config.PeerGroupName = "g1"
	pg.Config.PeerAs = 65001
	pg.Config.AuthPassword = secret
	assert.Equal(t, secret, NewPeerGroupFromConfigStruct(pg).Conf.GetAuthPassword(),
		"InitialConfig feeds this into AddPeerGroup; redacting here disables MD5")
}

// The flag has to be derived where the password still exists, and the password
// itself must not travel with it.
//
// PeerState.AuthPassword is declared in the proto and written by nothing, and
// ListPeer redacts Conf.AuthPassword on the way out - so the metric that read
// GetAuthPassword() != "" reported "no authentication" for every peer forever,
// including MD5 ones. The negative half of this test is the important half:
// State is not redacted anywhere, so a password placed there would leave the
// server through ListPeer and `gobgp neighbor -j`.
func TestNewPeerFromConfigStructSetsAuthPasswordSetFlagOnly(t *testing.T) {
	assert := assert.New(t)

	withPassword := &Neighbor{}
	withPassword.Config.NeighborAddress = netip.MustParseAddr("10.0.0.1")
	withPassword.Config.AuthPassword = "correct-horse-battery-staple"

	p := NewPeerFromConfigStruct(withPassword)
	assert.NotNil(p)
	assert.True(p.GetState().GetAuthPasswordSet(), "an MD5-configured peer must report the flag")
	assert.Empty(p.GetState().GetAuthPassword(),
		"State carries the flag, never the password: nothing redacts State")

	without := &Neighbor{}
	without.Config.NeighborAddress = netip.MustParseAddr("10.0.0.2")

	q := NewPeerFromConfigStruct(without)
	assert.NotNil(q)
	assert.False(q.GetState().GetAuthPasswordSet(), "a peer with no password must report false")
	assert.Empty(q.GetState().GetAuthPassword())
}
