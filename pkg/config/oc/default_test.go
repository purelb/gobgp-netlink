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

// OverwriteNeighborConfigWithPeerGroup had no test of any kind before the BFD
// inheritance change, which alters what it does for every grouped neighbor on
// both config paths. These were written against the old behaviour first so
// that the assertions which flipped could be seen to be the intended ones and
// no others; two did, and they now state the new contract.
//
// Every case uses its own neighbor address. configuredFields is a package
// global that RegisterConfiguredFields only ever adds to - nothing prunes it,
// and other packages' tests register into it too - so sharing an address
// between cases makes the result depend on test ordering and -run filtering.

func neighborWithBfd(addr string, group string, bfd BfdConfig) *Neighbor {
	n := &Neighbor{}
	n.Config.NeighborAddress = netip.MustParseAddr(addr)
	n.Config.PeerGroup = group
	n.Bfd.Config = bfd
	return n
}

func peerGroupWithBfd(name string, bfd BfdConfig) *PeerGroup {
	pg := &PeerGroup{}
	pg.Config.PeerGroupName = name
	pg.Bfd.Config = bfd
	return pg
}

// tomlNeighbor mirrors what the TOML loader hands RegisterConfiguredFields:
// the raw parsed neighbor entry, which is what v.IsSet is asked about.
func tomlNeighbor(addr string, bfd map[string]any) map[string]any {
	n := map[string]any{
		"config": map[string]any{"neighbor-address": addr},
	}
	if bfd != nil {
		n["bfd"] = map[string]any{"config": bfd}
	}
	return n
}

// A neighbor configured over gRPC keeps its own BFD settings. Nothing
// populates configuredFields on that path, so the per-field IsSet check used
// to be false for every BFD field and the group won them all - a group with
// no BFD block erased the neighbor's settings with its zero values.
func Test_OverwriteNeighborConfigWithPeerGroup_GrpcPathKeepsNeighborBfd(t *testing.T) {
	assert := assert.New(t)

	own := BfdConfig{
		Enabled:                  true,
		Port:                     9999,
		DetectionMultiplier:      7,
		DesiredMinimumTxInterval: 50000,
		RequiredMinimumReceive:   50000,
	}
	n := neighborWithBfd("198.51.100.1", "edge", own)
	pg := peerGroupWithBfd("edge", BfdConfig{})

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(own, n.Bfd.Config, "a group with no BFD block must not erase the neighbor's")
}

// The opt-out that per-field presence could never express: `enabled = false`
// on a neighbor in a group that has BFD on. false is the zero value, so a
// field-presence check cannot tell it from unset - only a block-level one can.
// The other fields are populated because that is how the block arrives from a
// CRD with defaults, and it is what makes the block non-empty.
func Test_OverwriteNeighborConfigWithPeerGroup_NeighborCanOptOutOfGroupBfd(t *testing.T) {
	assert := assert.New(t)

	optOut := BfdConfig{
		Enabled:                  false,
		Port:                     3784,
		DetectionMultiplier:      3,
		DesiredMinimumTxInterval: 1000000,
		RequiredMinimumReceive:   1000000,
	}
	n := neighborWithBfd("198.51.100.6", "edge", optOut)
	pg := peerGroupWithBfd("edge", BfdConfig{
		Enabled:                  true,
		Port:                     3784,
		DetectionMultiplier:      3,
		DesiredMinimumTxInterval: 300000,
		RequiredMinimumReceive:   300000,
	})

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.False(n.Bfd.Config.Enabled, "the neighbor opted out and the group must not turn BFD back on")
	assert.Equal(optOut, n.Bfd.Config)
}

// The inverse, and the behaviour that must survive the fix: a neighbor that
// configured no BFD inherits the group's.
func Test_OverwriteNeighborConfigWithPeerGroup_GrpcPathInheritsGroupBfd(t *testing.T) {
	assert := assert.New(t)

	groupBfd := BfdConfig{
		Enabled:                  true,
		Port:                     3784,
		DetectionMultiplier:      3,
		DesiredMinimumTxInterval: 300000,
		RequiredMinimumReceive:   300000,
	}
	n := neighborWithBfd("198.51.100.2", "edge", BfdConfig{})
	pg := peerGroupWithBfd("edge", groupBfd)

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(groupBfd, n.Bfd.Config, "a neighbor with no BFD block inherits the group's")
}

// BFD inherits as a whole block on the TOML path too. This used to be
// per-field - a neighbor setting only `enabled` inherited the group's port
// and intervals - and narrowing it is the deliberate cost of making
// `enabled = false` a working opt-out. The fields the neighbor left out stay
// zero here and pick up the global defaults later in
// setDefaultNeighborConfigValuesWithViper, not the group's values.
func Test_OverwriteNeighborConfigWithPeerGroup_TomlPathOverridesWholeBlock(t *testing.T) {
	assert := assert.New(t)

	const addr = "198.51.100.3"
	RegisterConfiguredFields(addr, tomlNeighbor(addr, map[string]any{"enabled": true}))

	n := neighborWithBfd(addr, "edge", BfdConfig{Enabled: true})
	pg := peerGroupWithBfd("edge", BfdConfig{
		Enabled:                  true,
		Port:                     4784,
		DetectionMultiplier:      9,
		DesiredMinimumTxInterval: 700000,
		RequiredMinimumReceive:   700000,
	})

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(BfdConfig{Enabled: true}, n.Bfd.Config,
		"the neighbor's block is kept whole; nothing is taken from the group")
}

// A TOML neighbor that set no BFD fields inherits the whole block, the same
// as the gRPC path.
func Test_OverwriteNeighborConfigWithPeerGroup_TomlPathWithoutBfdInherits(t *testing.T) {
	assert := assert.New(t)

	const addr = "198.51.100.4"
	RegisterConfiguredFields(addr, tomlNeighbor(addr, nil))

	groupBfd := BfdConfig{Enabled: true, Port: 3784, DetectionMultiplier: 3}
	n := neighborWithBfd(addr, "edge", BfdConfig{})
	pg := peerGroupWithBfd("edge", groupBfd)

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(groupBfd, n.Bfd.Config)
}

// newDynamicPeer calls this directly and then calls
// SetDefaultNeighborConfigValues, which calls it again, because State.LocalAs
// is still zero at that point and the idempotence guard does not fire. Running
// it twice must not produce a different answer from running it once - the
// property the BFD fix has to preserve, since after the first call the
// neighbor's block is no longer empty.
func Test_OverwriteNeighborConfigWithPeerGroup_IsIdempotent(t *testing.T) {
	assert := assert.New(t)

	groupBfd := BfdConfig{Enabled: true, Port: 3784, DetectionMultiplier: 3}
	pg := peerGroupWithBfd("edge", groupBfd)

	n := neighborWithBfd("198.51.100.5", "edge", BfdConfig{})
	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))
	once := n.Bfd.Config

	assert.NoError(OverwriteNeighborConfigWithPeerGroup(n, pg))
	assert.Equal(once, n.Bfd.Config, "a second overwrite must not change the result")
}
