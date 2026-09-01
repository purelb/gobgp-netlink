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

package table

import (
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

// TestAdjRibWithdrawUnknownPrefixDoesNotLeak is a memory-exhaustion gate.
//
// Update calls getOrCreateDest before it knows whether the path is a withdraw,
// so a withdraw for a prefix the peer never advertised creates a destination
// that nothing removes. A peer can therefore grow the Adj-RIB without ever
// advertising a route, which against the deployment's 256Mi limit is an
// unauthenticated OOM primitive.
func TestAdjRibWithdrawUnknownPrefixDoesNotLeak(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
	family := bgp.RF_IPv4_UC
	adj := NewAdjRib(slog.Default(), []bgp.Family{family})

	withdraws := make([]*Path, 0, 100)
	for i := range 100 {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", i)))
		assert.NoError(t, err)
		withdraws = append(withdraws,
			NewPath(family, pi, bgp.PathNLRI{NLRI: nlri}, true, attrs, time.Now(), false))
	}

	adj.Update(withdraws)

	assert.Empty(t, adj.table[family].GetDestinations(),
		"withdrawing never-advertised prefixes must not leave destinations behind")
	assert.Equal(t, 0, adj.Count([]bgp.Family{family}))
}
