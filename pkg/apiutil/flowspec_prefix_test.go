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

package apiutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The flow spec prefix component validated its address and not its prefix
// length, then built the prefix with netip.MustParsePrefix - so a prefix_len
// the address cannot carry panicked instead of erroring. Reachable from AddPath
// and AddPathStream, on the gRPC handler goroutine.
//
// The zone case is the subtle one: netip.ParseAddr accepts "fe80::1%eth0" and
// netip.ParsePrefix rejects a zone outright, so an address that passed the
// check immediately above still blew up.
func TestFlowSpecPrefixLengthIsValidated(t *testing.T) {
	mk := func(prefix string, prefixLen uint32, family bgp.Family) error {
		rule := &api.FlowSpecRule{Rule: &api.FlowSpecRule_IpPrefix{
			IpPrefix: &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_DST_PREFIX),
				Prefix:    prefix,
				PrefixLen: prefixLen,
			},
		}}
		_, err := UnmarshalNLRI(family, &api.NLRI{Nlri: &api.NLRI_FlowSpec{
			FlowSpec: &api.FlowSpecNLRI{Rules: []*api.FlowSpecRule{rule}},
		}})
		return err
	}

	t.Run("prefix length beyond the address width is an error", func(t *testing.T) {
		err := mk("10.0.0.0", 33, bgp.RF_FS_IPv4_UC)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid prefix")
	})

	t.Run("absurd prefix length is an error", func(t *testing.T) {
		err := mk("10.0.0.0", 4000, bgp.RF_FS_IPv4_UC)
		require.Error(t, err)
	})

	t.Run("zoned address is an error, not a panic", func(t *testing.T) {
		// ParseAddr accepts the zone, ParsePrefix does not.
		err := mk("fe80::1%eth0", 64, bgp.RF_FS_IPv6_UC)
		require.Error(t, err)
	})

	t.Run("a valid prefix still works", func(t *testing.T) {
		require.NoError(t, mk("10.0.0.0", 24, bgp.RF_FS_IPv4_UC))
	})
}
