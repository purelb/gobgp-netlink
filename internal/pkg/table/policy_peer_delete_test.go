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
	"log/slog"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/config/oc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeletePeerPolicyDropsAssignment gates an unauthenticated memory leak.
//
// SetPeerPolicy is reached from the dynamic-neighbour accept path before any
// OPEN is parsed, and nothing removed the entry when the peer went away, so
// assignmentMap grew on every inbound TCP connection - no session, no
// credentials, against a 256Mi limit. A stale entry could also be applied to a
// later peer reusing the same address.
func TestDeletePeerPolicyDropsAssignment(t *testing.T) {
	r := NewRoutingPolicy(slog.Default())

	require.NoError(t, r.AddPolicy(&Policy{Name: "p1"}, true))

	const id = "10.0.0.1"
	require.NoError(t, r.AddPolicyAssignment(id, POLICY_DIRECTION_IMPORT,
		[]*oc.PolicyDefinition{{Name: "p1"}}, ROUTE_TYPE_ACCEPT))

	_, ps, err := r.GetPolicyAssignment(id, POLICY_DIRECTION_IMPORT)
	require.NoError(t, err)
	assert.Len(t, ps, 1)
	assert.Len(t, r.assignmentMap, 1)

	r.DeletePeerPolicy(id)

	assert.Empty(t, r.assignmentMap, "the assignment must not outlive the peer")
}
