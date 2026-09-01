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

package bgp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateNextHopWithInvalidValueDoesNotPanic is a remote-crash gate.
//
// PathAttributeNextHop.DecodeFromBytes returns before assigning Value when the
// attribute length is neither 4 nor 16, leaving Value as the zero netip.Addr.
// treat-as-withdraw is on by default, so the attribute is kept rather than
// discarded and reaches validation, where AsSlice() yields an empty slice and
// the old isZero/isClassDorE closures indexed ip[0] unconditionally.
//
// A plain IPv4 UPDATE carrying a 5-byte NEXT_HOP was therefore enough to kill
// the daemon. This is GHSA-4p9m-8gc4-rw2h, which has no published fixed
// version upstream - v4.9.0 still contains the unguarded index.
func TestValidateNextHopWithInvalidValueDoesNotPanic(t *testing.T) {
	for _, length := range []uint16{0, 1, 5, 15, 17} {
		attr := &PathAttributeNextHop{
			PathAttribute: PathAttribute{
				Flags:  BGP_ATTR_FLAG_TRANSITIVE,
				Type:   BGP_ATTR_TYPE_NEXT_HOP,
				Length: length,
			},
			// Value deliberately left as the zero Addr: the state a
			// length-error decode leaves behind.
		}
		assert.False(t, attr.Value.IsValid())

		ok, err := ValidateAttribute(attr, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_NONE},
			true /* isEBGP */, false /* isConfed */, false /* loopbackNextHopAllowed */)
		_ = ok
		_ = err
	}
}
