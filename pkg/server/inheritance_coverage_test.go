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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

// Every configuration block that peer-group inheritance can overwrite must
// either have a presence signal recorded for it, or be recorded as having
// none, with the reason.
//
// This is the property the rest of the inheritance work was missing. The
// per-block inheritance tests in pkg/config/oc assert the right things, but
// they assert them about the blocks someone remembered to add to the table: a
// block in neither the presence map nor the test table fails nothing. That is
// how as-path options went a release with a grouped neighbor's allow-own-as,
// replace-peer-as and allow-aspath-loop-local silently replaced by the group's
// zeros - the same defect as graceful restart, in a block nobody looked at.
//
// The blocks are derived from oc.Neighbor rather than listed, so a block added
// by an upstream catch-up merge arrives here as a failure rather than as
// silence.
func TestEveryInheritedBlockHasAPresenceDecision(t *testing.T) {
	for _, block := range inheritableBlocks() {
		_, recorded := neighborPresenceBlocks[block]
		reason, excused := neighborBlocksWithNothingToRecord[block]

		assert.True(t, recorded || excused,
			"configuration block %q is overwritten by peer-group inheritance but has no presence decision. "+
				"Either record it in neighborPresenceBlocks, so a neighbor that sends it keeps it, or add it to "+
				"neighborBlocksWithNothingToRecord saying why the API cannot express it. Left undecided, a "+
				"grouped neighbor's settings in this block are silently replaced by the peer group's zero values.",
			block)
		assert.False(t, recorded && excused, "block %q is in both maps", block)
		if excused {
			assert.NotEmpty(t, reason, "block %q needs a reason, not an empty string", block)
		}
	}
}

// And nothing may be recorded that inheritance does not actually touch, so the
// two lists cannot drift apart in the other direction either.
func TestNoPresenceRecordedForBlocksInheritanceIgnores(t *testing.T) {
	inheritable := map[string]bool{}
	for _, b := range inheritableBlocks() {
		inheritable[b] = true
	}
	for block := range neighborPresenceBlocks {
		assert.True(t, inheritable[block],
			"presence is recorded for %q, but peer-group inheritance does not overwrite it", block)
	}
	for block := range neighborBlocksWithNothingToRecord {
		assert.True(t, inheritable[block],
			"%q is excused from presence, but peer-group inheritance does not overwrite it either", block)
	}
}

// inheritableBlocks is every named configuration block on an oc.Neighbor: a
// field whose type carries a Config of its own. That is exactly the shape
// OverwriteNeighborConfigWithPeerGroup copies, so deriving it here keeps this
// check honest without a second hand-maintained list to fall out of date.
func inheritableBlocks() []string {
	var out []string
	t := reflect.TypeOf(oc.Neighbor{})
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("mapstructure")
		if tag == "" || tag == "state" || tag == "afi-safis" {
			// state is read-only; afi-safis is a list and is inherited
			// wholesale rather than through overwriteConfig.
			continue
		}
		if f.Type.Kind() != reflect.Struct {
			continue
		}
		// "config" is itself a block here: NeighborConfig is copied directly.
		if tag == "config" {
			out = append(out, tag)
			continue
		}
		if _, ok := f.Type.FieldByName("Config"); ok {
			out = append(out, tag)
		}
	}
	return out
}
