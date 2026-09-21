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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

// Defined sets compile their input and then reported the compiled form back,
// so a client never got out what it put in. ParseCommunityRegexp anchors,
// expands a bare number to AS:VALUE and resolves a well-known name, so
// "65000:100" came back "^65000:100$" and "no_export" came back
// "^65535:65281$" with the name destroyed. A consumer diffing desired config
// against ListDefinedSet could never converge on any of these.
//
// Nothing covered this: grep for DefinedSet across the conformance suite
// returns nothing, and the one ListDefinedSet test in the tree uses
// DEFINED_TYPE_NEIGHBOR - the single type that stores plain strings and so is
// the one type that cannot show the bug.
func TestCommunitySetRoundTripsWhatWasConfigured(t *testing.T) {
	in := []string{"65000:100", "no_export", "^65100:2[0-9]*$", "4259840100"}
	s, err := NewCommunitySet(oc.CommunitySet{CommunitySetName: "c1", CommunityList: in})
	require.NoError(t, err)

	assert.Equal(t, in, s.List(), "the set must report what it was given")
	assert.Equal(t, in, s.ToConfig().CommunityList)
}

func TestLargeCommunitySetRoundTripsWhatWasConfigured(t *testing.T) {
	in := []string{"65000:100:200", "^65100:1:.*$"}
	s, err := NewLargeCommunitySet(oc.LargeCommunitySet{LargeCommunitySetName: "l1", LargeCommunityList: in})
	require.NoError(t, err)

	assert.Equal(t, in, s.List())
}

// Extended communities carry a prefix that the old List() rebuilt from the
// parsed subtype. "rt:65000:100" came back as "rt:^65000:100$".
func TestExtCommunitySetRoundTripsWhatWasConfigured(t *testing.T) {
	in := []string{"rt:65000:100", "soo:65000:200"}
	s, err := NewExtCommunitySet(oc.ExtCommunitySet{ExtCommunitySetName: "e1", ExtCommunityList: in})
	require.NoError(t, err)

	assert.Equal(t, in, s.List())
}

// Remove matches on the compiled form on purpose: "no_export",
// "65535:65281" and "^65535:65281$" are the same community, and removing by
// any spelling has always removed the entry however it was added. Recording
// originals must not change that, and the surviving entries must keep theirs.
func TestCommunitySetRemoveMatchesCompiledFormAndKeepsOriginals(t *testing.T) {
	s, err := NewCommunitySet(oc.CommunitySet{
		CommunitySetName: "c1",
		CommunityList:    []string{"65000:100", "no_export", "65000:300"},
	})
	require.NoError(t, err)

	// Remove the well-known community by its numeric spelling.
	rm, err := NewCommunitySet(oc.CommunitySet{
		CommunitySetName: "c1",
		CommunityList:    []string{"65535:65281"},
	})
	require.NoError(t, err)
	require.NoError(t, s.Remove(rm))

	assert.Equal(t, []string{"65000:100", "65000:300"}, s.List(),
		"removal by an equivalent spelling must work, and survivors keep the text they were configured with")
	assert.Len(t, s.list, 2, "the compiled list and the originals must stay in step")
}

func TestCommunitySetAppendKeepsOriginals(t *testing.T) {
	s, err := NewCommunitySet(oc.CommunitySet{CommunitySetName: "c1", CommunityList: []string{"65000:100"}})
	require.NoError(t, err)
	add, err := NewCommunitySet(oc.CommunitySet{CommunitySetName: "c1", CommunityList: []string{"no_export"}})
	require.NoError(t, err)

	require.NoError(t, s.Append(add))
	assert.Equal(t, []string{"65000:100", "no_export"}, s.List())
	assert.Len(t, s.originals, len(s.list), "originals must stay index-aligned with the compiled list")
}

// Matching must be unaffected: the compiled form is still what evaluates.
func TestCommunitySetStillMatchesAfterRecordingOriginals(t *testing.T) {
	s, err := NewCommunitySet(oc.CommunitySet{
		CommunitySetName: "c1",
		CommunityList:    []string{"no_export"},
	})
	require.NoError(t, err)
	require.Len(t, s.list, 1)
	assert.True(t, s.list[0].MatchString("65535:65281"),
		"the well-known name must still compile to a regex that matches the numeric form")
}
