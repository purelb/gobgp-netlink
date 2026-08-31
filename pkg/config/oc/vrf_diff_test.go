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
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func vrfDiffLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testVrf(name, rd string) Vrf {
	v := Vrf{}
	v.Config.Name = name
	v.Config.Rd = rd
	return v
}

func names(vrfs []Vrf) []string {
	out := make([]string, 0, len(vrfs))
	for _, v := range vrfs {
		out = append(out, v.Config.Name)
	}
	return out
}

func TestUpdateVrfConfigAddAndDelete(t *testing.T) {
	cur := &BgpConfigSet{Vrfs: []Vrf{testVrf("keep", "64553:1"), testVrf("gone", "64553:2")}}
	next := &BgpConfigSet{Vrfs: []Vrf{testVrf("keep", "64553:1"), testVrf("fresh", "64553:3")}}

	added, deleted, updated := UpdateVrfConfig(vrfDiffLogger(), cur, next)

	assert.Equal(t, []string{"fresh"}, names(added))
	assert.Equal(t, []string{"gone"}, names(deleted))
	assert.Empty(t, updated, "an unchanged VRF must not be recreated")
}

// TestUpdateVrfConfigRenameIsAddPlusDelete: a rename has no identity to match
// on, so it is a delete of the old name and an add of the new one. That is
// exactly the case a reload previously ignored entirely.
func TestUpdateVrfConfigRenameIsAddPlusDelete(t *testing.T) {
	cur := &BgpConfigSet{Vrfs: []Vrf{testVrf("kubevrf", "64553:175")}}
	next := &BgpConfigSet{Vrfs: []Vrf{testVrf("kubevrf0", "64553:175")}}

	added, deleted, updated := UpdateVrfConfig(vrfDiffLogger(), cur, next)

	assert.Equal(t, []string{"kubevrf0"}, names(added))
	assert.Equal(t, []string{"kubevrf"}, names(deleted))
	assert.Empty(t, updated)
}

// TestUpdateVrfConfigNetlinkOnlyChangeIsNotStructural is the important one.
//
// Vrf.Equal covers the netlink blocks as well as identity, so comparing whole
// VRFs would report a changed export metric as an update - and an update means
// delete and re-add, moving every route in the VRF. Netlink changes are applied
// separately by StartNetlinkWithConfig and must not appear here.
func TestUpdateVrfConfigNetlinkOnlyChangeIsNotStructural(t *testing.T) {
	before := testVrf("kubevrf0", "64553:175")
	before.NetlinkExport.Enabled = true
	before.NetlinkExport.Metric = 10

	after := testVrf("kubevrf0", "64553:175")
	after.NetlinkExport.Enabled = true
	after.NetlinkExport.Metric = 25
	after.NetlinkImport.Enabled = true
	after.NetlinkImport.InterfaceList = []string{"kubevrf0"}

	// Guard the premise: whole-VRF equality does see this change.
	assert.False(t, after.Equal(&before), "the netlink blocks did change")

	added, deleted, updated := UpdateVrfConfig(vrfDiffLogger(),
		&BgpConfigSet{Vrfs: []Vrf{before}}, &BgpConfigSet{Vrfs: []Vrf{after}})

	assert.Empty(t, added)
	assert.Empty(t, deleted)
	assert.Empty(t, updated,
		"a netlink-only change must not recreate the VRF and move its routes")
}

// TestUpdateVrfConfigIdentityChangeIsStructural: RD or route targets changing
// genuinely cannot be applied in place.
func TestUpdateVrfConfigIdentityChangeIsStructural(t *testing.T) {
	for _, tt := range []struct {
		name  string
		apply func(*Vrf)
	}{
		{"rd", func(v *Vrf) { v.Config.Rd = "64553:999" }},
		{"import-rt", func(v *Vrf) { v.Config.ImportRtList = []string{"64553:9"} }},
		{"export-rt", func(v *Vrf) { v.Config.ExportRtList = []string{"64553:9"} }},
		{"id", func(v *Vrf) { v.Config.Id = 7 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := testVrf("kubevrf0", "64553:175")
			after := testVrf("kubevrf0", "64553:175")
			tt.apply(&after)

			added, deleted, updated := UpdateVrfConfig(vrfDiffLogger(),
				&BgpConfigSet{Vrfs: []Vrf{before}}, &BgpConfigSet{Vrfs: []Vrf{after}})

			assert.Empty(t, added)
			assert.Empty(t, deleted)
			assert.Equal(t, []string{"kubevrf0"}, names(updated))
		})
	}
}

func TestUpdateVrfConfigNoVrfsEitherSide(t *testing.T) {
	added, deleted, updated := UpdateVrfConfig(vrfDiffLogger(), &BgpConfigSet{}, &BgpConfigSet{})
	assert.Empty(t, added)
	assert.Empty(t, deleted)
	assert.Empty(t, updated)
}
