//go:build linux

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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRouteProtocol(t *testing.T) {
	for _, tt := range []struct {
		name  string
		proto int
		ok    bool
	}{
		{"RTPROT_BGP", RTPROT_BGP, true},
		{"upper bound", 255, true},
		{"lower bound", 5, true},

		// Out of range. Negative is reachable because the API field is int32,
		// and it is the worst case: the netlink library only writes the protocol
		// when > 0, so routes would install as RTPROT_UNSPEC while the cleanup
		// filter still looked for the negative value.
		{"zero", 0, false},
		{"negative", -1, false},
		{"above 255", 256, false},
		{"far above", 100000, false},

		// Reserved. Using one of these would make the cleanup sweep delete the
		// system's own routes.
		{"RTPROT_REDIRECT", 1, false},
		{"RTPROT_KERNEL", 2, false},
		{"RTPROT_BOOT", 3, false},
		{"RTPROT_STATIC", 4, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteProtocol(tt.proto)
			if tt.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestSweepTablesOnlyConfiguredTables pins the narrowing: the stale-route sweep
// may only touch tables this daemon is configured to export into.
//
// Previously it enumerated the main table plus every VRF table present on the
// host, so it deleted other daemons' routes in tables it never writes to.
func TestSweepTablesOnlyConfiguredTables(t *testing.T) {
	e := &netlinkExportClient{
		rules: []*exportRule{
			{Name: "a", TableId: 100},
			{Name: "b", TableId: 200},
			{Name: "dup", TableId: 100},
		},
		vrfRules: map[string]*vrfExportConfig{
			"red": {VrfName: "red", LinuxTableId: 300},
		},
	}
	assert.Equal(t, []int{100, 200, 300}, e.sweepTables())
}

func TestSweepTablesIncludesMainOnlyWhenNamed(t *testing.T) {
	// TableId 0 means the main table, and it is the default for a global rule,
	// so naming it is how an operator opts main in.
	withMain := &netlinkExportClient{rules: []*exportRule{{Name: "global", TableId: 0}}}
	assert.Equal(t, []int{0}, withMain.sweepTables())

	// A rule for a dedicated table must not pull the main table in with it.
	withoutMain := &netlinkExportClient{rules: []*exportRule{{Name: "vrfonly", TableId: 100}}}
	assert.Equal(t, []int{100}, withoutMain.sweepTables())
}

func TestSweepTablesEmptyWithoutRules(t *testing.T) {
	// No rules means this daemon owns nothing, so there is nothing to reconcile
	// and the sweep must not run at all.
	e := &netlinkExportClient{}
	assert.Empty(t, e.sweepTables())
}

// TestCleanupStaleRoutesRunsOnce guards the invariant that the sweep is a
// startup reconciliation.
//
// StartNetlink runs on every enable and config change. A second sweep would
// delete this daemon's own live routes while e.exported still listed them, after
// which exportRoute's idempotency check returns early and never reprograms them.
func TestCleanupStaleRoutesRunsOnce(t *testing.T) {
	// No rules, so cleanupStaleRoutes returns before touching the kernel and the
	// test needs no privileges.
	e := &netlinkExportClient{logger: logger}

	assert.False(t, e.sweptStaleRoutes)
	assert.NoError(t, e.cleanupStaleRoutesOnce())
	assert.True(t, e.sweptStaleRoutes)

	// Second call must be a no-op.
	assert.NoError(t, e.cleanupStaleRoutesOnce())
	assert.True(t, e.sweptStaleRoutes)
}
