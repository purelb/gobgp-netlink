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

package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func findSubcommand(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("netlink command %q not found", name)
	return nil
}

// TestNetlinkFlagDefaultsAreUnchangedSentinels pins the zero-value contract
// between this CLI and the server.
//
// The server treats a zero field as "leave it alone" and substitutes its own
// default only when nothing is configured. A non-zero default here means every
// invocation sends a value, so merely re-enabling export rewrites whatever was
// configured. That was observed on a live daemon: running with route-protocol
// 201, "gobgp netlink enable-export" reset the configuration to 186 while the
// routes already in the kernel kept protocol 201. The two then disagreed, and a
// restart would sweep for 186 and never reclaim those routes.
func TestNetlinkFlagDefaultsAreUnchangedSentinels(t *testing.T) {
	netlinkCmd := newNetlinkCmd()

	enableExport := findSubcommand(t, netlinkCmd, "enable-export")
	for _, name := range []string{"route-protocol", "dampening-interval"} {
		f := enableExport.Flags().Lookup(name)
		if assert.NotNil(t, f, "flag %q should exist", name) {
			assert.Equal(t, "0", f.DefValue,
				"%q must default to 0 so an unset flag leaves the running config alone", name)
		}
	}
}

// TestNetlinkOptionalFlagsDefaultToZero covers the rest of the surface, so a
// future flag does not reintroduce the same trap.
func TestNetlinkOptionalFlagsDefaultToZero(t *testing.T) {
	netlinkCmd := newNetlinkCmd()

	for _, tc := range []struct{ cmd, flag, want string }{
		{"enable-import", "vrf", ""},
		{"enable-import", "interfaces", ""},
		{"vrf-enable-export", "linux-vrf", ""},
		{"vrf-enable-export", "table-id", "0"},
		{"vrf-enable-export", "metric", "0"},
		{"vrf-enable-export", "communities", ""},
		{"vrf-enable-export", "large-communities", ""},
		{"vrf-enable-import", "interfaces", ""},
	} {
		t.Run(tc.cmd+"/"+tc.flag, func(t *testing.T) {
			f := findSubcommand(t, netlinkCmd, tc.cmd).Flags().Lookup(tc.flag)
			if assert.NotNil(t, f) {
				assert.Equal(t, tc.want, f.DefValue)
			}
		})
	}
}

// TestBuildVrfExportConfigNoFlagsLeavesConfigAlone is the defect this guards.
//
// vrf-enable-export built its message straight from flag values, and the server
// overwrites every field whenever a config is supplied. Enabling export on a VRF
// configured with metric 10 and validate-nexthop false therefore reset the
// metric to 0 and flipped validation on. Worse, it cleared the community filter,
// and an empty community list means "match every route" - a filtered export
// silently became unfiltered.
//
// With no configuration flags given there is nothing to change, so no config is
// sent at all and the server leaves the VRF as it was.
func TestBuildVrfExportConfigNoFlagsLeavesConfigAlone(t *testing.T) {
	cmd := findSubcommand(t, newNetlinkCmd(), "vrf-enable-export")

	config, err := buildVrfExportConfig(cmd, "kubevrf")
	assert.NoError(t, err)
	assert.Nil(t, config,
		"with no configuration flags the command must send no config at all")
}

// TestVrfExportConfigFlagsAreComplete keeps the "did anything change?" check in
// step with the flags the command actually defines. A flag missing from the list
// would be silently ignored.
func TestVrfExportConfigFlagsAreComplete(t *testing.T) {
	cmd := findSubcommand(t, newNetlinkCmd(), "vrf-enable-export")

	for _, name := range vrfExportConfigFlags {
		assert.NotNil(t, cmd.Flags().Lookup(name),
			"flag %q is listed as a config flag but not defined", name)
	}

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		assert.Contains(t, vrfExportConfigFlags, f.Name,
			"flag %q is defined but not treated as a config flag, so setting it "+
				"would be ignored", f.Name)
	})
}

func TestSplitList(t *testing.T) {
	// An empty string must mean "no entries", not one empty entry: the latter
	// would be parsed as a community and rejected.
	assert.Nil(t, splitList(""))
	assert.Equal(t, []string{"65000:1"}, splitList("65000:1"))
	assert.Equal(t, []string{"65000:1", "65000:2"}, splitList("65000:1,65000:2"))
}
