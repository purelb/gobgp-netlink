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
