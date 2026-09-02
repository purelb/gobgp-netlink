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

package config

import (
	"context"
	"testing"

	api "github.com/osrg/gobgp/v4/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitialConfigStartsNetlink is a regression gate for the config-file
// startup path.
//
// Netlink is the reason this fork exists, and nothing in the unit suite
// asserted that loading a config file actually turns it on. The v4.9.0 merge
// dropped the StartNetlinkWithConfig call from InitialConfig - it survived only
// in UpdateConfig - and the result was a daemon that came up with
// "Import: false, Export: false" while still holding the previous run's kernel
// routes, so the FIB looked correct. Every gate was green: build, vet, the full
// unit suite, -race and golangci-lint. Only the hardware box found it.
//
// The assertion is deliberately about behaviour reachable from the API rather
// than about the call being present, so it survives refactoring.
func TestInitialConfigStartsNetlink(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	cfg := configWithValidPeerGroup()
	cfg.Netlink.Import.Enabled = true
	cfg.Netlink.Import.InterfaceList = []string{"lo"}

	_, err := InitialConfig(ctx, bgpServer, cfg, false)
	require.NoError(t, err)

	resp, err := bgpServer.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.ImportEnabled,
		"loading a config with netlink import enabled must start netlink; "+
			"the daemon otherwise comes up silently inert")
}
