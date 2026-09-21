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
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The API socket's mode used to be whatever the process umask left behind.
// Go creates it 0777 &^ umask, so it varied by deployment and nothing said so.
func TestUnixSocketModeIsExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.sock")

	lis, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer lis.Close()

	require.NoError(t, hardenUnixSocket(path, slog.Default()))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(apiSocketMode), fi.Mode().Perm(),
		"the API is a write interface; its socket must not inherit the umask")
}

// Abstract sockets have no filesystem presence and therefore no permissions:
// any process in the network namespace can connect, which under a hostNetwork
// DaemonSet is every process on the node. os.Chmod on one returns ENOENT, so a
// mode cannot be applied after the fact either - it has to be refused up front.
func TestAbstractUnixSocketIsRefused(t *testing.T) {
	err := checkUnixSocketPath("@gobgp", slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "abstract")

	// A normal path is fine.
	assert.NoError(t, checkUnixSocketPath("/var/run/gobgp/api.sock", slog.Default()))
}

// parseHost decides which of these a host string is, so the abstract check has
// to see what it produces.
func TestParseHostRecognisesAbstractSocket(t *testing.T) {
	network, address := parseHost("unix://@gobgp")
	assert.Equal(t, "unix", network)
	assert.Equal(t, "@gobgp", address,
		"an abstract socket reaches net.Listen as @name, which is what must be refused")
}
