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
	"encoding/binary"
	"net"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

// TestRecvMessageUnknownTypeDoesNotPanic is a remote-crash regression gate.
//
// ParseBGPBody returns a nil *BGPMessage together with an error for a
// header-level failure such as an unknown message type. handlingError then
// dereferences m.Header.Type, so before the guard this killed the process.
//
// It matters because the path is reachable in OPENSENT, before any OPEN has
// been validated: 19 bytes from anything that can complete a TCP handshake to
// port 179, with no credentials and no session. The container entrypoint exits
// 0 on a panic, so it does not even present as a crash.
func TestRecvMessageUnknownTypeDoesNotPanic(t *testing.T) {
	local, remote := net.Pipe()
	p, h := makePeerAndHandler(local)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	// A well-formed 19-byte header declaring a message type that does not exist.
	msg := make([]byte, 19)
	for i := range 16 {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], 19)
	msg[18] = 99

	go func() {
		_, _ = remote.Write(msg)
	}()

	stateReasonCh := make(chan fsmStateReason, 1)
	fmsg, err := h.recvMessageWithError(local, stateReasonCh)

	// The contract is "reset the session", not "die". SESSION_RESET returns the
	// parse error alongside the message, so a non-nil error is expected here.
	assert.EqualError(t, err, "unknown message type")
	if assert.NotNil(t, fmsg) {
		assert.Equal(t, bgp.ERROR_HANDLING_SESSION_RESET, fmsg.handling,
			"a header-level parse failure must reset the session, not crash")
	}
}
