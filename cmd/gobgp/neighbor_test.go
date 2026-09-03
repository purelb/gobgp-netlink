// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
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
	"time"

	"github.com/osrg/gobgp/v4/api"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func Test_makeShowRouteArgsUndecodableNlri(t *testing.T) {
	assert := assert.New(t)
	// A path whose NLRI cannot be decoded must not panic the CLI formatter.
	p := &api.Path{}
	var args []any
	assert.NotPanics(func() {
		args = makeShowRouteArgs(p, 0, time.Now(), false, true, false, false, false, bgp.BGP_ADD_PATH_NONE)
	})
	assert.Contains(args, "?")
}

// TestBfdStateNameDoesNotLeakTheEnumNumber pins the rendering that stops an
// operator reading the session state as its opposite.
//
// This proto numbers UP as 1, but RFC 5880 6.8.1 numbers Down as 1 and Up as 3.
// Anyone who knows BFD and reads the raw JSON value therefore reads a healthy
// session as a dead one - which is exactly what happened while diagnosing a live
// session on hardware.
func TestBfdStateNameDoesNotLeakTheEnumNumber(t *testing.T) {
	assert.Equal(t, "UP", bfdStateName(api.BfdSessionState_BFD_SESSION_STATE_UP))
	assert.Equal(t, "DOWN", bfdStateName(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	assert.Equal(t, "ADMIN_DOWN", bfdStateName(api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN))
	assert.Equal(t, "-", bfdStateName(api.BfdSessionState_BFD_SESSION_STATE_UNSPECIFIED),
		"an unset state must not print as a word implying a real session state")

	// The value that must never reach an operator as a bare number.
	assert.Equal(t, api.BfdSessionState(1), api.BfdSessionState_BFD_SESSION_STATE_UP,
		"if this changes, the rendering above is what keeps operators correct")
}

// TestBfdIntervalRendersMicrosecondsAsTime: intervals are configured and
// reported in microseconds, and the pyang-generated Go drops the YANG `units`
// comment, so the number alone invites being read as milliseconds. 300 entered
// as "300ms" is 300us - roughly 3,300 packets a second per peer.
func TestBfdIntervalRendersMicrosecondsAsTime(t *testing.T) {
	assert.Equal(t, "300ms", bfdInterval(300000))
	assert.Equal(t, "1s", bfdInterval(1000000))
	assert.Equal(t, "300µs", bfdInterval(300),
		"the mis-entered value must render visibly wrong, not plausibly right")
}
