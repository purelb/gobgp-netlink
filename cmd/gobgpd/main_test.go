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

import "testing"

// isLoopbackHostPort decides whether the operator gets told that an
// unauthenticated endpoint is reachable off-host, so a wrong answer is a
// warning that never fires. The wildcard forms matter most: ":6060" and
// "0.0.0.0:6060" look local and are not.
func Test_isLoopbackHostPort(t *testing.T) {
	for _, tc := range []struct {
		hostPort string
		want     bool
		why      string
	}{
		{"localhost:6060", true, "the default pprof host"},
		{"127.0.0.1:50051", true, "explicit v4 loopback"},
		{"[::1]:50051", true, "explicit v6 loopback"},
		{"127.0.0.53:53", true, "all of 127/8 is loopback, not just .1"},

		{":6060", false, "empty host is the wildcard, which is every interface"},
		{"0.0.0.0:7475", false, "wildcard spelled out"},
		{"[::]:7475", false, "v6 wildcard"},
		{"192.168.1.10:7475", false, "a node address is what hostNetwork exposes"},

		{"", false, "unparseable must not read as loopback"},
		{"localhost", false, "no port, so not a bind address"},
		{"not a host:7475", false, "unresolvable must not read as loopback"},
	} {
		if got := isLoopbackHostPort(tc.hostPort); got != tc.want {
			t.Errorf("isLoopbackHostPort(%q) = %v, want %v (%s)", tc.hostPort, got, tc.want, tc.why)
		}
	}
}
