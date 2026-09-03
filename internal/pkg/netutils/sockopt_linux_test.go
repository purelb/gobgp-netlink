// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

//go:build linux

package netutils

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func Test_buildTcpMD5Sig(t *testing.T) {
	s := buildTcpMD5Sig(nil, "1.2.3.4", "hello")

	if unsafe.Sizeof(*s) != 216 {
		t.Error("TCPM5Sig struct size is wrong", unsafe.Sizeof(s))
	}

	buf1 := new(bytes.Buffer)
	if err := binary.Write(buf1, binary.LittleEndian, s); err != nil {
		t.Error(err)
	}

	buf2 := []uint8{2, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	if bytes.Equal(buf1.Bytes(), buf2) {
		t.Log("OK")
	} else {
		t.Error("Something wrong v4")
	}
}

func Test_buildTcpMD5Sigv6(t *testing.T) {
	s := buildTcpMD5Sig(nil, "fe80::4850:31ff:fe01:fc55", "helloworld")

	buf1 := new(bytes.Buffer)
	if err := binary.Write(buf1, binary.LittleEndian, s); err != nil {
		t.Error(err)
	}

	buf2 := []uint8{10, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 72, 80, 49, 255, 254, 1, 252, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 119, 111, 114, 108, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	buf2[0] = syscall.AF_INET6

	if bytes.Equal(buf1.Bytes(), buf2) {
		t.Log("OK")
	} else {
		t.Error("Something wrong v6")
	}
}

func Test_buildTcpMD5Sig_bindInterface(t *testing.T) {
	tests := []struct {
		name            string
		bindInterface   netlink.Link
		expectedIfindex int32
	}{
		{
			name:            "Unspecified bindInterface",
			bindInterface:   nil,
			expectedIfindex: 0,
		},
		{
			name: "VRF bindInterface",
			bindInterface: &netlink.Vrf{
				LinkAttrs: netlink.LinkAttrs{
					Index: 123,
				},
			},
			expectedIfindex: 123,
		},
		{
			name: "Non-VRF bindInterface",
			bindInterface: &netlink.GenericLink{
				LinkAttrs: netlink.LinkAttrs{
					Index: 123,
				},
			},
			expectedIfindex: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Don't confuse IPv6 zone with ifindex
			s := buildTcpMD5Sig(tt.bindInterface, "fe80::4850:31ff:fe01:fc55%456", "helloworld")
			require.NotNil(t, s, "Gen md5 sig failed")
			if s.Ifindex != tt.expectedIfindex {
				t.Errorf("Unexpected ifindex value for %T: got %d, want %d", tt.bindInterface, s.Ifindex, tt.expectedIfindex)
			}
		})
	}
}

func Test_buildTcpMD5Sig_CIDR(t *testing.T) {
	v4buff := [216]uint8{2, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 24, 5, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 0}
	v6buff := [216]uint8{10, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 72, 80, 49, 255, 254, 1, 252, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 5, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 0}
	tests := []struct {
		name     string
		addr     string
		expected []byte
	}{
		{"v4", "1.2.3.0/24", v4buff[:]},
		{"v6", "fe80::4850:31ff:fe01:fc55/64", v6buff[:]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := buildTcpMD5Sig(nil, tt.addr, "hello")
			if sig == nil {
				t.Fatal("Gen md5 sig failed")
			}
			got := new(bytes.Buffer)
			if err := binary.Write(got, binary.LittleEndian, sig); err != nil {
				t.Error(err)
			}
			if bytes.Equal(got.Bytes(), tt.expected) {
				t.Log("OK")
			} else {
				t.Error("Something wrong with cidr")
			}
		})
	}
}

// TestRecvHopLimitReportsTheTTL proves RFC 5881 §5 is actually enforceable on
// receive, on a real socket.
//
// Transmission already set TTL 255, but the receive path used ReadFromUDP and
// never asked the kernel for the value, so the discard rule could not be
// applied and GTSM was one-directional. A unit test of the parser alone would
// not have caught that: the gap was that nothing ever requested the control
// message.
func TestRecvHopLimitReportsTheTTL(t *testing.T) {
	// Both shapes matter. The BFD server binds ":3784", which is dual-stack,
	// but a v4-only socket rejects the IPv6 option outright - and returning
	// that error disabled the check on exactly the sockets where IP_RECVTTL
	// had in fact been applied.
	for _, addr := range []string{"127.0.0.1:0", ":0"} {
		t.Run(addr, func(t *testing.T) { testRecvHopLimit(t, addr) })
	}
}

func testRecvHopLimit(t *testing.T, listenAddr string) {
	var setErr error
	var lc net.ListenConfig
	lc.Control = func(_, _ string, sc syscall.RawConn) error {
		setErr = SetRecvHopLimitSockopt(sc)
		return nil
	}

	c, err := lc.ListenPacket(context.Background(), "udp", listenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer c.Close()
	if setErr != nil {
		t.Fatalf("SetRecvHopLimitSockopt: %v", setErr)
	}

	uc, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatal("not a UDP connection")
	}

	target := uc.LocalAddr().String()
	if listenAddr == ":0" {
		target = fmt.Sprintf("127.0.0.1:%d", uc.LocalAddr().(*net.UDPAddr).Port)
	}
	d, err := net.Dial("udp", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer d.Close()
	if _, err := d.Write([]byte("probe")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := uc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 64)
	oob := make([]byte, 128)
	_, oobn, _, _, err := uc.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatalf("readmsg: %v", err)
	}

	hopLimit, present := ParseHopLimit(oob[:oobn])
	if !present {
		t.Fatal("no TTL control message: the discard rule cannot be enforced, " +
			"which is exactly the gap this exists to close")
	}
	// Loopback delivers the sender's default TTL, not 255; the point is that a
	// value is reported at all, so a wrong one can be rejected.
	if hopLimit <= 0 || hopLimit > 255 {
		t.Fatalf("implausible hop limit %d", hopLimit)
	}
}
