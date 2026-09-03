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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	ipv6MinHopCount = 73 // Generalized TTL Security Mechanism (RFC5082)
)

func buildTcpMD5Sig(bindInterface netlink.Link, address, key string) *unix.TCPMD5Sig {
	t := unix.TCPMD5Sig{}

	var addr netip.Addr
	var err error
	if strings.Contains(address, "/") {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil
		}
		addr = prefix.Addr()
		t.Prefixlen = uint8(prefix.Bits())
		t.Flags |= unix.TCP_MD5SIG_FLAG_PREFIX
	} else {
		addr, err = netip.ParseAddr(address)
		if err != nil {
			return nil
		}
	}

	if addr.Is4() {
		t.Addr.Family = unix.AF_INET
		bits := addr.As4()
		copy(t.Addr.Data[2:], bits[:])
	} else if addr.Is6() {
		t.Addr.Family = unix.AF_INET6
		bits := addr.As16()
		copy(t.Addr.Data[6:], bits[:])
	} else {
		return nil
	}

	// Ifindex option is only valid for VRF device. It's still valid
	// to set md5sig for the socket bound to non-VRF device, but in
	// that case, Ifindex shouldn't be set.
	//
	// Ref: https://github.com/torvalds/linux/commit/6b102db50cdde3ba2f78631ed21222edf3a5fb51
	if bindInterface != nil && bindInterface.Type() == "vrf" {
		t.Ifindex = int32(bindInterface.Attrs().Index)
		t.Flags |= unix.TCP_MD5SIG_FLAG_IFINDEX
	}

	t.Keylen = uint16(len(key))
	copy(t.Key[0:], []byte(key))

	return &t
}

func SetTCPMD5SigSockopt(l *net.TCPListener, bindInterface string, address string, key string) error {
	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}

	var link netlink.Link
	if bindInterface != "" {
		link, err = netlink.LinkByName(bindInterface)
		if err != nil {
			return fmt.Errorf("failed to get link for interface %s: %w", bindInterface, err)
		}
	}

	var sockerr error
	t := buildTcpMD5Sig(link, address, key)
	if t == nil {
		return fmt.Errorf("unable to generate TcpMD5Sig from %s", address)
	}
	if err := sc.Control(func(s uintptr) {
		sockerr = unix.SetsockoptTCPMD5Sig(int(s), unix.IPPROTO_TCP, unix.TCP_MD5SIG_EXT, t)
	}); err != nil {
		return err
	}
	return sockerr
}

func setSockOptString(sc syscall.RawConn, level int, opt int, str string) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptString(int(s), level, opt, str)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}

func SetBindToDevSockopt(sc syscall.RawConn, device string) error {
	return setSockOptString(sc, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}

func SetTCPTTLSockopt(conn net.Conn, ttl int) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptIpTtl(sc, family, ttl)
}

func SetTCPMinTTLSockopt(conn net.Conn, ttl int) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_IP
	name := syscall.IP_MINTTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = ipv6MinHopCount
	}
	return setSockOptInt(sc, level, name, ttl)
}

func SetTCPMSSSockopt(conn net.Conn, mss uint16) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptTcpMss(sc, family, mss)
}

func SetIPTOSSockopt(conn net.Conn, tos uint8) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptIpTos(sc, family, tos)
}

func SetUDPTTLSockopt(conn net.Conn, ttl int) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptIpTtl(sc, family, ttl)
}

func SetReuseAddrSockopt(sc syscall.RawConn) error {
	return setSockOptInt(sc, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func DialerControl(logger *slog.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, mss uint16, password string, bindInterface string, tos uint8) error {
	family := syscall.AF_INET
	raddr, _ := net.ResolveTCPAddr("tcp", address)
	if raddr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	var sockerr error
	if password != "" {
		var (
			err  error
			link netlink.Link
		)
		if bindInterface != "" {
			link, err = netlink.LinkByName(bindInterface)
			if err != nil {
				return fmt.Errorf("failed to get link for interface %s: %w", bindInterface, err)
			}
		}
		addr, _, _ := net.SplitHostPort(address)
		t := buildTcpMD5Sig(link, addr, password)
		if err := c.Control(func(fd uintptr) {
			sockerr = os.NewSyscallError("setSockOpt", unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG_EXT, t))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if ttl != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_IP
			name := syscall.IP_TTL
			if family == syscall.AF_INET6 {
				level = syscall.IPPROTO_IPV6
				name = syscall.IPV6_UNICAST_HOPS
			}
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(ttl)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if minTtl != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_IP
			name := syscall.IP_MINTTL
			if family == syscall.AF_INET6 {
				level = syscall.IPPROTO_IPV6
				name = ipv6MinHopCount
			}
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(minTtl)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if mss != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_TCP
			name := syscall.TCP_MAXSEG
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(mss)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if bindInterface != "" {
		if err := SetBindToDevSockopt(c, bindInterface); err != nil {
			return err
		}
	}

	if tos != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_IP
			name := syscall.IP_TOS
			if family == syscall.AF_INET6 {
				level = syscall.IPPROTO_IPV6
				name = syscall.IPV6_TCLASS
			}
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(tos)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}
	return nil
}

// SetRecvHopLimitSockoptImpl asks the kernel to attach the received TTL (IPv4)
// and hop limit (IPv6) to each datagram as a control message.
//
// RFC 5881 §5 requires a single-hop BFD implementation to discard packets whose
// TTL or hop limit is not 255. Transmission already sets 255, but without these
// options the receive path cannot see the value at all, so the check could not
// be made and the protection was one-directional.
//
// The socket is dual-stack, so both options are set. IPv4 is best-effort: on a
// v6-only socket IP_RECVTTL is not meaningful and its failure must not stop the
// v6 option being applied.
func SetRecvHopLimitSockopt(sc syscall.RawConn) error {
	// Both are attempted because the family of the socket is not known here.
	// A v4-only socket rejects the IPv6 option with ENOPROTOOPT and vice versa,
	// so success is "at least one applied": requiring both would disable the
	// check on every single-family listener.
	errV4 := setSockOptInt(sc, syscall.IPPROTO_IP, syscall.IP_RECVTTL, 1)
	errV6 := setSockOptInt(sc, syscall.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	if errV4 != nil && errV6 != nil {
		return fmt.Errorf("neither IP_RECVTTL (%v) nor IPV6_RECVHOPLIMIT (%v) could be set", errV4, errV6)
	}
	return nil
}

// ParseHopLimitImpl extracts the received TTL (IPv4) or hop limit (IPv6) from a
// datagram's control messages. The second return is false when neither is
// present, which a caller must not treat as a hop limit of zero.
func ParseHopLimit(oob []byte) (int, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_TTL,
			m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_HOPLIMIT:
			if len(m.Data) >= 1 {
				// Both are delivered as a C int in native byte order; the low
				// byte carries the value for any plausible TTL.
				return int(m.Data[0]), true
			}
		}
	}
	return 0, false
}
