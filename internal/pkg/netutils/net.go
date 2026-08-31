// Copyright (C) 2025 Nippon Telegraph and Telephone Corporation.
// Copyright (C) 2025 Acnodal Inc.
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

package netutils

import (
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
)

type ConnectedRoute struct {
	Prefix  *net.IPNet
	NextHop net.IP
}

// isGlob reports whether a pattern contains shell glob metacharacters.
func isGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// ExpandInterfacePatterns resolves a configured interface list into concrete
// interface names.
//
// Entries containing glob metacharacters (`*`, `?`, `[`) are matched against the
// interfaces currently present on the host; entries without them are passed
// through unchanged, so a literal name that does not exist still reaches the
// caller and produces the same "failed to find interface" error it always has.
//
// Literal entries keep their configured order and come first, preserving exactly
// what operators see today. Glob matches are sorted and appended after them, so
// expansion is deterministic. The whole result is de-duplicated, keeping the
// first occurrence, so an interface named by two patterns is scanned once.
//
// Order is not cosmetic: routes are collected into a map keyed by prefix, so if
// two interfaces carry the same prefix the last one scanned wins.
func ExpandInterfacePatterns(patterns []string, logger *slog.Logger) ([]string, error) {
	var literals []string
	var globs []string
	for _, p := range patterns {
		if isGlob(p) {
			globs = append(globs, p)
		} else {
			literals = append(literals, p)
		}
	}

	var matched []string
	// Only pay for the interface enumeration when a glob is actually configured.
	if len(globs) > 0 {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to list interfaces: %w", err)
		}

		for _, pattern := range globs {
			n := 0
			for _, iface := range ifaces {
				ok, err := filepath.Match(pattern, iface.Name)
				if err != nil {
					// Malformed pattern (e.g. an unterminated "["). Report it rather
					// than silently importing nothing.
					return nil, fmt.Errorf("invalid interface pattern %q: %w", pattern, err)
				}
				if ok {
					matched = append(matched, iface.Name)
					n++
				}
			}
			if logger != nil {
				logger.Debug("Expanded interface pattern",
					slog.String("Topic", "netlink"),
					slog.String("Pattern", pattern),
					slog.Int("Matched", n))
			}
		}
		slices.Sort(matched)
	}

	result := make([]string, 0, len(literals)+len(matched))
	seen := make(map[string]struct{}, len(literals)+len(matched))
	for _, name := range slices.Concat(literals, matched) {
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result, nil
}

// GetGlobalUnicastRoutes returns a list of global unicast IP addresses
// for a given network interface.
func GetGlobalUnicastRoutes(interfaceName string, logger *slog.Logger) ([]*ConnectedRoute, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", interfaceName, err)
	}

	var routes []*ConnectedRoute
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			isGlobal := !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified()

			// Calculate the network address
			network := &net.IPNet{
				IP:   ipnet.IP.Mask(ipnet.Mask),
				Mask: ipnet.Mask,
			}

			logger.Debug("Found address on interface",
				slog.String("Topic", "net"),
				slog.String("Address", ipnet.String()),
				slog.String("Network", network.String()),
				slog.String("Interface", interfaceName),
				slog.Bool("IsGlobal", isGlobal))

			if isGlobal {
				routes = append(routes, &ConnectedRoute{
					Prefix:  network,
					NextHop: ip,
				})
			}
		}
	}

	routeStrings := make([]string, len(routes))
	for i, r := range routes {
		routeStrings[i] = r.Prefix.String()
	}

	logger.Debug("Returning routes from interface",
		slog.String("Topic", "net"),
		slog.Any("Routes", routeStrings),
		slog.String("Interface", interfaceName))
	return routes, nil
}

// GetLinkLocalIPv6Address returns the link-local IPv6 address for a given
// network interface.
func GetLinkLocalIPv6Address(interfaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", interfaceName, err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			if ip.To4() == nil && ip.IsLinkLocalUnicast() {
				return ip, nil
			}
		}
	}

	return nil, fmt.Errorf("no link-local IPv6 address found for interface %s", interfaceName)
}

// GetIPv4Nexthop returns the IPv4 address for a given network interface.
// This function looks for a global unicast IPv4 address on the interface.
func GetIPv4Nexthop(interfaceName string, logger *slog.Logger) (net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", interfaceName, err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			// Check if it's IPv4 and is global unicast
			if ip.To4() != nil {
				isGlobal := !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified()
				if isGlobal {
					logger.Debug("Found IPv4 nexthop on interface",
						slog.String("Topic", "net"),
						slog.String("Interface", interfaceName),
						slog.String("Address", ip.String()))
					return ip, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}

// GetInterfaceByIP returns the name of the network interface that has the given IP address.
func GetInterfaceByIP(ip net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ip) {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no interface found for IP %s", ip.String())
}

type IPv6Nexthops struct {
	Global    net.IP
	LinkLocal net.IP
}

func GetIPv6Nexthops(interfaceName string, logger *slog.Logger) (*IPv6Nexthops, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", interfaceName, err)
	}

	nexthops := &IPv6Nexthops{}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			if ip.To4() == nil {
				if ip.IsGlobalUnicast() {
					if nexthops.Global == nil {
						nexthops.Global = ip
					}
				} else if ip.IsLinkLocalUnicast() {
					if nexthops.LinkLocal == nil {
						nexthops.LinkLocal = ip
					}
				}
			}
		}
	}

	logger.Debug("Found IPv6 nexthops on interface",
		slog.String("Topic", "net"),
		slog.String("Interface", interfaceName),
		slog.Any("Global", nexthops.Global),
		slog.Any("LinkLocal", nexthops.LinkLocal))

	return nexthops, nil
}
