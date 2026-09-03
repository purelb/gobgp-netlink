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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/osrg/gobgp/v4/api"
)

// BFD had no CLI at all: `gobgp neighbor` printed nothing about it and there was
// no bfd command, so the only way to see whether a session was up was to read
// raw JSON and know that BFD_SESSION_STATE_UP is 1. That is a poor interface for
// the one subsystem whose entire purpose is telling you something has failed.
//
// Two rendering decisions here exist to defuse traps that are easy to walk into:
//
//   - States print as words. The enum numbers UP as 1, but RFC 5880 6.8.1 numbers
//     Down as 1 and Up as 3, so a reader who knows the RFC reads the raw JSON
//     value as the opposite of what it means.
//   - Intervals print in milliseconds. They are configured and reported in
//     microseconds, and the generated Go drops the YANG units comment, so 300
//     entered as "300ms" silently becomes 300us - about 3,300 packets a second.

// bfdStateName renders a session state without its enum prefix: "UP", "DOWN".
func bfdStateName(s api.BfdSessionState) string {
	name := strings.TrimPrefix(s.String(), "BFD_SESSION_STATE_")
	if name == "" || name == "UNSPECIFIED" {
		return "-"
	}
	return name
}

// bfdInterval renders a microsecond interval the way it was almost certainly
// meant to be read.
func bfdInterval(micros uint32) string {
	return (time.Duration(micros) * time.Microsecond).String()
}

// showBfdNeighbor prints the BFD section of `gobgp neighbor <peer>`.
//
// It prints a line even when BFD is off. "Not configured" is a useful answer -
// its absence is what makes people ask whether the feature is present at all.
func showBfdNeighbor(p *api.Peer) {
	conf := p.GetBfd()
	if !conf.GetEnabled() {
		fmt.Printf("  BFD: not configured\n")
		return
	}

	state := p.GetState().GetBfdState()
	detect := time.Duration(conf.GetDetectionMultiplier()) *
		time.Duration(conf.GetRequiredMinimumReceive()) * time.Microsecond

	// Remote session state and the diagnostic codes exist in the proto but are
	// never populated by the BFD peer, so they are not printed: a blank "remote"
	// or a default "no diagnostic" reads as knowledge we do not have.
	fmt.Printf("  BFD: enabled, session %s\n", bfdStateName(state.GetSessionState()))
	fmt.Printf("    Intervals: tx %s, rx %s, multiplier %d (detect %s), port %d\n",
		bfdInterval(conf.GetDesiredMinimumTxInterval()),
		bfdInterval(conf.GetRequiredMinimumReceive()),
		conf.GetDetectionMultiplier(), detect, conf.GetPort())

	async := state.GetBfdAsync()
	fmt.Printf("    Packets: tx %d, rx %d, failure transitions %d\n",
		async.GetTransmittedPackets(), async.GetReceivedPackets(),
		state.GetFailureTransitions())

	// Our packets are leaving and none are coming back. The usual cause is that
	// the peer address we match on receive is not the address the packets carry -
	// a link-local neighbor configured without its zone, for instance.
	if async.GetTransmittedPackets() > 0 && async.GetReceivedPackets() == 0 &&
		state.GetSessionState() != api.BfdSessionState_BFD_SESSION_STATE_UP {
		fmt.Printf("    Note: transmitting but receiving nothing; check `gobgp bfd` for unknown-peer packets\n")
	}
}

func showBfd() error {
	peers := make([]*api.Peer, 0, 8)
	stream, err := client.ListPeer(context.Background(), &api.ListPeerRequest{})
	if err != nil {
		return err
	}
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if r.Peer.GetBfd().GetEnabled() {
			peers = append(peers, r.Peer)
		}
	}

	srv, err := client.GetBfdServerState(context.Background(), &api.GetBfdServerStateRequest{})
	if err != nil {
		return err
	}

	if globalOpts.Json {
		type out struct {
			Peers  []*api.Peer   `json:"peers"`
			Server *api.BfdState `json:"server"`
		}
		j, _ := json.Marshal(out{Peers: peers, Server: srv.GetState()})
		fmt.Println(string(j))
		return nil
	}

	if len(peers) == 0 {
		fmt.Println("No peers have BFD enabled.")
	} else {
		fmt.Printf("%-32s %-6s %-10s %-10s %s\n",
			"Peer", "State", "Tx", "Rx", "Transitions")
		for _, p := range peers {
			s := p.GetState().GetBfdState()
			a := s.GetBfdAsync()
			fmt.Printf("%-32s %-6s %-10d %-10d %d\n",
				p.GetState().GetNeighborAddress(),
				bfdStateName(s.GetSessionState()),
				a.GetTransmittedPackets(), a.GetReceivedPackets(),
				s.GetFailureTransitions())
		}
	}

	st := srv.GetState()
	if st == nil {
		// Defensive: the server always constructs its BFD server, so this only
		// happens if that changes or the daemon is older than this command.
		fmt.Printf("\nServer: counters unavailable\n")
		return nil
	}

	fmt.Printf("\nServer: rx %d  drop %d  error %d  invalid %d  unknown-peer %d\n",
		st.GetReceivedPacket(), st.GetReceivedDrop(), st.GetReceivedError(),
		st.GetInvalidPacket(), st.GetUnknownPeer())

	// These two are the ones worth explaining at the point of use, because both
	// are silent everywhere else in the daemon.
	if st.GetUnknownPeer() > 0 {
		fmt.Printf("  unknown-peer: packets arrived from an address with no configured peer.\n" +
			"    A link-local neighbor must carry its zone (fe80::1%%eth0); without it the\n" +
			"    receive lookup cannot match and the session stays down.\n")
	}
	if st.GetReceivedDrop() > 0 {
		fmt.Printf("  drop: a peer's receive queue was full. The queue holds one packet, so\n" +
			"    this means an event loop stalled longer than one transmit interval.\n")
	}
	return nil
}

func newBfdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bfd",
		Short: "show BFD session state and server counters",
		Run: func(cmd *cobra.Command, args []string) {
			if err := showBfd(); err != nil {
				exitWithError(err)
			}
		},
	}
}
