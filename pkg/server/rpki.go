// Copyright (C) 2015-2021 Nippon Telegraph and Telephone Corporation.
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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
)

const (
	connectRetryInterval = 30
)

func before(a, b uint32) bool {
	return int32(a-b) < 0
}

type roaEventType uint8

const (
	roaConnected roaEventType = iota
	roaDisconnected
	roaRTR
	roaLifetimeout
)

type roaEvent struct {
	EventType roaEventType
	Src       string
	Data      []byte
	conn      *net.TCPConn
	timestamp time.Time
}

type roaManager struct {
	eventCh   chan *roaEvent
	clientMap map[string]*roaClient
	table     *table.ROATable
	logger    *slog.Logger
}

func newROAManager(table *table.ROATable, logger *slog.Logger) *roaManager {
	m := &roaManager{
		eventCh:   make(chan *roaEvent),
		clientMap: make(map[string]*roaClient),
		table:     table,
		logger:    logger,
	}
	return m
}

func (m *roaManager) enabled() bool {
	return len(m.clientMap) != 0
}

func (m *roaManager) AddServer(host string, lifetime int64) error {
	address, port, err := net.SplitHostPort(host)
	if err != nil {
		return err
	}
	if lifetime == 0 {
		lifetime = 3600
	}
	if _, ok := m.clientMap[host]; ok {
		return fmt.Errorf("ROA server exists %s", host)
	}
	m.clientMap[host] = newRoaClient(address, port, m.eventCh, lifetime)
	return nil
}

func (m *roaManager) DeleteServer(host string) error {
	client, ok := m.clientMap[host]
	if !ok {
		return fmt.Errorf("ROA server doesn't exists %s", host)
	}
	client.stop()
	m.table.DeleteAll(host)
	delete(m.clientMap, host)
	return nil
}

// Stop tears down every ROA client. StopBgp closes listeners, deletes
// neighbours and stops netlink, and left these running: their goroutines
// outlived the server, holding TCP connections to the caches open and blocking
// for ever on an event channel nobody drained.
//
// Serve-goroutine only, like DeleteServer - StopBgp calls it inside the same
// mgmtOperation closure that does the netlink and neighbour teardown.
func (m *roaManager) Stop() {
	for host, client := range m.clientMap {
		client.stop()
		m.table.DeleteAll(host)
		delete(m.clientMap, host)
	}
}

func (m *roaManager) Enable(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			return client.enable(client.serialNumber)
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) Disable(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			client.reset()
			m.table.DeleteAll(add)
			return nil
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) Reset(address string) error {
	return m.Disable(address)
}

func (m *roaManager) SoftReset(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			m.table.DeleteAll(network)
			return client.softReset()
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) ReceiveROA() chan *roaEvent {
	return m.eventCh
}

// sendEvent delivers an event to the manager, or gives up if this client has
// been stopped.
//
// eventCh is unbuffered and drained only by Serve. StopBgp tears down netlink,
// neighbours, listeners and keychains and left the ROA clients running, so
// after it returned nothing drained the channel and every one of these sends
// blocked for ever: one leaked goroutine per RPKI server per StopBgp, holding
// a TCP connection open. roaManager.Stop now cancels each client, and this is
// what lets a send already in flight unblock instead of pinning the goroutine
// to a channel nobody will ever read.
func (c *roaClient) sendEvent(ev *roaEvent) bool {
	select {
	case c.eventCh <- ev:
		return true
	case <-c.ctx.Done():
		return false
	}
}

func (c *roaClient) lifetimeout() {
	c.sendEvent(&roaEvent{
		EventType: roaLifetimeout,
		Src:       c.host,
		timestamp: time.Now(),
	})
}

func (m *roaManager) HandleROAEvent(ev *roaEvent) {
	client, y := m.clientMap[ev.Src]
	if !y {
		if ev.EventType == roaConnected {
			ev.conn.Close()
		}
		m.logger.Error("Can't find ROA server configuration",
			slog.String("Topic", "rpki"),
			slog.Any("Key", ev.Src))
		return
	}
	switch ev.EventType {
	case roaDisconnected:
		m.logger.Info("ROA server is disconnected",
			slog.String("Topic", "rpki"),
			slog.Any("Key", ev.Src))
		client.state.Downtime = time.Now().Unix()
		// clear state
		client.endOfData = false
		client.pendingROAs = make([]*table.ROA, 0)
		client.state.RpkiMessages = oc.RpkiMessages{}
		client.conn = nil
		go client.tryConnect()
		client.timer = time.AfterFunc(time.Duration(client.lifetime)*time.Second, client.lifetimeout)
		client.oldSessionID = client.sessionID
	case roaConnected:
		m.logger.Info("ROA server is connected",
			slog.String("Topic", "rpki"),
			slog.Any("Key", ev.Src))
		client.conn = ev.conn
		client.state.Uptime = time.Now().Unix()
		// The opening Reset Query, sent here rather than from established()'s
		// goroutine: softReset writes counters and cache state that Serve also
		// owns, and two goroutines were writing them and the connection at
		// once. A failure here is left to the read loop, which will see the
		// dead connection and raise roaDisconnected as usual.
		if err := client.softReset(); err != nil {
			m.logger.Error("Failed to send the opening reset query",
				slog.String("Topic", "rpki"),
				slog.String("Host", client.host),
				slog.String("Error", err.Error()))
		}
		go client.established()
	case roaRTR:
		m.handleRTRMsg(client, &client.state, ev.Data)
	case roaLifetimeout:
		// a) already reconnected but hasn't received
		// EndOfData -> needs to delete stale ROAs
		// b) not reconnected -> needs to delete stale ROAs
		//
		// c) already reconnected and received EndOfData so
		// all stale ROAs were deleted -> timer was cancelled
		// so should not be here.
		if client.oldSessionID != client.sessionID {
			m.logger.Info("Reconnected, ignore timeout",
				slog.String("Topic", "rpki"),
				slog.String("Key", client.host),
			)
		} else {
			m.logger.Info("Deleting all ROAs due to timeout",
				slog.String("Topic", "rpki"),
				slog.String("Key", client.host),
			)
			m.table.DeleteAll(client.host)
		}
	}
}

func (m *roaManager) handleRTRMsg(client *roaClient, state *oc.RpkiServerState, buf []byte) {
	received := &state.RpkiMessages.RpkiReceived

	m1, err := rtr.ParseRTR(buf)
	if err == nil {
		switch msg := m1.(type) {
		case *rtr.RTRSerialNotify:
			if before(client.serialNumber, msg.SerialNumber) {
				if err := client.enable(client.serialNumber); err != nil {
					m.logger.Error("Failed to send serial query",
						slog.String("Topic", "rpki"),
						slog.String("Host", client.host),
						slog.String("Error", err.Error()),
					)
				}
			} else if client.serialNumber == msg.SerialNumber {
				// nothing
			} else {
				// should not happen. try to get the whole ROAs.
				if err := client.softReset(); err != nil {
					m.logger.Error("Failed to send soft reset",
						slog.String("Topic", "rpki"),
						slog.String("Host", client.host),
						slog.String("Error", err.Error()),
					)
				}
			}
			received.SerialNotify++
		case *rtr.RTRSerialQuery:
		case *rtr.RTRResetQuery:
		case *rtr.RTRCacheResponse:
			received.CacheResponse++
			client.endOfData = false
		case *rtr.RTRIPPrefix:
			family := bgp.AFI_IP
			if msg.Type == rtr.RTR_IPV4_PREFIX {
				received.Ipv4Prefix++
			} else {
				family = bgp.AFI_IP6
				received.Ipv6Prefix++
			}
			roa := table.NewROA(family, msg.Prefix.AsSlice(), msg.PrefixLen, msg.MaxLen, msg.AS, client.host)
			if msg.Flags&1 == 1 {
				if client.endOfData {
					m.table.Add(roa)
				} else {
					client.pendingROAs = append(client.pendingROAs, roa)
				}
			} else {
				m.table.Delete(roa)
			}
		case *rtr.RTREndOfData:
			received.EndOfData++
			if client.sessionID != msg.SessionID {
				// remove all ROAs related with the
				// previous session
				m.table.DeleteAll(client.host)
			}
			client.sessionID = msg.SessionID
			client.serialNumber = msg.SerialNumber
			client.endOfData = true
			if client.timer != nil {
				client.timer.Stop()
				client.timer = nil
			}
			for _, roa := range client.pendingROAs {
				m.table.Add(roa)
			}
			client.pendingROAs = make([]*table.ROA, 0)
		case *rtr.RTRCacheReset:
			received.CacheReset++
			// Answering every Cache Reset with a Reset Query hands the cache a
			// write on the Serve goroutine, under shared.mu, once per PDU it
			// chooses to send - so a cache that floods them stalls peer
			// events, API calls and netlink for as long as it likes. The
			// deadline on the write bounds each one; this bounds how many.
			//
			// Only the received path is throttled. An operator calling
			// ResetRpki --soft is not the attacker and is never refused.
			if now := time.Now(); now.Sub(client.lastCacheResetQuery) < cacheResetMinInterval {
				m.logger.Warn("Ignoring a cache reset sent too soon after the last one",
					slog.String("Topic", "rpki"),
					slog.String("Host", client.host),
					slog.Duration("MinInterval", cacheResetMinInterval))
			} else {
				client.lastCacheResetQuery = now
				if err := client.softReset(); err != nil {
					m.logger.Error("Failed to send soft reset",
						slog.String("Topic", "rpki"),
						slog.String("Host", client.host),
						slog.String("Error", err.Error()))
				}
			}
		case *rtr.RTRErrorReport:
			received.Error++
		}
	} else {
		m.logger.Info("Failed to parse an RTR message",
			slog.String("Topic", "rpki"),
			slog.String("Host", client.host),
			slog.String("Error", err.Error()),
		)
	}
}

func (m *roaManager) GetServers() []*oc.RpkiServer {
	recordsV4, prefixesV4 := m.table.Info(bgp.RF_IPv4_UC)
	recordsV6, prefixesV6 := m.table.Info(bgp.RF_IPv6_UC)

	l := make([]*oc.RpkiServer, 0, len(m.clientMap))
	for _, client := range m.clientMap {
		state := &client.state

		if client.conn == nil {
			state.Up = false
		} else {
			state.Up = true
		}
		f := func(m map[string]uint32, key string) uint32 {
			if r, ok := m[key]; ok {
				return r
			}
			return 0
		}
		state.RecordsV4 = f(recordsV4, client.host)
		state.RecordsV6 = f(recordsV6, client.host)
		state.PrefixesV4 = f(prefixesV4, client.host)
		state.PrefixesV6 = f(prefixesV6, client.host)
		state.SerialNumber = client.serialNumber

		addr, port, _ := net.SplitHostPort(client.host)
		// AddRpki validates the address now, so this should not fail. Skip
		// rather than panic if it somehow does: GetServers has no error return,
		// and taking the daemon down on a read path is the worse outcome.
		parsed, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		l = append(l, &oc.RpkiServer{
			Config: oc.RpkiServerConfig{
				Address: parsed,
				// Note: RpkiServerConfig.Port is uint32 type, but the TCP/UDP
				// port is 16-bit length.
				Port: func() uint32 { p, _ := strconv.ParseUint(port, 10, 16); return uint32(p) }(),
				// The effective lifetime, so a caller that sent 0 sees the
				// default that was applied rather than the 0 it sent. It was
				// accepted by AddRpki and reported nowhere.
				RecordLifetime: client.lifetime,
			},
			State: client.state,
		})
	}
	return l
}

type roaClient struct {
	host         string
	conn         *net.TCPConn
	state        oc.RpkiServerState
	eventCh      chan *roaEvent
	sessionID    uint16
	oldSessionID uint16
	serialNumber uint32
	timer        *time.Timer
	lifetime     int64
	endOfData    bool
	pendingROAs  []*table.ROA
	// When this client last answered a received Cache Reset with a Reset
	// Query. Serve-goroutine only, like every other field here.
	lastCacheResetQuery time.Time
	cancelfnc           context.CancelFunc
	ctx                 context.Context
}

func newRoaClient(address, port string, ch chan *roaEvent, lifetime int64) *roaClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &roaClient{
		host:        net.JoinHostPort(address, port),
		eventCh:     ch,
		lifetime:    lifetime,
		pendingROAs: make([]*table.ROA, 0),
		ctx:         ctx,
		cancelfnc:   cancel,
	}
	go c.tryConnect()
	return c
}

// rtrWriteTimeout bounds a write to an RPKI cache. Every one of these runs on
// the Serve goroutine under shared.mu, so a cache that accepts the connection
// and then stops reading would otherwise stall the whole daemon - no peer
// events, no API calls, no netlink - for as long as it cared to. The value
// matches the BGP notification write deadline in fsm.go.
//
// The deadline is set before each write rather than once on the connection,
// because a deadline is a point in time and sticks: set once at connect, it
// would expire and fail every later write.
const rtrWriteTimeout = time.Second

// cacheResetMinInterval is the shortest gap between two Reset Queries sent in
// answer to a cache's own Cache Reset PDUs. A legitimate cache sends one when
// it loses its state, which is rare; the pacing only bites on a flood.
const cacheResetMinInterval = time.Second

func (c *roaClient) enable(serial uint32) error {
	if c.conn != nil {
		r := rtr.NewRTRSerialQuery(c.sessionID, serial)
		data, _ := r.Serialize()
		if err := c.conn.SetWriteDeadline(time.Now().Add(rtrWriteTimeout)); err != nil {
			return err
		}
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.SerialQuery++
	}
	return nil
}

func (c *roaClient) softReset() error {
	if c.conn != nil {
		r := rtr.NewRTRResetQuery()
		data, _ := r.Serialize()
		if err := c.conn.SetWriteDeadline(time.Now().Add(rtrWriteTimeout)); err != nil {
			return err
		}
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.ResetQuery++
		c.endOfData = false
		c.pendingROAs = make([]*table.ROA, 0)
	}
	return nil
}

func (c *roaClient) reset() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *roaClient) stop() {
	c.cancelfnc()
	// The lifetime timer is a time.AfterFunc whose callback sends on eventCh.
	// Leaving it armed keeps a timer goroutine alive past the client and fires
	// lifetimeout at a manager that has forgotten this host. Serve-goroutine
	// only, like every other write to this field.
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.reset()
}

func (c *roaClient) tryConnect() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		if conn, err := net.Dial("tcp", c.host); err != nil {
			// better to use context with timeout
			time.Sleep(connectRetryInterval * time.Second)
		} else {
			// The manager owns the connection once the event lands. If the
			// client was stopped while we were dialling nobody will ever read
			// it, so close it here rather than leaking the socket too.
			if !c.sendEvent(&roaEvent{
				EventType: roaConnected,
				Src:       c.host,
				conn:      conn.(*net.TCPConn),
				timestamp: time.Now(),
			}) {
				conn.Close()
			}
			return
		}
	}
}

func (c *roaClient) established() (err error) {
	defer func() {
		c.conn.Close()
		c.sendEvent(&roaEvent{
			EventType: roaDisconnected,
			Src:       c.host,
			timestamp: time.Now(),
		})
	}()

	// The opening Reset Query used to be sent from here, on this goroutine,
	// while softReset writes c.state.RpkiMessages, c.endOfData and
	// c.pendingROAs - all of which the Serve goroutine reads and writes in
	// handleRTRMsg. That was a data race on four fields and two concurrent
	// writers on one TCP connection. It is sent from the roaConnected handler
	// instead, so every write to a roaClient now happens on Serve and no lock
	// is needed anywhere.

	for {
		header := make([]byte, rtr.RTR_MIN_LEN)
		if _, err = io.ReadFull(c.conn, header); err != nil {
			return err
		}
		totalLen := binary.BigEndian.Uint32(header[4:8])
		if totalLen < rtr.RTR_MIN_LEN {
			return fmt.Errorf("too short header length %v", totalLen)
		}

		body := make([]byte, totalLen-rtr.RTR_MIN_LEN)
		if _, err = io.ReadFull(c.conn, body); err != nil {
			return err
		}

		if !c.sendEvent(&roaEvent{
			EventType: roaRTR,
			Src:       c.host,
			Data:      append(header, body...),
			timestamp: time.Now(),
		}) {
			return nil
		}
	}
}
