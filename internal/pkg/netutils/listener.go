// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package netutils

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
)

type TCPConn struct {
	*net.TCPConn
	cb func(*TCPConn)
}

func (c *TCPConn) Close() error {
	if c.cb != nil {
		c.cb(c)
	}
	return c.TCPConn.Close()
}

func (c *TCPConn) Key() string {
	if c == nil || c.TCPConn == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

// Ensure TCPConn implements net.Conn/syscall.Conn interfaces
var (
	_ net.Conn     = (*TCPConn)(nil)
	_ syscall.Conn = (*TCPConn)(nil)
)

// AcceptedConn is a connection handed to the BGP server, carrying when it was
// taken off the listener. acceptLoop can outrun the single Serve goroutine -
// connChan is buffered - so the gap between the two is real latency that was
// previously invisible.
type AcceptedConn struct {
	Conn net.Conn
	// Enqueued is when the connection was accepted, before the enqueue. It
	// therefore includes the SetKeepAlive syscall and the bookkeeping below,
	// which are part of what delays a session coming up.
	Enqueued time.Time
}

type TCPListener struct {
	ctx          context.Context
	cancel       context.CancelFunc
	l            *net.TCPListener
	connChan     chan AcceptedConn
	acceptedConn cmap.ConcurrentMap[string, *TCPConn] // key is RemoteAddr().String()
	stopWg       *sync.WaitGroup                      // used to wait for acceptLoop to finish
	logger       *slog.Logger
}

func listenControl(logger *slog.Logger, bindToDev string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		family := extractFamilyFromAddress(address)
		if bindToDev != "" {
			if err := SetBindToDevSockopt(c, bindToDev); err != nil {
				logger.Warn("failed to bind Listener to device ",
					slog.String("Topic", "Peer"),
					slog.String("Key", address),
					slog.String("BindToDev", bindToDev),
					slog.String("Error", err.Error()),
				)
				return err
			}
		}
		// Note: Set TTL=255 for incoming connection listener in order to accept
		// connection in case for the neighbor has TTL Security settings.
		if err := setSockOptIpTtl(c, family, 255); err != nil {
			logger.Warn("cannot set TTL (255) for TCPListener",
				slog.String("Topic", "Peer"),
				slog.String("Key", address),
				slog.String("Error", err.Error()))
		}
		return nil
	}
}

func (l *TCPListener) closeConnCb(tcpConn *TCPConn) {
	key := tcpConn.Key()
	if key == "" {
		return // nothing to do
	}
	l.acceptedConn.Remove(key)
}

func (l *TCPListener) acceptLoop() {
	defer l.stopWg.Done()
	for {
		conn, err := l.l.AcceptTCP()
		accepted := time.Now()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				l.logger.Warn("Failed to AcceptTCP",
					slog.String("Topic", "Peer"),
					slog.String("Error", err.Error()))
			}
			return
		}
		tcpConn := &TCPConn{
			TCPConn: conn,
			cb:      l.closeConnCb,
		}
		key := tcpConn.Key()
		l.acceptedConn.Set(key, tcpConn)

		err = conn.SetKeepAlive(false)
		if err != nil {
			l.logger.Warn("Failed to SetKeepAlive; dropping this connection",
				slog.String("Topic", "Peer"),
				slog.String("Key", key),
				slog.String("Error", err.Error()))
			// Drop this connection and carry on. This used to return, which
			// exited acceptLoop for the life of the process: the listener
			// stayed bound but accepted nothing ever again, silently, so
			// passive sessions simply never came up. It also leaked the
			// connection, which is already registered in acceptedConn above.
			_ = tcpConn.Close()
			continue
		}

		// No default case: when the buffer fills, this blocks and stops
		// calling AcceptTCP, so the backlog moves to the kernel accept queue
		// where AcceptedConn.Enqueued cannot see it. Under a flood the queue
		// wait therefore understates the delay - watch TcpExtListenOverflows
		// for that.
		select {
		case l.connChan <- AcceptedConn{Conn: tcpConn, Enqueued: accepted}:
		case <-l.ctx.Done():
			return
		}
	}
}

// avoid mapped IPv6 address
func NewTCPListener(logger *slog.Logger, address string, port uint32, bindToDev string, connChan chan AcceptedConn) (*TCPListener, error) {
	proto := extractProtoFromAddress(address)
	config := net.ListenConfig{
		Control: listenControl(logger, bindToDev),
	}

	// Since 1.24, Go stdlib enables MPTCP for listeners by default. This
	// makes setsockopt to call MPTCP-specific handler. This breaks the
	// listener that enables TCP MD5 because it is not compatible with
	// MPTCP. This is a workaround for that.
	//
	// See: https://github.com/golang/go/issues/74643 for more details.
	config.SetMultipathTCP(false)

	addr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	listener, err := config.Listen(context.Background(), proto, addr)
	if err != nil {
		return nil, err
	}
	netListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("unexpected connection listener (not for TCP)")
	}

	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	// Create the stopWg to wait for acceptLoop to finish
	// when Close() is called.
	stopWg := &sync.WaitGroup{}
	stopWg.Add(1)
	l := &TCPListener{
		ctx:          listenerCtx,
		cancel:       listenerCancel,
		l:            netListener,
		stopWg:       stopWg,
		connChan:     connChan,
		acceptedConn: cmap.New[*TCPConn](),
		logger:       logger,
	}
	go l.acceptLoop()
	return l, nil
}

func (l *TCPListener) Close() {
	l.cancel()
	_ = l.l.Close()
	l.stopWg.Wait()
	for t := range l.acceptedConn.IterBuffered() {
		_ = t.Val.TCPConn.Close()
	}
	l.acceptedConn.Clear()
}

func (l *TCPListener) Addr() net.Addr {
	if l.l == nil {
		return nil
	}
	return l.l.Addr()
}

func (l *TCPListener) Listener() *net.TCPListener {
	return l.l
}
