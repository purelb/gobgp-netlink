// This is partial implementation of BFD protocol (https://datatracker.ietf.org/doc/html/rfc5880)
// only for fast detection of connection failures between BGP peers.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

type bfdServerStats struct {
	rxPacket      atomic.Uint64
	rxDrop        atomic.Uint64
	rxError       atomic.Uint64
	invalidPacket atomic.Uint64
	unknownPeer   atomic.Uint64
	wrongHopLimit atomic.Uint64
}

// bfdRequiredHopLimit is RFC 5881 5's mandated TTL/hop limit for single-hop
// BFD, both on transmit and on receive.
const bfdRequiredHopLimit = 255

type bfdEventConfig struct {
	config *oc.BfdConfig
	ack    chan struct{}
}

type bfdEventPeerUpdate struct {
	isAdd         bool
	peerAddress   netip.Addr
	config        oc.BfdConfig
	bindInterface string
	// result, when non-nil, receives whether the listener is up after this
	// peer was added. The socket is bound lazily - binding at Start would
	// claim UDP/3784 even for a daemon with no BFD peers, and on a host also
	// running FRR's bfdd that is silent packet theft rather than a clean
	// error. Lazy binding is therefore correct, but it used to mean a failure
	// surfaced only as a 1s retry loop while BGP came up regardless.
	result chan error
}

type bfdPeerState struct {
	peerAddress netip.Addr
	state       api.BfdPeerState
}

type peerState interface {
	ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error
}

type bfdServer struct {
	peerState peerState
	logger    *slog.Logger

	config *oc.BfdConfig

	udpServer *net.UDPConn
	// udpServerLive mirrors whether udpServer is bound. udpServer is only
	// touched by the event loop, so a separate atomic lets metrics and the API
	// read the state without racing that goroutine.
	udpServerLive atomic.Bool
	// gtsmRxAvailable records whether the kernel will report each datagram's
	// TTL, which is what makes RFC 5881 5 enforceable on receive.
	gtsmRxAvailable atomic.Bool
	listenInterface string

	peersMutex sync.RWMutex
	peers      map[netip.Addr]*bfdPeer

	eventStartStop  *time.Ticker
	eventConfig     chan *bfdEventConfig
	eventPeerUpdate chan *bfdEventPeerUpdate
	eventShutdown   chan struct{}
	shutdownOnce    sync.Once
	stopped         atomic.Bool

	shutdownWait sync.WaitGroup

	serverStop chan struct{}
	serverWait sync.WaitGroup

	stats bfdServerStats
}

func NewBfdServer(ps peerState, logger *slog.Logger) *bfdServer {
	s := &bfdServer{
		peerState: ps,
		logger:    logger,

		peers: make(map[netip.Addr]*bfdPeer),

		eventStartStop:  time.NewTicker(time.Second),
		eventConfig:     make(chan *bfdEventConfig, 1),
		eventPeerUpdate: make(chan *bfdEventPeerUpdate, 1),
		eventShutdown:   make(chan struct{}),
	}

	s.shutdownWait.Add(1)
	go s.loop()
	return s
}

func (s *bfdServer) Start(ctx context.Context, config oc.BfdConfig) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	// Acknowledged rather than fire-and-forget. Start and AddPeer post to
	// different channels and select picks randomly among ready ones, so without
	// this a peer could be processed while s.config is still nil - the listener
	// would be skipped, and AddPeer would report a bind failure that is really
	// just an ordering artefact.
	ack := make(chan struct{}, 1)

	select {
	case s.eventConfig <- &bfdEventConfig{config: &config, ack: ack}:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}

	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) Stop() {
	s.shutdownOnce.Do(func() {
		s.stopped.Store(true)
		close(s.eventShutdown)
		s.shutdownWait.Wait()
	})
}

func (s *bfdServer) AddPeer(ctx context.Context, peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	if !config.Enabled {
		return nil
	}

	// Buffered so the event loop never blocks if this caller goes away.
	result := make(chan error, 1)

	select {
	case s.eventPeerUpdate <- &bfdEventPeerUpdate{isAdd: true, peerAddress: peerAddress, config: config, bindInterface: bindInterface, result: result}:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}

	// Wait for the listener outcome. Enabling BFD on a peer while the socket
	// cannot be bound used to succeed here and retry forever in the background.
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) DeletePeer(ctx context.Context, peerAddress netip.Addr) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	select {
	case s.eventPeerUpdate <- &bfdEventPeerUpdate{isAdd: false, peerAddress: peerAddress}:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) GetPeerState(peerAddress netip.Addr) (*bfdPeerState, error) {
	state := s.getPeerState(peerAddress)
	if state == nil {
		return nil, errors.New("peer not found")
	}
	return state, nil
}

func (s *bfdServer) GetPeerStateList() []*bfdPeerState {
	return s.getPeerStateList()
}

// listenPort is the UDP port the server listens on, defaulting to RFC 5881's
// 3784 before any config has been applied.
func (s *bfdServer) listenPort() uint16 {
	if s.config != nil && s.config.Port != 0 {
		return s.config.Port
	}
	return BfdServerPort
}

// IsListening reports whether the BFD socket is actually bound.
//
// A BFD server that is configured but not listening is the dangerous state:
// BGP comes up, the peers exist, and nothing detects anything. It has to be
// observable, because the operator's belief that they have sub-second failover
// is otherwise unfalsifiable.
func (s *bfdServer) IsListening() bool {
	return s.udpServerLive.Load()
}

func (s *bfdServer) GetServerStats() *api.BfdState {
	return &api.BfdState{
		Listening:      s.udpServerLive.Load(),
		WrongHopLimit:  s.stats.wrongHopLimit.Load(),
		ReceivedPacket: s.stats.rxPacket.Load(),
		ReceivedDrop:   s.stats.rxDrop.Load(),
		ReceivedError:  s.stats.rxError.Load(),
		InvalidPacket:  s.stats.invalidPacket.Load(),
		UnknownPeer:    s.stats.unknownPeer.Load(),
	}
}

func (s *bfdServer) loop() {
	defer s.shutdownWait.Done()

	for {
		select {
		case <-s.eventStartStop.C:
			success := true

			s.peersMutex.RLock()
			peersLen := len(s.peers)
			s.peersMutex.RUnlock()

			if peersLen > 0 {
				success = s.start()
			} else {
				s.stop()
			}

			if success {
				s.eventStartStop.Stop()
			}
		case ev := <-s.eventConfig:
			s.config = ev.config
			if ev.ack != nil {
				ev.ack <- struct{}{}
			}
		case ev := <-s.eventPeerUpdate:
			var err error
			if ev.isAdd {
				s.addBfdPeer(ev.peerAddress, ev.config, ev.bindInterface)
				// Bind now rather than waiting for the next tick, so the
				// caller can be told. Retrying invisibly is what let an
				// operator believe they had sub-second failover.
				if !s.start() {
					err = fmt.Errorf("BFD is enabled for %s but the server cannot listen on UDP %d",
						ev.peerAddress, s.listenPort())
				}
			} else {
				s.deleteBfdPeer(ev.peerAddress)
			}
			if ev.result != nil {
				ev.result <- err
			}

			s.eventStartStop.Reset(time.Second)
		case <-s.eventShutdown:
			s.shutdown()
			return
		}
	}
}

func (s *bfdServer) start() bool {
	if s.udpServer == nil {
		s.startServer()
	}

	return s.udpServer != nil
}

func (s *bfdServer) startServer() {
	if s.config == nil {
		// BFD server not configured
		return
	}

	addressString := ":" + strconv.FormatUint(uint64(s.config.Port), 10)

	var lc net.ListenConfig
	lc.Control = func(network, address string, sc syscall.RawConn) error {
		if s.listenInterface != "" {
			s.logger.Info("binding bfd listener to interface", slog.String("interface", s.listenInterface))
			if err := netutils.SetBindToDevSockopt(sc, s.listenInterface); err != nil {
				return err
			}
		}

		// RFC 5881 5 requires discarding packets whose TTL/hop limit is not
		// 255. Without this the receive path cannot see the value, so the
		// protection was transmit-only. Recorded rather than fatal: on a
		// platform that cannot report it, BFD should still run, just without
		// the check, and say so.
		if err := netutils.SetRecvHopLimitSockopt(sc); err != nil {
			s.gtsmRxAvailable.Store(false)
			s.logger.Warn("cannot enable receive hop-limit reporting; RFC 5881 GTSM validation is disabled",
				slog.String("Topic", "bfd"),
				slog.Any("Error", err),
			)
		} else {
			s.gtsmRxAvailable.Store(true)
		}

		return netutils.SetReuseAddrSockopt(sc)
	}

	l, err := lc.ListenPacket(context.Background(), "udp", addressString)
	if err != nil {
		// Spelled out because the consequence is not obvious from a bind error:
		// peers stay configured, BGP comes up, and nothing detects a failure.
		s.logger.Error("BFD server cannot listen; sub-second failover is NOT active",
			slog.String("Topic", "bfd"),
			slog.String("Address", addressString),
			slog.Any("Error", err),
		)
		return
	}

	var ok bool
	s.udpServer, ok = l.(*net.UDPConn)
	if !ok {
		s.logger.Error("Unexpected connection listener",
			slog.String("Topic", "bfd"),
			slog.String("Address", addressString),
			slog.Any("Error", err),
		)
		return
	}

	s.udpServerLive.Store(true)

	s.logger.Info("BFD server is started",
		slog.String("Topic", "bfd"),
		slog.String("Address", addressString),
	)

	s.serverStop = make(chan struct{})
	s.serverWait.Add(1)
	go s.serverLoop()
}

func (s *bfdServer) stop() {
	if s.udpServer == nil {
		return
	}

	close(s.serverStop)
	s.udpServer.Close()
	s.serverWait.Wait()
	s.udpServer = nil
	s.udpServerLive.Store(false)

	s.logger.Info("BFD server is stopped",
		slog.String("Topic", "bfd"),
	)
}

func (s *bfdServer) addBfdPeer(peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) {
	s.peersMutex.RLock()
	_, ok := s.peers[peerAddress]
	s.peersMutex.RUnlock()

	if ok {
		s.logger.Debug("BFD peer already exist",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		return
	}

	bfdPeer := NewBfdPeer(s.peerState, s.logger, peerAddress, config, bindInterface)
	if bfdPeer != nil {
		s.logger.Info("Insert BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		s.peersMutex.Lock()
		s.peers[peerAddress] = bfdPeer
		s.peersMutex.Unlock()
	}
}

func (s *bfdServer) deleteBfdPeer(peerAddress netip.Addr) {
	s.peersMutex.RLock()
	peer, ok := s.peers[peerAddress]
	s.peersMutex.RUnlock()

	if !ok {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		return
	}

	s.peersMutex.Lock()
	delete(s.peers, peerAddress)
	s.peersMutex.Unlock()
	peer.Stop()

	s.logger.Info("Remove BFD peer",
		slog.String("Topic", "bfd"),
		slog.String("Peer", peerAddress.String()),
	)
}

func (s *bfdServer) getPeerState(address netip.Addr) *bfdPeerState {
	s.peersMutex.RLock()
	peer, ok := s.peers[address]
	s.peersMutex.RUnlock()

	if !ok {
		return nil
	}

	// Only the fields the peer actually maintains are set. RemoteSessionState,
	// the diagnostic codes, LastFailureTime and RemoteMinimumReceiveInterval are
	// not tracked anywhere, so they are left unset rather than reported as a
	// zero that reads like real data. The discriminators are deliberately not
	// exposed: they are plain fields written by the peer's own goroutine, and
	// reading them here would be a data race for no operational benefit.
	return &bfdPeerState{
		peerAddress: peer.peerAddress,
		state: api.BfdPeerState{
			SessionState:       api.BfdSessionState(peer.state.Load()),
			FailureTransitions: peer.stats.downTransitions.Load(),
			BfdAsync: &api.BfdAsyncCounters{
				ReceivedPackets:    peer.stats.rxPacket.Load(),
				TransmittedPackets: peer.stats.txPacket.Load(),
			},
		},
	}
}

func (s *bfdServer) getPeerStateList() []*bfdPeerState {
	s.peersMutex.RLock()
	list := make([]*bfdPeerState, 0, len(s.peers))
	for _, peer := range s.peers {
		list = append(list, &bfdPeerState{
			peerAddress: peer.peerAddress,
			state: api.BfdPeerState{
				SessionState: api.BfdSessionState(peer.state.Load()),
				BfdAsync: &api.BfdAsyncCounters{
					ReceivedPackets:    peer.stats.rxPacket.Load(),
					TransmittedPackets: peer.stats.txPacket.Load(),
				},
			},
		})
	}
	s.peersMutex.RUnlock()

	return list
}

func (s *bfdServer) shutdown() {
	s.peersMutex.Lock()
	peers := make([]*bfdPeer, 0, len(s.peers))
	for address, peer := range s.peers {
		peers = append(peers, peer)
		delete(s.peers, address)
	}
	s.peersMutex.Unlock()

	for _, peer := range peers {
		peer.Stop()
	}

	s.stop()
	s.eventStartStop.Stop()
}

func (s *bfdServer) serverLoop() {
	defer s.serverWait.Done()

	// buffer size must be more than BFD Control Packet size
	buffer := make([]byte, 4096)
	oob := make([]byte, 128)
	for {
		length, oobLen, _, address, err := s.udpServer.ReadMsgUDP(buffer, oob)
		if err != nil {
			select {
			case <-s.serverStop:
				return
			default:
				s.stats.rxError.Add(1)
			}

			continue
		}

		// RFC 5881 5: a single-hop session must discard anything that did not
		// arrive with TTL/hop limit 255, which is what stops an off-path
		// sender reaching the session at all. Only enforced when the kernel
		// actually reports the value; otherwise the check is skipped rather
		// than failing every packet closed.
		if s.gtsmRxAvailable.Load() {
			if hopLimit, ok := netutils.ParseHopLimit(oob[:oobLen]); ok && hopLimit != bfdRequiredHopLimit {
				s.logger.Debug("Discarding BFD packet with wrong hop limit",
					slog.String("Topic", "bfd"),
					slog.Any("Peer", address),
					slog.Int("HopLimit", hopLimit),
				)
				s.stats.wrongHopLimit.Add(1)
				continue
			}
		}

		bfdPacket := &bfd.BFDHeader{}
		err = bfdPacket.UnmarshalBinary(buffer[:length])
		if err != nil {
			s.logger.Debug("Invalid packet",
				slog.String("Topic", "bfd"),
				slog.Any("Error", err),
			)

			s.stats.invalidPacket.Add(1)
			continue
		}

		s.rxPacket(address, bfdPacket)
	}
}

func (s *bfdServer) rxPacket(address *net.UDPAddr, packet *bfd.BFDHeader) {
	addr := address.AddrPort().Addr().Unmap()

	s.peersMutex.RLock()
	peer, ok := s.peers[addr]
	s.peersMutex.RUnlock()

	if !ok {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.Any("Peer", addr),
		)

		s.stats.unknownPeer.Add(1)
		return
	}

	ok = peer.Rx(packet)
	if !ok {
		s.stats.rxDrop.Add(1)
		return
	}

	s.stats.rxPacket.Add(1)
}
