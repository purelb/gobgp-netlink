package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc5881
	//   The source port MUST be in the range 49152 through 65535
	bfdSourcePortMin = 49152
	bfdSourcePortMax = 65535

	// Some default values
	defaultMultiplier = 3
	defaultRxInterval = 1000 * time.Millisecond
	defaultTxInterval = 1000 * time.Millisecond

	// bfdRxQueueDepth is how many received control packets may wait for the
	// peer's event loop.
	//
	// It was 1, with Rx() dropping on a full queue. Any stall longer than one
	// transmit interval therefore discarded proof that the peer was alive,
	// which is the opposite of what the queue is for: under exactly the CPU
	// pressure that makes a stall likely, BFD would manufacture a session-down
	// on a healthy peer. Depth covers a whole detection window at the default
	// multiplier of 3, doubled for headroom, and stays bounded so a wedged
	// loop cannot grow memory.
	bfdRxQueueDepth = 8

	// RFC 5880 6.8.7: the transmit interval is jittered down by up to 25% so
	// peers do not synchronise. With a multiplier of 1 the reduction is at
	// least 10%, so a single lost packet cannot immediately expire the session.
	bfdTxJitterMaxPercent   = 25
	bfdTxJitterMinPercent   = 0
	bfdTxJitterMinPercentM1 = 10
)

type bfdPeerStats struct {
	rxPacket             atomic.Uint64
	txPacket             atomic.Uint64
	txDrop               atomic.Uint64
	txError              atomic.Uint64
	invalidDiscriminator atomic.Uint64
	invalidMultiplier    atomic.Uint64
	expired              atomic.Uint64
	// downTransitions counts sessions going up -> down, which is what an
	// operator means by a flap. expired counts only the detect-timer path, so it
	// misses a peer that signalled DOWN explicitly.
	downTransitions atomic.Uint64
}

type bfdPeer struct {
	peerState     peerState
	logger        *slog.Logger
	peerAddress   netip.Addr
	peerPort      int
	bindInterface string

	udpClient *net.UDPConn

	expiryInterval time.Duration

	state             atomic.Int32
	myDiscriminator   uint32
	yourDiscriminator uint32
	multiplier        uint8
	rxInterval        time.Duration
	txInterval        time.Duration

	// lastRxAccept is when a packet last passed validation and re-armed the
	// detect timer. Only the event loop touches it, so it needs no lock.
	lastRxAccept time.Time

	eventStart    *time.Ticker
	eventRxPacket chan *bfd.BFDHeader
	eventTx       *time.Timer
	eventExpiry   *time.Ticker
	eventShutdown chan struct{}
	shutdownOnce  sync.Once
	shutdownWait  sync.WaitGroup
	stopped       atomic.Bool

	stats bfdPeerStats
}

func NewBfdPeer(ps peerState, logger *slog.Logger, peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) *bfdPeer {
	peerPort := int(config.Port)
	if peerPort == 0 {
		peerPort = BfdServerPort
	}

	p := &bfdPeer{
		peerState:     ps,
		logger:        logger,
		peerAddress:   peerAddress,
		peerPort:      peerPort,
		bindInterface: bindInterface,

		myDiscriminator: randomBFDMyDiscriminator(),
		multiplier:      defaultMultiplier,
		rxInterval:      defaultRxInterval,
		txInterval:      defaultTxInterval,

		eventStart:    time.NewTicker(time.Second),
		eventRxPacket: make(chan *bfd.BFDHeader, bfdRxQueueDepth),
		eventShutdown: make(chan struct{}),
	}

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))

	if config.DetectionMultiplier > 0 {
		p.multiplier = config.DetectionMultiplier
	}

	if config.RequiredMinimumReceive > 0 {
		p.rxInterval = time.Duration(config.RequiredMinimumReceive) * time.Microsecond
	}

	if config.DesiredMinimumTxInterval > 0 {
		p.txInterval = time.Duration(config.DesiredMinimumTxInterval) * time.Microsecond
	}

	p.expiryInterval = time.Duration(p.multiplier) * p.rxInterval
	p.eventTx = time.NewTimer(p.jitteredTxInterval())

	p.eventExpiry = time.NewTicker(p.expiryInterval)
	p.eventExpiry.Stop()

	p.shutdownWait.Add(1)
	go p.loop()
	return p
}

func (p *bfdPeer) Rx(packet *bfd.BFDHeader) bool {
	if p.stopped.Load() {
		return false
	}

	select {
	case p.eventRxPacket <- packet:
		return true
	case <-p.eventShutdown:
		return false
	default:
		return false
	}
}

func (p *bfdPeer) Stop() {
	p.shutdownOnce.Do(func() {
		p.stopped.Store(true)
		close(p.eventShutdown)
		p.shutdownWait.Wait()
	})
}

func (p *bfdPeer) loop() {
	defer p.shutdownWait.Done()

	for {
		select {
		case <-p.eventStart.C:
			success := p.start()
			if success {
				p.eventStart.Stop()
			}
		case bfdPacket := <-p.eventRxPacket:
			p.rxPacket(bfdPacket)
		case <-p.eventTx.C:
			p.tx()
			// A Timer, not a Ticker, because each period is jittered.
			p.eventTx.Reset(p.jitteredTxInterval())
		case <-p.eventExpiry.C:
			// Drain first. select picks uniformly among ready cases, so a
			// queued valid packet and a fired detect timer give a coin flip
			// on declaring a live session down with the proof of life still
			// sitting in the channel.
			p.drainRxPacket()
			p.expiry()
		case <-p.eventShutdown:
			p.shutdown()
			return
		}
	}
}

func (p *bfdPeer) start() bool {
	if p.udpClient == nil {
		p.startClient()
	}

	return p.udpClient != nil
}

func (p *bfdPeer) stop() {
	if p.udpClient == nil {
		return
	}

	err := p.udpClient.Close()
	if err != nil {
		p.logger.Warn("Can't close UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)
	}

	p.udpClient = nil

	p.logger.Debug("BFD client is stopped",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)
}

// remoteUDPAddr builds the BFD peer's UDP address. The zone is preserved so a link-local peer
// (fe80::…%iface, as used by unnumbered single-hop BFD per RFC 5881) can be reached — dialing a
// link-local address without its zone fails.
func (p *bfdPeer) remoteUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.peerAddress.AsSlice(),
		Zone: p.peerAddress.Zone(),
		Port: p.peerPort,
	}
}

func (p *bfdPeer) startClient() {
	localAddress := &net.UDPAddr{
		Port: randRange(bfdSourcePortMin, bfdSourcePortMax),
	}

	remoteAddress := p.remoteUDPAddr()

	var err error

	dialer := net.Dialer{
		LocalAddr: localAddress,
		Control: func(network, address string, c syscall.RawConn) error {
			if p.bindInterface != "" {
				return netutils.SetBindToDevSockopt(c, p.bindInterface)
			}

			return nil
		},
	}

	conn, err := dialer.Dial("udp", remoteAddress.String())
	if err != nil {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		return
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", "connection is not a UDP connection"),
		)

		return
	}

	p.udpClient = udpConn

	// https://datatracker.ietf.org/doc/html/rfc5881
	//   If BFD authentication is not in use on a session, all BFD Control
	//   packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//   Limit value of 255
	err = netutils.SetUDPTTLSockopt(p.udpClient, 255)
	if err != nil {
		p.logger.Error("Can't set TTL to 255",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		err = p.udpClient.Close()
		if err != nil {
			p.logger.Warn("Can't close UDP",
				slog.String("Topic", "bfd"),
				slog.String("Peer", p.peerAddress.String()),
			)
		}

		p.udpClient = nil
		return
	}

	p.logger.Debug("BFD client is started",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
		slog.String("LocalAddress", localAddress.String()),
		slog.String("RemoteAddress", remoteAddress.String()),
	)
}

func (p *bfdPeer) rxPacket(h *bfd.BFDHeader) {
	// RFC 5880 Section 6.8.6: if the Detect Mult field is zero, the packet
	// MUST be discarded.
	if h.DetectTimeMultiplier == 0 {
		p.stats.invalidMultiplier.Add(1)
		return
	}

	// RFC 5880 Section 6.8.6: if the My Discriminator field is zero, the
	// packet MUST be discarded.
	if h.MyDiscriminator == 0 {
		p.stats.invalidDiscriminator.Add(1)
		return
	}

	// RFC 5880 Section 6.8.6: a nonzero Your Discriminator selects the
	// session and MUST match ours. A zero Your Discriminator carries no
	// session binding, so it is only accepted from a remote system that has
	// not learned our discriminator yet, i.e. one in Down or AdminDown.
	if h.YourDiscriminator != 0 {
		if h.YourDiscriminator != p.myDiscriminator {
			p.stats.invalidDiscriminator.Add(1)
			return
		}
	} else {
		if h.State != bfd.StateDown && h.State != bfd.StateAdminDown {
			p.stats.invalidDiscriminator.Add(1)
			return
		}

		// Once the remote discriminator is bound, a packet that omits Your
		// Discriminator still has to come from that same remote system, or
		// it can tear the session down without ever having seen it.
		if p.yourDiscriminator != 0 && h.MyDiscriminator != p.yourDiscriminator {
			p.stats.invalidDiscriminator.Add(1)
			return
		}
	}

	p.stats.rxPacket.Add(1)

	// RFC 5880 Section 6.8.4: Detection Time is the remote Detect Mult
	// multiplied by the negotiated receive interval, i.e. the greater of our
	// RequiredMinRxInterval and the remote DesiredMinTxInterval.
	negotiatedRx := p.rxInterval
	if remoteTx := time.Duration(h.DesiredMinTxInterval) * time.Microsecond; remoteTx > negotiatedRx {
		negotiatedRx = remoteTx
	}
	p.expiryInterval = time.Duration(h.DetectTimeMultiplier) * negotiatedRx

	switch h.State {
	case bfd.StateAdminDown:
		if p.sessionState() != api.BfdSessionState_BFD_SESSION_STATE_DOWN {
			p.remoteDown()
		}
	case bfd.StateDown:
		switch p.sessionState() {
		case api.BfdSessionState_BFD_SESSION_STATE_DOWN:
			p.setStateInit(h.MyDiscriminator)
		case api.BfdSessionState_BFD_SESSION_STATE_UP:
			p.remoteDown()
		}
	case bfd.StateInit:
		switch p.sessionState() {
		case api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState_BFD_SESSION_STATE_INIT:
			p.setStateUp(h.MyDiscriminator)
		}
	case bfd.StateUp:
		if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT {
			p.setStateUp(h.MyDiscriminator)
		}
	}

	if h.Poll {
		p.sendPacket(p.sessionStateToWire(), false, true, h.MyDiscriminator)
	}

	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT ||
		p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_UP {
		p.lastRxAccept = time.Now()
		p.eventExpiry.Reset(p.expiryInterval)
	}
}

// jitteredTxInterval returns the next transmit interval, reduced by a random
// percentage per RFC 5880 6.8.7.
//
// Without this every peer transmits on a fixed period. Across a DaemonSet that
// synchronises every node's transmit phase, so a fabric event lines up every
// node's BGP reset instead of spreading them.
func (p *bfdPeer) jitteredTxInterval() time.Duration {
	minPct := bfdTxJitterMinPercent
	if p.multiplier == 1 {
		minPct = bfdTxJitterMinPercentM1
	}
	reduction := randRange(minPct, bfdTxJitterMaxPercent)
	return time.Duration(int64(p.txInterval) * int64(100-reduction) / 100)
}

func (p *bfdPeer) tx() {
	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		p.sendPacket(bfd.StateUp, false, false, p.yourDiscriminator)
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		p.sendPacket(bfd.StateInit, false, false, p.yourDiscriminator)
	default:
		p.sendPacket(bfd.StateDown, false, false, 0)
	}
}

// drainRxPacket processes every control packet already queued, without
// blocking. Called from the event loop only.
func (p *bfdPeer) drainRxPacket() {
	for {
		select {
		case packet := <-p.eventRxPacket:
			p.rxPacket(packet)
		default:
			return
		}
	}
}

func (p *bfdPeer) expiry() {
	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_DOWN {
		p.eventExpiry.Stop()
		return
	}

	// The timer firing is not proof the session is dead; the absence of a
	// recent valid packet is. Draining above may have accepted one, and a
	// packet can also land between the timer firing and this check. Either way
	// the deadline is authoritative, so re-arm for the remaining time instead
	// of tearing down a session that is demonstrably alive.
	if !p.lastRxAccept.IsZero() {
		if since := time.Since(p.lastRxAccept); since < p.expiryInterval {
			p.eventExpiry.Reset(p.expiryInterval - since)
			return
		}
	}

	p.logger.Warn("Expired",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.stats.expired.Add(1)

	p.resetPeer()
	p.setStateDown()
}

func (p *bfdPeer) shutdown() {
	p.stop()
	p.eventStart.Stop()
	p.eventTx.Stop()
	p.eventExpiry.Stop()
}

func (p *bfdPeer) remoteDown() {
	p.logger.Warn("Remote peer signaled BFD down",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.resetPeer()
	p.setStateDown()
}

func (p *bfdPeer) resetPeer() {
	if err := p.peerState.ResetPeer(context.Background(), &api.ResetPeerRequest{
		Address:       p.peerAddress.String(),
		Communication: "BFD is down",
		Soft:          false,
	}); err != nil {
		p.logger.Warn("ResetPeer failed",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("Err", err.Error()),
		)
	}
}

func (p *bfdPeer) sendPacket(state bfd.StateType, poll bool, final bool, yourDiscriminator uint32) {
	if p.udpClient == nil {
		p.stats.txDrop.Add(1)
		return
	}

	packet := &bfd.BFDHeader{
		Version:               1,
		State:                 state,
		Poll:                  poll,
		Final:                 final,
		DetectTimeMultiplier:  p.multiplier,
		MyDiscriminator:       p.myDiscriminator,
		YourDiscriminator:     yourDiscriminator,
		DesiredMinTxInterval:  uint32(p.txInterval.Microseconds()),
		RequiredMinRxInterval: uint32(p.rxInterval.Microseconds()),
	}

	buffer, err := packet.MarshalBinary()
	if err != nil {
		// should never happen
		p.logger.Error("MarshalBinary",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)
		return
	}

	_, err = p.udpClient.Write(buffer)
	if err != nil {
		p.logger.Debug("Can't send UDP packet",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)

		p.stats.txError.Add(1)
		return
	}

	p.stats.txPacket.Add(1)
}

func (p *bfdPeer) sessionState() api.BfdSessionState {
	return api.BfdSessionState(p.state.Load())
}

func (p *bfdPeer) sessionStateToWire() bfd.StateType {
	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		return bfd.StateUp
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		return bfd.StateInit
	case api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN:
		return bfd.StateAdminDown
	default:
		return bfd.StateDown
	}
}

func (p *bfdPeer) setStateDown() {
	p.logger.Debug("Set state to DOWN",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	// Only a transition out of UP is a failure. Re-entering DOWN from DOWN or
	// INIT is a session that never came up, which is a different condition and
	// must not inflate the flap count.
	if api.BfdSessionState(p.state.Load()) == api.BfdSessionState_BFD_SESSION_STATE_UP {
		p.stats.downTransitions.Add(1)
	}

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	p.yourDiscriminator = 0

	p.eventExpiry.Stop()
}

func (p *bfdPeer) setStateInit(yourDiscriminator uint32) {
	p.logger.Debug("Set state to INIT",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_INIT))
	p.yourDiscriminator = yourDiscriminator
}

func (p *bfdPeer) setStateUp(yourDiscriminator uint32) {
	p.logger.Debug("Set state to UP",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = yourDiscriminator

	p.eventExpiry.Reset(p.expiryInterval)

	// send poll packet
	p.sendPacket(bfd.StateUp, true, false, yourDiscriminator)
}
