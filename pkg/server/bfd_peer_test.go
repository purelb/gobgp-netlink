package server

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"github.com/stretchr/testify/assert"
)

func Test_NewBfdPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	assert.NotNil(p)
}

func Test_NewBfdPeerDefaultPort(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Enabled: true,
	}, "")
	defer p.Stop()

	assert.Equal(BfdServerPort, p.peerPort)
}

func Test_BfdPeerRemoteUDPAddrZone(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}

	// link-local peer with an interface zone (unnumbered single-hop BFD): the zone must carry through to
	// the dialed UDP address, otherwise the socket can't reach the link-local peer.
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("fe80::1%eth0"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")
	defer p.Stop()

	addr := p.remoteUDPAddr()
	assert.Equal("eth0", addr.Zone)
	assert.Equal("fe80::1", addr.IP.String())
	assert.Equal(13784, addr.Port)

	// a global peer carries no zone.
	g := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("10.0.0.1"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")
	defer g.Stop()

	assert.Empty(g.remoteUDPAddr().Zone)
}

func Test_BfdPeerStopIdempotent(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")

	p.Stop()
	p.Stop()

	assert.True(p.stopped.Load())
}

func Test_RxPacket(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")

	assert.Equal(p.stats.rxPacket.Load(), uint64(0))

	p.Rx(&bfd.BFDHeader{MyDiscriminator: 111, DetectTimeMultiplier: 5})

	time.Sleep(2 * time.Second)
	p.Stop()

	assert.NotEqual(p.stats.rxPacket.Load(), uint64(0))
}

func Test_RxPacketRemoteDownResetsPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator.Store(12345)

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      67890,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})

	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState(p.state.Load()))
	assert.Equal(int64(1), atomic.LoadInt64(&ps.resetPeerCount))
}

func Test_RxPacketRFCStateTransitions(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, api.BfdSessionState(p.state.Load()))
	assert.Equal(uint32(111), p.yourDiscriminator.Load())

	p.setStateDown()
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		MyDiscriminator:      222,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState(p.state.Load()))

	p.setStateInit(333)
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		MyDiscriminator:      444,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, api.BfdSessionState(p.state.Load()))
	assert.Equal(uint32(444), p.yourDiscriminator.Load())
}

// Test_RxPacketDetectionTimeFromRemote pins RFC 5880 Section 6.8.4: the detection time
// must be the remote Detect Mult multiplied by max(local RequiredMinRx,
// remote DesiredMinTx), not our own multiplier multiplied by our own rxInterval.
// With local rx=300ms/mult=3 and remote tx=1000ms, the old detector expired at
// 900ms, before the next remote packet. After the fix it stretches to 3000ms.
func Test_RxPacketDetectionTimeFromRemote(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000, // 300ms
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// Before any packet: our-config-only baseline (the old, buggy value).
	assert.Equal(3*300*time.Millisecond, p.expiryInterval)

	// Peer advertises a SLOWER cadence (BIRD default on the tap): tx=1000ms, mult=3.
	p.rxPacket(&bfd.BFDHeader{
		State:                 bfd.StateDown,
		MyDiscriminator:       111,
		YourDiscriminator:     p.myDiscriminator,
		DesiredMinTxInterval:  1000000, // 1000ms
		DetectTimeMultiplier:  3,
		RequiredMinRxInterval: 1000000,
	})
	// Detection must now track the peer: 3 * max(300ms, 1000ms) = 3000ms.
	assert.Equal(3*1000*time.Millisecond, p.expiryInterval)

	// RFC 5880 Section 6.8.6: a packet with Detect Mult == 0 MUST be discarded,
	// so it must NOT collapse the detector to a bogus value — the previously
	// negotiated detection time stays in effect.
	p.rxPacket(&bfd.BFDHeader{
		State:             bfd.StateUp,
		MyDiscriminator:   111,
		YourDiscriminator: p.myDiscriminator,
	})
	assert.Equal(3*1000*time.Millisecond, p.expiryInterval)
	assert.Equal(uint64(1), p.stats.invalidMultiplier.Load())
}

func Test_RxPacketZeroMultiplierDiscarded(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// RFC 5880 Section 6.8.6: Detect Mult == 0 MUST be discarded before it can
	// drive any state transition or reset the detection timer.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DesiredMinTxInterval: 1000000,
		DetectTimeMultiplier: 0,
	})
	assert.Equal(uint64(1), p.stats.invalidMultiplier.Load())
	assert.Equal(uint64(0), p.stats.rxPacket.Load())
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
}

func Test_RxPacketUnboundDiscriminatorDiscarded(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// RFC 5880 Section 6.8.6: a zero Your Discriminator is only meaningful
	// from a remote system in Down or AdminDown. Init carries no session
	// binding here, so it must not drive the session Up.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateInit,
		MyDiscriminator:      111,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(uint64(1), p.stats.invalidDiscriminator.Load())

	// RFC 5880 Section 6.8.6: a zero My Discriminator MUST be discarded. It
	// is also the value setStateDown uses to mean "no remote session".
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      0,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(uint32(0), p.yourDiscriminator.Load())
	assert.Equal(uint64(2), p.stats.invalidDiscriminator.Load())

	// A Down packet with a zero Your Discriminator is still accepted: that is
	// how a remote system that has not learned our discriminator starts up.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      222,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, p.sessionState())
	assert.Equal(uint32(222), p.yourDiscriminator.Load())
}

func Test_RxPacketZeroYourDiscriminatorForeignRemoteDiscarded(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator.Store(12345)

	// The remote discriminator is already bound, so a Down packet that omits
	// Your Discriminator and carries a different My Discriminator did not come
	// from that remote system. Accepting it would reset the BGP peer.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      67890,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())
	assert.Equal(uint32(12345), p.yourDiscriminator.Load())
	assert.Equal(int64(0), atomic.LoadInt64(&ps.resetPeerCount))
	assert.Equal(uint64(1), p.stats.invalidDiscriminator.Load())

	// The bound remote system may still omit Your Discriminator when it
	// signals Down, and that packet has to be honored.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      12345,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(int64(1), atomic.LoadInt64(&ps.resetPeerCount))
}

func Test_ExpiryDoesNotResetAlreadyDownPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")
	defer p.Stop()

	p.setStateDown()
	p.expiry()

	assert.Equal(int64(0), atomic.LoadInt64(&ps.resetPeerCount))
}

func Test_TxPacket(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")

	err := eventually(4*time.Second, func() error {
		if p.stats.txPacket.Load() > 3 {
			return nil
		}
		return fmt.Errorf("must be: txPacket > 3")
	})
	assert.NoError(err)

	p.Stop()
}

// Test_BfdFailureTransitionsCountOnlyRealFlaps pins the counter that answers
// "has this session been flapping?".
//
// It exists because api.BfdPeerState.FailureTransitions was in the proto, copied
// through pkg/config/oc, and never written by anything - so it read as a
// confident zero on a session that had just been torn down repeatedly on
// hardware. The distinction that matters is that only a transition out of UP is
// a failure: a session that has never come up re-enters DOWN on every detect
// interval, and counting those would report a permanently broken peer as a
// wildly flapping one.
func Test_BfdFailureTransitionsCountOnlyRealFlaps(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// A session that never came up: DOWN -> DOWN, repeatedly.
	p.setStateDown()
	p.setStateDown()
	assert.Equal(uint64(0), p.stats.downTransitions.Load(),
		"a session that never came up has not failed; counting these would report "+
			"an unreachable peer as a flapping one")

	// INIT -> DOWN is also not a failure: it never reached UP.
	p.setStateInit(1)
	p.setStateDown()
	assert.Equal(uint64(0), p.stats.downTransitions.Load())

	// UP -> DOWN is the real thing.
	p.setStateUp(1)
	p.setStateDown()
	assert.Equal(uint64(1), p.stats.downTransitions.Load())

	p.setStateUp(1)
	p.setStateDown()
	assert.Equal(uint64(2), p.stats.downTransitions.Load())
}

// newBareBfdPeer builds a peer without starting its event loop, so state
// machine behaviour can be driven deterministically from the test.
func newBareBfdPeer(t *testing.T, state api.BfdSessionState, expiry time.Duration) *bfdPeer {
	t.Helper()
	p := &bfdPeer{
		peerState:      &mockPeerState{},
		logger:         slog.Default(),
		peerAddress:    netip.MustParseAddr("127.0.0.1"),
		expiryInterval: expiry,
		eventExpiry:    time.NewTicker(time.Hour),
	}
	p.state.Store(int32(state))
	return p
}

// Test_BfdExpiryHonoursTheDetectDeadline is the §7.3 false-session-down fix.
//
// loop() selects over rx, tx and expiry, and Go picks uniformly among ready
// cases. With a valid packet queued and the detect timer fired, there was a
// coin flip on tearing down a live session while the proof of life sat in the
// channel. The timer firing is not evidence the peer is gone; the absence of a
// recent accepted packet is, so expiry re-checks the deadline.
func Test_BfdExpiryHonoursTheDetectDeadline(t *testing.T) {
	assert := assert.New(t)
	const expiry = 900 * time.Millisecond

	t.Run("a packet inside the window keeps the session up", func(t *testing.T) {
		p := newBareBfdPeer(t, api.BfdSessionState_BFD_SESSION_STATE_UP, expiry)
		p.lastRxAccept = time.Now()

		p.expiry()

		assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState(),
			"the detect timer fired but a packet was accepted well inside the "+
				"window; tearing down here is the false session-down")
		assert.Equal(uint64(0), p.stats.expired.Load())
		assert.Equal(int64(0), p.peerState.(*mockPeerState).resetPeerCount,
			"a live session must not reset its BGP peer")
	})

	t.Run("no packet within the window expires the session", func(t *testing.T) {
		p := newBareBfdPeer(t, api.BfdSessionState_BFD_SESSION_STATE_UP, expiry)
		p.lastRxAccept = time.Now().Add(-2 * expiry)

		p.expiry()

		assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
		assert.Equal(uint64(1), p.stats.expired.Load())
		assert.Equal(int64(1), p.peerState.(*mockPeerState).resetPeerCount)
	})

	t.Run("a session that never received anything still expires", func(t *testing.T) {
		p := newBareBfdPeer(t, api.BfdSessionState_BFD_SESSION_STATE_UP, expiry)
		// lastRxAccept is the zero time: the deadline check must not read that
		// as "recently seen" and pin an unreachable peer up forever.
		p.expiry()

		assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	})
}

// Test_BfdTxIntervalIsJittered covers RFC 5880 §6.8.7. Without jitter every
// peer transmits on a fixed period, which across a DaemonSet synchronises every
// node's transmit phase and lines up every node's BGP reset on a fabric event.
func Test_BfdTxIntervalIsJittered(t *testing.T) {
	assert := assert.New(t)

	p := &bfdPeer{txInterval: 300 * time.Millisecond, multiplier: 3}
	seen := map[time.Duration]bool{}
	for range 200 {
		d := p.jitteredTxInterval()
		assert.LessOrEqual(d, p.txInterval, "jitter reduces the interval, never extends it")
		assert.GreaterOrEqual(d, p.txInterval*75/100, "RFC 5880 §6.8.7 bounds the reduction at 25%")
		seen[d] = true
	}
	assert.Greater(len(seen), 1, "a fixed interval is what this exists to prevent")

	// With a multiplier of 1 a single lost packet expires the session, so the
	// reduction is at least 10% to keep a margin.
	p1 := &bfdPeer{txInterval: 300 * time.Millisecond, multiplier: 1}
	for range 200 {
		d := p1.jitteredTxInterval()
		assert.LessOrEqual(d, p1.txInterval*90/100)
		assert.GreaterOrEqual(d, p1.txInterval*75/100)
	}
}

// Test_BfdRxQueueIsDeeperThanOne: the queue was depth 1 with Rx() dropping when
// full, so any stall longer than one transmit interval discarded proof that the
// peer was alive - under exactly the CPU pressure that makes a stall likely.
func Test_BfdRxQueueIsDeeperThanOne(t *testing.T) {
	assert := assert.New(t)
	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port: 13784, Enabled: true, DetectionMultiplier: 3,
		RequiredMinimumReceive: 300000, DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	assert.Equal(bfdRxQueueDepth, cap(p.eventRxPacket))
	assert.GreaterOrEqual(bfdRxQueueDepth, 3,
		"the queue must absorb a whole detection window at the default multiplier")
}

// Test_BfdPeerStateSnapshotPopulatesEveryField proves no BfdPeerState field is
// reported as a confident zero.
//
// Five of the ten - the remote session state, both diagnostic codes, the last
// failure time and the remote receive interval - were written by nothing at
// all, and two more were only reachable through one of the two accessors. A
// session that had just flapped therefore reported "remote -" and "0 failure
// transitions", both false, which is worse than reporting nothing.
func Test_BfdPeerStateSnapshotPopulatesEveryField(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port: 13784, Enabled: true, DetectionMultiplier: 3,
		RequiredMinimumReceive: 300000, DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// Drive a session up, then fail it, entirely through the state machine.
	p.rxPacket(&bfd.BFDHeader{
		State: bfd.StateDown, Diagnostic: bfd.DiagnosticNoDiagnostic,
		MyDiscriminator: 4242, DetectTimeMultiplier: 3,
		RequiredMinRxInterval: 500000, DesiredMinTxInterval: 500000,
	})
	p.rxPacket(&bfd.BFDHeader{
		State: bfd.StateInit, Diagnostic: bfd.DiagnosticNoDiagnostic,
		MyDiscriminator: 4242, YourDiscriminator: p.myDiscriminator,
		DetectTimeMultiplier: 3, RequiredMinRxInterval: 500000, DesiredMinTxInterval: 500000,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())

	p.lastRxAccept = time.Now().Add(-time.Hour) // force a real expiry
	p.expiry()

	s := peerStateSnapshot(p)

	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, s.GetSessionState())
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, s.GetRemoteSessionState(),
		"the peer's own advertised state must be recorded, not left unset")
	assert.Equal(api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_DETECTION_TIMEOUT,
		s.GetLocalDiagnosticCode(), "we timed the session out, so say so")
	assert.Equal(api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC, s.GetRemoteDiagnosticCode())
	assert.Equal(uint32(500000), s.GetRemoteMinimumReceiveInterval())
	assert.NotZero(s.GetLocalDiscriminator())
	assert.Equal(uint64(1), s.GetFailureTransitions())
	assert.NotZero(s.GetLastFailureTime(), "a session that just failed has a failure time")
	assert.NotNil(s.GetBfdAsync())
	assert.Equal(uint64(2), s.GetBfdAsync().GetReceivedPackets())
}
