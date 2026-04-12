/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type benchmarkNoOpBind struct{}

func (benchmarkNoOpBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, 0, errors.New("not supported")
}
func (benchmarkNoOpBind) Close() error                       { return nil }
func (benchmarkNoOpBind) SetMark(uint32) error               { return nil }
func (benchmarkNoOpBind) Send([][]byte, conn.Endpoint) error { return nil }
func (benchmarkNoOpBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, errors.New("not supported")
}
func (benchmarkNoOpBind) BatchSize() int { return conn.IdealBatchSize }

func benchmarkFirstPeer(tb testing.TB, dev *Device) *Peer {
	tb.Helper()

	dev.peers.RLock()
	defer dev.peers.RUnlock()
	for _, peer := range dev.peers.keyMap {
		return peer
	}
	tb.Fatal("no configured peers")
	return nil
}

func BenchmarkSendHandshakeInitiation(b *testing.B) {
	pair := genTestPair(b, false)
	if err := pair[0].dev.Down(); err != nil {
		b.Fatal(err)
	}
	if err := pair[1].dev.Down(); err != nil {
		b.Fatal(err)
	}
	peer := benchmarkFirstPeer(b, pair[0].dev)

	oldCachedBind := peer.device.net.cachedBind.Load()
	peer.device.net.cachedBind.Store(nil)
	b.Cleanup(func() {
		peer.device.net.cachedBind.Store(oldCachedBind)
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.handshake.mutex.Lock()
		peer.handshake.lastSentHandshake = time.Time{}
		peer.handshake.mutex.Unlock()

		if err := peer.SendHandshakeInitiation(true); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSendHandshakeCookie(b *testing.B) {
	pair := genTestPair(b, false)
	if err := pair[0].dev.Down(); err != nil {
		b.Fatal(err)
	}
	if err := pair[1].dev.Down(); err != nil {
		b.Fatal(err)
	}
	peer := benchmarkFirstPeer(b, pair[0].dev)

	oldBind := peer.device.net.bind
	peer.device.net.bind = benchmarkNoOpBind{}
	b.Cleanup(func() {
		peer.device.net.bind = oldBind
	})

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		b.Fatal(err)
	}
	var packet [MessageInitiationSize]byte
	_ = msg.marshal(packet[:])
	peer.cookieGenerator.AddMacs(packet[:])

	elem := QueueHandshakeElement{
		packet:   packet[:],
		endpoint: &DummyEndpoint{dst: netip.AddrFrom4([4]byte{127, 0, 0, 1})},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := peer.device.SendHandshakeCookie(&elem); err != nil {
			b.Fatal(err)
		}
	}
}
