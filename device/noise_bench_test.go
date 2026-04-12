/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/tai64n"
)

func BenchmarkHMAC1(b *testing.B) {
	var (
		sum [blake2s.Size]byte
		key [blake2s.Size]byte
		in  [96]byte
	)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range in {
		in[i] = byte(255 - i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HMAC1(&sum, key[:], in[:])
	}
}

func BenchmarkHMAC2(b *testing.B) {
	var (
		sum [blake2s.Size]byte
		key [blake2s.Size]byte
		in0 [48]byte
		in1 [48]byte
	)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range in0 {
		in0[i] = byte(i)
		in1[i] = byte(255 - i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(in0) + len(in1)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HMAC2(&sum, key[:], in0[:], in1[:])
	}
}

func BenchmarkKDF2(b *testing.B) {
	var (
		t0    [blake2s.Size]byte
		t1    [blake2s.Size]byte
		chain [blake2s.Size]byte
		input [32]byte
	)
	for i := range chain {
		chain[i] = byte(i + 17)
	}
	for i := range input {
		input[i] = byte(31 - i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KDF2(&t0, &t1, chain[:], input[:])
	}
}

func BenchmarkMixHash(b *testing.B) {
	var (
		dst  [blake2s.Size]byte
		hash [blake2s.Size]byte
		data [148]byte
	)
	for i := range hash {
		hash[i] = byte(100 + i)
	}
	for i := range data {
		data[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mixHash(&dst, &hash, data[:])
	}
}

func BenchmarkCreateMessageInitiation(b *testing.B) {
	pair := genTestPair(b, false)
	if err := pair[0].dev.Down(); err != nil {
		b.Fatal(err)
	}
	if err := pair[1].dev.Down(); err != nil {
		b.Fatal(err)
	}
	peer := benchmarkFirstPeer(b, pair[0].dev)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := peer.device.CreateMessageInitiation(peer); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkCreateMessageInitiationFixedEphemeral(device *Device, peer *Peer, ephemeral NoisePublicKey, ss [NoisePublicKeySize]byte) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: ephemeral,
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	var key [chacha20poly1305.KeySize]byte
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		ss[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], handshake.hash[:])
	handshake.mixHash(msg.Static[:])

	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	device.indexTable.Delete(handshake.localIndex)
	var err error
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func BenchmarkCreateMessageInitiationFixedEphemeral(b *testing.B) {
	pair := genTestPair(b, false)
	if err := pair[0].dev.Down(); err != nil {
		b.Fatal(err)
	}
	if err := pair[1].dev.Down(); err != nil {
		b.Fatal(err)
	}
	peer := benchmarkFirstPeer(b, pair[0].dev)

	localEphemeral, err := newPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	ephemeralPub := localEphemeral.publicKey()
	ss, err := localEphemeral.sharedSecret(peer.handshake.remoteStatic)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := benchmarkCreateMessageInitiationFixedEphemeral(peer.device, peer, ephemeralPub, ss); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkCreateMessageInitiationFixedEphemeralPrecomputedAEAD(device *Device, peer *Peer, ephemeral NoisePublicKey, staticCiphertext [NoisePublicKeySize + poly1305.TagSize]byte, hashAfterStatic [blake2s.Size]byte, aeadTimestamp cipher.AEAD) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	handshake.hash = hashAfterStatic
	handshake.chainKey = InitialChainKey

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: ephemeral,
		Static:    staticCiphertext,
	}

	timestamp := tai64n.Now()
	aeadTimestamp.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	device.indexTable.Delete(handshake.localIndex)
	var err error
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func BenchmarkCreateMessageInitiationFixedEphemeralPrecomputedAEAD(b *testing.B) {
	pair := genTestPair(b, false)
	if err := pair[0].dev.Down(); err != nil {
		b.Fatal(err)
	}
	if err := pair[1].dev.Down(); err != nil {
		b.Fatal(err)
	}
	peer := benchmarkFirstPeer(b, pair[0].dev)

	localEphemeral, err := newPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	ephemeralPub := localEphemeral.publicKey()
	ss, err := localEphemeral.sharedSecret(peer.handshake.remoteStatic)
	if err != nil {
		b.Fatal(err)
	}

	hashStart := InitialHash
	chainStart := InitialChainKey
	mixHash(&hashStart, &hashStart, peer.handshake.remoteStatic[:])
	mixKey(&chainStart, &chainStart, ephemeralPub[:])
	mixHash(&hashStart, &hashStart, ephemeralPub[:])

	var (
		chainAfterStatic = chainStart
		keyStatic        [chacha20poly1305.KeySize]byte
	)
	KDF2(&chainAfterStatic, &keyStatic, chainStart[:], ss[:])
	aeadStatic, _ := chacha20poly1305.New(keyStatic[:])

	var staticCiphertext [NoisePublicKeySize + poly1305.TagSize]byte
	aeadStatic.Seal(staticCiphertext[:0], ZeroNonce[:], peer.device.staticIdentity.publicKey[:], hashStart[:])

	hashAfterStatic := hashStart
	mixHash(&hashAfterStatic, &hashAfterStatic, staticCiphertext[:])

	var keyTimestamp [chacha20poly1305.KeySize]byte
	KDF2(&chainAfterStatic, &keyTimestamp, chainAfterStatic[:], peer.handshake.precomputedStaticStatic[:])
	aeadTimestamp, _ := chacha20poly1305.New(keyTimestamp[:])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := benchmarkCreateMessageInitiationFixedEphemeralPrecomputedAEAD(peer.device, peer, ephemeralPub, staticCiphertext, hashAfterStatic, aeadTimestamp); err != nil {
			b.Fatal(err)
		}
	}
}
