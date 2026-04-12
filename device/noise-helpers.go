/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"
	"sync"

	"github.com/cloudflare/circl/dh/x25519"
	"golang.org/x/crypto/blake2s"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	hmacBlake2s(sum, key, in0, nil)
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	hmacBlake2s(sum, key, in0, in1)
}

var blake2sHashPool = sync.Pool{New: func() any {
	h, _ := blake2s.New256(nil)
	return h
}}

var (
	kdfInput1 = [1]byte{0x1}
	kdfInput2 = [1]byte{0x2}
	kdfInput3 = [1]byte{0x3}
)

type blake2sHMACScratch struct {
	k0    [blake2s.BlockSize]byte
	ipad  [blake2s.BlockSize]byte
	opad  [blake2s.BlockSize]byte
	inner [blake2s.Size]byte
}

var blake2sHMACScratchPool = sync.Pool{New: func() any {
	return new(blake2sHMACScratch)
}}

func hmacBlake2s(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	s := blake2sHMACScratchPool.Get().(*blake2sHMACScratch)
	setZero(s.k0[:])

	if len(key) > blake2s.BlockSize {
		h := blake2sHashPool.Get().(hash.Hash)
		h.Reset()
		h.Write(key)
		h.Sum(s.inner[:0])
		blake2sHashPool.Put(h)
		copy(s.k0[:], s.inner[:])
		setZero(s.inner[:])
	} else {
		copy(s.k0[:], key)
	}

	for i := range s.k0 {
		s.ipad[i] = s.k0[i] ^ 0x36
		s.opad[i] = s.k0[i] ^ 0x5c
	}

	h := blake2sHashPool.Get().(hash.Hash)
	h.Reset()
	h.Write(s.ipad[:])
	h.Write(in0)
	if in1 != nil {
		h.Write(in1)
	}
	h.Sum(s.inner[:0])

	h.Reset()
	h.Write(s.opad[:])
	h.Write(s.inner[:])
	h.Sum(sum[:0])
	blake2sHashPool.Put(h)

	setZero(s.inner[:])
	setZero(s.k0[:])
	setZero(s.ipad[:])
	setZero(s.opad[:])
	blake2sHMACScratchPool.Put(s)
}

func hmacBlake2sKey32(sum *[blake2s.Size]byte, key *[blake2s.Size]byte, in0, in1 []byte) {
	var (
		k0       [blake2s.BlockSize]byte
		ipad     [blake2s.BlockSize]byte
		opad     [blake2s.BlockSize]byte
		innerBuf [blake2s.BlockSize + blake2s.Size + 1]byte
		outerBuf [blake2s.BlockSize + blake2s.Size]byte
	)

	copy(k0[:blake2s.Size], key[:])
	for i := range k0 {
		ipad[i] = k0[i] ^ 0x36
		opad[i] = k0[i] ^ 0x5c
	}

	n := copy(innerBuf[:], ipad[:])
	n += copy(innerBuf[n:], in0)
	if in1 != nil {
		n += copy(innerBuf[n:], in1)
	}
	inner := blake2s.Sum256(innerBuf[:n])

	n = copy(outerBuf[:], opad[:])
	n += copy(outerBuf[n:], inner[:])
	*sum = blake2s.Sum256(outerBuf[:n])

	setZero(k0[:])
	setZero(ipad[:])
	setZero(opad[:])
	setZero(innerBuf[:])
	setZero(outerBuf[:])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	if len(key) == blake2s.Size {
		var key32 [blake2s.Size]byte
		copy(key32[:], key)
		hmacBlake2sKey32(t0, &key32, input, nil)
		hmacBlake2sKey32(t0, t0, kdfInput1[:], nil)
		setZero(key32[:])
		return
	}

	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], kdfInput1[:])
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	if len(key) == blake2s.Size {
		var prk [blake2s.Size]byte
		var key32 [blake2s.Size]byte
		copy(key32[:], key)
		hmacBlake2sKey32(&prk, &key32, input, nil)
		hmacBlake2sKey32(t0, &prk, kdfInput1[:], nil)
		hmacBlake2sKey32(t1, &prk, t0[:], kdfInput2[:])
		setZero(prk[:])
		setZero(key32[:])
		return
	}

	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], kdfInput1[:])
	HMAC2(t1, prk[:], t0[:], kdfInput2[:])
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	if len(key) == blake2s.Size {
		var prk [blake2s.Size]byte
		var key32 [blake2s.Size]byte
		copy(key32[:], key)
		hmacBlake2sKey32(&prk, &key32, input, nil)
		hmacBlake2sKey32(t0, &prk, kdfInput1[:], nil)
		hmacBlake2sKey32(t1, &prk, t0[:], kdfInput2[:])
		hmacBlake2sKey32(t2, &prk, t1[:], kdfInput3[:])
		setZero(prk[:])
		setZero(key32[:])
		return
	}

	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], kdfInput1[:])
	HMAC2(t1, prk[:], t0[:], kdfInput2[:])
	HMAC2(t2, prk[:], t1[:], kdfInput3[:])
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	skKey := (*x25519.Key)(sk)
	pkKey := (*x25519.Key)(&pk)
	x25519.KeyGen(pkKey, skKey)
	return
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	skKey := (*x25519.Key)(sk)
	pkKey := (*x25519.Key)(&pk)
	ssKey := (*x25519.Key)(&ss)
	if ok := x25519.Shared(ssKey, skKey, pkKey); !ok {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}
