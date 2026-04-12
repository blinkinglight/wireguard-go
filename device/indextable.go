/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

type IndexTableEntry struct {
	peer      *Peer
	handshake *Handshake
	keypair   *Keypair
}

type IndexTable struct {
	smap sync.Map
}

func randUint32() (uint32, error) {
	var integer [4]byte
	_, err := rand.Read(integer[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(integer[:]), err
}

func (table *IndexTable) Init() {
	table.smap = sync.Map{}
}

func (table *IndexTable) Delete(index uint32) {
	table.smap.Delete(index)
}

func (table *IndexTable) SwapIndexForKeypair(index uint32, keypair *Keypair) {
	value, ok := table.smap.Load(index)
	if !ok {
		return
	}
	entry := value.(IndexTableEntry)
	table.smap.Store(index, IndexTableEntry{
		peer:      entry.peer,
		keypair:   keypair,
		handshake: nil,
	})
}

func (table *IndexTable) NewIndexForHandshake(peer *Peer, handshake *Handshake) (uint32, error) {
	for {
		// generate random index
		index, err := randUint32()
		if err != nil {
			return index, err
		}

		// check if index used, store if not (atomic)
		entry := IndexTableEntry{
			peer:      peer,
			handshake: handshake,
			keypair:   nil,
		}
		_, loaded := table.smap.LoadOrStore(index, entry)
		if loaded {
			continue
		}
		return index, nil
	}
}

func (table *IndexTable) Lookup(id uint32) IndexTableEntry {
	value, ok := table.smap.Load(id)
	if !ok {
		return IndexTableEntry{}
	}
	return value.(IndexTableEntry)
}
