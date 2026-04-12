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
	mu    sync.RWMutex
	items map[uint32]IndexTableEntry
}

func randUint32() (uint32, error) {
	var integer [4]byte
	_, err := rand.Read(integer[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(integer[:]), err
}

func (table *IndexTable) Init() {
	table.items = make(map[uint32]IndexTableEntry)
}

func (table *IndexTable) Delete(index uint32) {
	table.mu.Lock()
	delete(table.items, index)
	table.mu.Unlock()
}

func (table *IndexTable) SwapIndexForKeypair(index uint32, keypair *Keypair) {
	table.mu.Lock()
	defer table.mu.Unlock()
	entry, ok := table.items[index]
	if !ok {
		return
	}
	table.items[index] = IndexTableEntry{
		peer:      entry.peer,
		keypair:   keypair,
		handshake: nil,
	}
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
		table.mu.Lock()
		_, loaded := table.items[index]
		if loaded {
			table.mu.Unlock()
			continue
		}
		table.items[index] = entry
		table.mu.Unlock()
		return index, nil
	}
}

func (table *IndexTable) Lookup(id uint32) IndexTableEntry {
	table.mu.RLock()
	entry, ok := table.items[id]
	table.mu.RUnlock()
	if !ok {
		return IndexTableEntry{}
	}
	return entry
}
