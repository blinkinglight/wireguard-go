//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "golang.zx2c4.com/wireguard/conn"

const (
	QueueStagedSize            = conn.IdealBatchSize
	QueueOutboundSize          = 4096
	QueueInboundSize           = 4096
	QueueHandshakeSize         = 1024
	MaxSegmentSize             = (1 << 16) - 1 // largest possible UDP datagram
	PreallocatedBuffersPerPool = 0             // Disable and allow for infinite memory growth

	// decryptionBatchSize limits elements per inbound container, enabling
	// parallel decryption across multiple workers. Without this, a single
	// GRO-coalesced ReadBatch produces one large container processed by
	// one worker, leaving other decryption workers idle.
	decryptionBatchSize = 16
)
