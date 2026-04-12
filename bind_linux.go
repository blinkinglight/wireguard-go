//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"os"
	"strconv"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	ENV_WG_XDP_IFACE    = "WG_XDP_IFACE"
	ENV_WG_XDP_ZEROCOPY = "WG_XDP_ZEROCOPY"
	ENV_WG_XDP_NATIVE   = "WG_XDP_NATIVE"
	ENV_WG_XDP_QUEUE    = "WG_XDP_QUEUE"
)

func createBind() conn.Bind {
	xdpIface := os.Getenv(ENV_WG_XDP_IFACE)
	if xdpIface == "" {
		return conn.NewDefaultBind()
	}

	opts := conn.XDPBindOpts{
		InterfaceName: xdpIface,
	}
	if os.Getenv(ENV_WG_XDP_ZEROCOPY) == "1" {
		opts.ZeroCopy = true
	}
	if os.Getenv(ENV_WG_XDP_NATIVE) == "1" {
		opts.NativeMode = true
	}
	if qStr := os.Getenv(ENV_WG_XDP_QUEUE); qStr != "" {
		if q, err := strconv.Atoi(qStr); err == nil {
			opts.QueueID = q
		}
	}

	return conn.NewXDPBind(opts)
}
