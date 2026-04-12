//go:build !linux && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import "golang.zx2c4.com/wireguard/conn"

func createBind() conn.Bind {
	return conn.NewDefaultBind()
}
