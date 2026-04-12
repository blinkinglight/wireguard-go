/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	state4 := s.ipv4.Load()
	if state4 == nil {
		return -1, ErrBindAlreadyOpen
	}
	sysconn, err := state4.conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	state6 := s.ipv6.Load()
	if state6 == nil {
		return -1, ErrBindAlreadyOpen
	}
	sysconn, err := state6.conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}
