//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// eBPF instruction encoding.
type bpfInsn struct {
	op   uint8
	regs uint8 // dst_reg:4 | src_reg:4
	off  int16
	imm  int32
}

func bpfReg(dst, src uint8) uint8 { return (src << 4) | dst }

// eBPF instruction constructors.

func bpfMovReg(dst, src uint8) bpfInsn {
	return bpfInsn{op: 0xbf, regs: bpfReg(dst, src)}
}

func bpfMovImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{op: 0xb7, regs: bpfReg(dst, 0), imm: imm}
}

func bpfAddImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{op: 0x07, regs: bpfReg(dst, 0), imm: imm}
}

func bpfLdxW(dst, src uint8, off int16) bpfInsn {
	return bpfInsn{op: 0x61, regs: bpfReg(dst, src), off: off}
}

func bpfLdxH(dst, src uint8, off int16) bpfInsn {
	return bpfInsn{op: 0x69, regs: bpfReg(dst, src), off: off}
}

func bpfLdxB(dst, src uint8, off int16) bpfInsn {
	return bpfInsn{op: 0x71, regs: bpfReg(dst, src), off: off}
}

func bpfJgtReg(a, b uint8, off int16) bpfInsn {
	return bpfInsn{op: 0x2d, regs: bpfReg(a, b), off: off}
}

func bpfJneImm(dst uint8, imm int32, off int16) bpfInsn {
	return bpfInsn{op: 0x55, regs: bpfReg(dst, 0), off: off, imm: imm}
}

func bpfJa(off int16) bpfInsn {
	return bpfInsn{op: 0x05, off: off}
}

// bpfLdMapFd loads a map file descriptor as a 64-bit immediate (2 instruction slots).
func bpfLdMapFd(dst uint8, fd int32) [2]bpfInsn {
	return [2]bpfInsn{
		{op: 0x18, regs: bpfReg(dst, 1), imm: fd}, // BPF_LD | BPF_DW | BPF_IMM, src=BPF_PSEUDO_MAP_FD
		{op: 0x00, imm: 0},                        // second half of 64-bit immediate
	}
}

func bpfCall(helperID int32) bpfInsn {
	return bpfInsn{op: 0x85, imm: helperID}
}

func bpfExit() bpfInsn {
	return bpfInsn{op: 0x95}
}

// buildXDPProgram creates a minimal XDP program that redirects UDP packets
// matching the given port to an AF_XDP socket via the XSKMAP.
// All other traffic passes through to the kernel stack.
func buildXDPProgram(port uint16, xsksMapFD int) []bpfInsn {
	// Port in network byte order (big-endian).
	nport := int32(uint16(port>>8) | uint16(port<<8))

	mapInsns := bpfLdMapFd(1, int32(xsksMapFD))

	// Instruction layout:
	//  0: save ctx
	//  1-2: load data/data_end
	//  3-5: check eth header fits
	//  6: load ethertype
	//  7: check IPv4
	//  8-14: IPv4 path (check IP+UDP, check port)
	//  15: jump to redirect
	//  16-23: IPv6 path
	//  24-29: redirect via bpf_redirect_map
	//  30-31: XDP_PASS
	return []bpfInsn{
		bpfMovReg(6, 1),     // 0: r6 = r1 (save xdp_md ctx)
		bpfLdxW(2, 6, 0),    // 1: r2 = xdp_md->data
		bpfLdxW(3, 6, 4),    // 2: r3 = xdp_md->data_end
		bpfMovReg(4, 2),     // 3: r4 = data
		bpfAddImm(4, 14),    // 4: r4 = data + ETH_HLEN
		bpfJgtReg(4, 3, 25), // 5: if r4 > data_end goto PASS (30)
		bpfLdxH(5, 2, 12),   // 6: r5 = eth->h_proto

		// IPv4 path
		bpfJneImm(5, 0x0008, 8), // 7: if ethertype != ETH_P_IP goto check_ipv6 (16)
		bpfMovReg(4, 2),         // 8: r4 = data
		bpfAddImm(4, 14+20+8),   // 9: r4 = data + eth + ip + udp
		bpfJgtReg(4, 3, 20),     // 10: if r4 > data_end goto PASS (30)
		bpfLdxB(5, 2, 14+9),     // 11: r5 = ip->protocol
		bpfJneImm(5, 17, 18),    // 12: if protocol != UDP goto PASS (30)
		bpfLdxH(5, 2, 14+20+2),  // 13: r5 = udp->dest
		bpfJneImm(5, nport, 16), // 14: if dport != PORT goto PASS (30)
		bpfJa(9),                // 15: goto REDIRECT (25)

		// IPv6 path
		bpfJneImm(5, 0xDD86, 14), // 16: if ethertype != ETH_P_IPV6 goto PASS (30)
		bpfMovReg(4, 2),          // 17: r4 = data
		bpfAddImm(4, 14+40+8),    // 18: r4 = data + eth + ipv6 + udp
		bpfJgtReg(4, 3, 11),      // 19: if r4 > data_end goto PASS (30)
		bpfLdxB(5, 2, 14+6),      // 20: r5 = ipv6->nexthdr
		bpfJneImm(5, 17, 9),      // 21: if nexthdr != UDP goto PASS (30)
		bpfLdxH(5, 2, 14+40+2),   // 22: r5 = udp->dest
		bpfJneImm(5, nport, 7),   // 23: if dport != PORT goto PASS (30)
		bpfJa(0),                 // 24: goto REDIRECT (25)

		// REDIRECT: bpf_redirect_map(&xsks_map, rx_queue_index, XDP_PASS)
		mapInsns[0],       // 25: r1 = &xsks_map (part 1)
		mapInsns[1],       // 26: (part 2 of LD_IMM64)
		bpfLdxW(2, 6, 16), // 27: r2 = xdp_md->rx_queue_index
		bpfMovImm(3, 2),   // 28: r3 = XDP_PASS (fallback action)
		bpfCall(51),       // 29: call bpf_redirect_map
		bpfExit(),         // 30: exit (returns redirect result)

		// PASS
		bpfMovImm(0, 2), // 31: r0 = XDP_PASS
		bpfExit(),       // 32: exit
	}
}

// marshalBPFInsns serializes eBPF instructions to bytes for the kernel.
func marshalBPFInsns(insns []bpfInsn) []byte {
	buf := make([]byte, len(insns)*8)
	for i, ins := range insns {
		off := i * 8
		buf[off] = ins.op
		buf[off+1] = ins.regs
		binary.LittleEndian.PutUint16(buf[off+2:], uint16(ins.off))
		binary.LittleEndian.PutUint32(buf[off+4:], uint32(ins.imm))
	}
	return buf
}

// BPF syscall command constants.
const (
	bpfCmdMapCreate      = 0
	bpfCmdProgLoad       = 5
	bpfHelperRedirectMap = 51
)

// bpfMapCreateAttr is the minimal attribute struct for BPF_MAP_CREATE.
type bpfMapCreateAttr struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
}

// bpfProgLoadAttr is the attribute struct for BPF_PROG_LOAD.
type bpfProgLoadAttr struct {
	progType           uint32
	insnCnt            uint32
	insns              uint64 // pointer to instructions
	license            uint64 // pointer to license string
	logLevel           uint32
	logSize            uint32
	logBuf             uint64
	kernVersion        uint32
	progFlags          uint32
	progName           [16]byte
	progIfIndex        uint32
	expectedAttachType uint32
}

func bpfSyscall(cmd int, attr unsafe.Pointer, size uintptr) (int, error) {
	r1, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	if errno != 0 {
		return 0, fmt.Errorf("bpf syscall cmd=%d: %w", cmd, errno)
	}
	return int(r1), nil
}

// createXSKMap creates a BPF_MAP_TYPE_XSKMAP for AF_XDP socket redirection.
func createXSKMap(maxEntries int) (int, error) {
	attr := bpfMapCreateAttr{
		mapType:    unix.BPF_MAP_TYPE_XSKMAP,
		keySize:    4,
		valueSize:  4,
		maxEntries: uint32(maxEntries),
	}
	return bpfSyscall(bpfCmdMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}

// bpfMapUpdateElem updates a single element in a BPF map.
func bpfMapUpdateElem(mapFD int, key, value unsafe.Pointer) error {
	type attr struct {
		mapFD uint32
		key   uint64
		value uint64
		flags uint64
	}
	a := attr{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}
	_, err := bpfSyscall(2 /* BPF_MAP_UPDATE_ELEM */, unsafe.Pointer(&a), unsafe.Sizeof(a))
	return err
}

// bpfMapDeleteElem deletes a single element from a BPF map.
func bpfMapDeleteElem(mapFD int, key unsafe.Pointer) error {
	type attr struct {
		mapFD uint32
		key   uint64
	}
	a := attr{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(key)),
	}
	_, err := bpfSyscall(3 /* BPF_MAP_DELETE_ELEM */, unsafe.Pointer(&a), unsafe.Sizeof(a))
	return err
}

// loadXDPProgram loads the XDP BPF program into the kernel.
func loadXDPProgram(insns []byte) (int, error) {
	license := []byte("GPL\x00")
	var name [16]byte
	copy(name[:], "wg_xdp_filter")

	attr := bpfProgLoadAttr{
		progType: unix.BPF_PROG_TYPE_XDP,
		insnCnt:  uint32(len(insns) / 8),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
		progName: name,
	}
	fd, err := bpfSyscall(bpfCmdProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		// Retry with log buffer for better error messages.
		logBuf := make([]byte, 65536)
		attr.logLevel = 1
		attr.logSize = uint32(len(logBuf))
		attr.logBuf = uint64(uintptr(unsafe.Pointer(&logBuf[0])))
		fd, err2 := bpfSyscall(bpfCmdProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if err2 != nil {
			// Find the end of the verifier log.
			logEnd := 0
			for i, b := range logBuf {
				if b == 0 {
					logEnd = i
					break
				}
			}
			if logEnd > 0 {
				return 0, fmt.Errorf("bpf prog load: %w; verifier: %s", err, string(logBuf[:logEnd]))
			}
			return 0, fmt.Errorf("bpf prog load: %w", err)
		}
		return fd, nil
	}
	return fd, nil
}

// attachXDP attaches an XDP program to a network interface via netlink.
func attachXDP(ifIndex int, progFD int, flags uint32) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	// Build RTM_SETLINK message with IFLA_XDP nested attribute.
	// Message layout:
	//   nlmsghdr (16 bytes)
	//   ifinfomsg (16 bytes)
	//   nlattr IFLA_XDP (nested):
	//     nlattr IFLA_XDP_FD (8 bytes)
	//     nlattr IFLA_XDP_FLAGS (8 bytes)

	const (
		nlmsgHdrLen  = 16
		ifInfoMsgLen = 16
		nlaHdrLen    = 4
		nlaAlignTo   = 4
	)

	nlaAlign := func(l int) int { return (l + nlaAlignTo - 1) &^ (nlaAlignTo - 1) }

	// Inner attributes
	fdAttrLen := nlaAlign(nlaHdrLen + 4)    // IFLA_XDP_FD: int32
	flagsAttrLen := nlaAlign(nlaHdrLen + 4) // IFLA_XDP_FLAGS: uint32
	innerLen := fdAttrLen + flagsAttrLen

	// Outer IFLA_XDP attribute (nested)
	outerLen := nlaAlign(nlaHdrLen + innerLen)

	msgLen := nlmsgHdrLen + ifInfoMsgLen + outerLen
	msg := make([]byte, msgLen)

	// nlmsghdr
	binary.LittleEndian.PutUint32(msg[0:], uint32(msgLen))                    // nlmsg_len
	binary.LittleEndian.PutUint16(msg[4:], unix.RTM_SETLINK)                  // nlmsg_type
	binary.LittleEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK) // nlmsg_flags
	binary.LittleEndian.PutUint32(msg[8:], 1)                                 // nlmsg_seq
	// nlmsg_pid = 0

	// ifinfomsg
	off := nlmsgHdrLen
	msg[off] = unix.AF_UNSPEC // ifi_family
	// ifi_type, ifi_index, ifi_flags, ifi_change
	binary.LittleEndian.PutUint32(msg[off+4:], uint32(ifIndex)) // ifi_index (offset 4 in ifinfomsg)

	// IFLA_XDP (nested)
	off = nlmsgHdrLen + ifInfoMsgLen
	binary.LittleEndian.PutUint16(msg[off:], uint16(nlaHdrLen+innerLen))        // nla_len
	binary.LittleEndian.PutUint16(msg[off+2:], unix.IFLA_XDP|unix.NLA_F_NESTED) // nla_type

	// IFLA_XDP_FD
	off += nlaHdrLen
	binary.LittleEndian.PutUint16(msg[off:], uint16(nlaHdrLen+4))
	binary.LittleEndian.PutUint16(msg[off+2:], unix.IFLA_XDP_FD)
	binary.LittleEndian.PutUint32(msg[off+4:], uint32(progFD))

	// IFLA_XDP_FLAGS
	off += fdAttrLen
	binary.LittleEndian.PutUint16(msg[off:], uint16(nlaHdrLen+4))
	binary.LittleEndian.PutUint16(msg[off+2:], unix.IFLA_XDP_FLAGS)
	binary.LittleEndian.PutUint32(msg[off+4:], flags)

	// Send
	if err := unix.Sendto(sock, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	// Receive ACK
	resp := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, resp, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}

	if n < nlmsgHdrLen+4 {
		return errors.New("netlink: response too short")
	}

	// Check for error in response
	nlmsgType := binary.LittleEndian.Uint16(resp[4:])
	if nlmsgType == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(resp[nlmsgHdrLen:]))
		if errno != 0 {
			return fmt.Errorf("netlink RTM_SETLINK XDP: %w", unix.Errno(-errno))
		}
	}

	return nil
}

// detachXDP removes the XDP program from a network interface.
func detachXDP(ifIndex int) error {
	return attachXDP(ifIndex, -1, 0)
}
