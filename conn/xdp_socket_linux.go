//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AF_XDP constants.
const (
	xdpFrameSize     = 4096 // bytes per UMEM frame
	xdpNumFrames     = 4096 // total frames (16MB UMEM)
	xdpRxRingSize    = 2048 // RX ring entries
	xdpFillRingSize  = 4096 // Fill ring entries (should be >= RX)
	xdpCompRingSize  = 2048 // Completion ring entries
	xdpBatchSize     = 64   // max packets per poll
	xdpPollTimeoutMs = 100  // poll timeout in milliseconds

	// Ethernet/IP/UDP header sizes.
	ethHeaderLen  = 14
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	udpHeaderLen  = 8
)

// xdpSocket wraps an AF_XDP socket with UMEM and ring buffers.
type xdpSocket struct {
	fd   int
	umem []byte // mmap'd UMEM area

	// Rings — mmap'd memory and typed descriptor slices.
	fillRing     []byte // mmap'd fill ring memory
	fillDescs    []uint64
	fillProducer *uint32
	fillConsumer *uint32
	fillMask     uint32

	rxRing     []byte // mmap'd RX ring memory
	rxDescs    []unix.XDPDesc
	rxProducer *uint32
	rxConsumer *uint32
	rxMask     uint32

	compRing []byte // mmap'd completion ring (required by kernel, unused in hybrid)

	mu         sync.Mutex
	freeFrames []uint64 // pool of available frame addresses
	closed     atomic.Bool
}

// newXDPSocket creates and configures an AF_XDP socket bound to the given
// interface and queue. Uses XDP_COPY mode for broad compatibility.
func newXDPSocket(ifIndex, queueID int, zeroCopy bool) (*xdpSocket, error) {
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_XDP socket: %w", err)
	}

	x := &xdpSocket{fd: fd}
	success := false
	defer func() {
		if !success {
			x.close()
		}
	}()

	// Allocate UMEM.
	umemSize := xdpFrameSize * xdpNumFrames
	x.umem, err = unix.Mmap(-1, 0, umemSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap UMEM: %w", err)
	}

	// Register UMEM.
	umemReg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&x.umem[0]))),
		Len:      uint64(umemSize),
		Size:     xdpFrameSize,
		Headroom: 0,
	}
	if err := setsockoptXDPUmemReg(fd, &umemReg); err != nil {
		return nil, fmt.Errorf("XDP_UMEM_REG: %w", err)
	}

	// Set ring sizes.
	if err := setsockoptUint32(fd, unix.SOL_XDP, unix.XDP_RX_RING, xdpRxRingSize); err != nil {
		return nil, fmt.Errorf("XDP_RX_RING: %w", err)
	}
	if err := setsockoptUint32(fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, xdpFillRingSize); err != nil {
		return nil, fmt.Errorf("XDP_UMEM_FILL_RING: %w", err)
	}
	if err := setsockoptUint32(fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, xdpCompRingSize); err != nil {
		return nil, fmt.Errorf("XDP_UMEM_COMPLETION_RING: %w", err)
	}

	// Get mmap offsets.
	offsets, err := getsockoptXDPMmapOffsets(fd)
	if err != nil {
		return nil, fmt.Errorf("XDP_MMAP_OFFSETS: %w", err)
	}

	// mmap RX ring.
	rxMapSize := offsets.Rx.Desc + uint64(xdpRxRingSize)*uint64(unsafe.Sizeof(unix.XDPDesc{}))
	x.rxRing, err = unix.Mmap(fd, int64(unix.XDP_PGOFF_RX_RING), int(rxMapSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap RX ring: %w", err)
	}
	x.rxProducer = (*uint32)(unsafe.Pointer(&x.rxRing[offsets.Rx.Producer]))
	x.rxConsumer = (*uint32)(unsafe.Pointer(&x.rxRing[offsets.Rx.Consumer]))
	x.rxDescs = unsafe.Slice(
		(*unix.XDPDesc)(unsafe.Pointer(&x.rxRing[offsets.Rx.Desc])),
		xdpRxRingSize,
	)
	x.rxMask = xdpRxRingSize - 1

	// mmap Fill ring.
	fillMapSize := offsets.Fr.Desc + uint64(xdpFillRingSize)*8
	x.fillRing, err = unix.Mmap(fd, int64(unix.XDP_UMEM_PGOFF_FILL_RING), int(fillMapSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap Fill ring: %w", err)
	}
	x.fillProducer = (*uint32)(unsafe.Pointer(&x.fillRing[offsets.Fr.Producer]))
	x.fillConsumer = (*uint32)(unsafe.Pointer(&x.fillRing[offsets.Fr.Consumer]))
	x.fillDescs = unsafe.Slice(
		(*uint64)(unsafe.Pointer(&x.fillRing[offsets.Fr.Desc])),
		xdpFillRingSize,
	)
	x.fillMask = xdpFillRingSize - 1

	// mmap Completion ring (required by kernel even if unused).
	compMapSize := offsets.Cr.Desc + uint64(xdpCompRingSize)*8
	x.compRing, err = unix.Mmap(fd, int64(unix.XDP_UMEM_PGOFF_COMPLETION_RING), int(compMapSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap Comp ring: %w", err)
	}

	// Initialize free frame list and pre-fill the fill ring.
	x.freeFrames = make([]uint64, xdpNumFrames)
	for i := range x.freeFrames {
		x.freeFrames[i] = uint64(i) * xdpFrameSize
	}
	x.refillFillRing()

	// Bind to interface and queue.
	bindFlags := uint16(unix.XDP_COPY)
	if zeroCopy {
		bindFlags = unix.XDP_ZEROCOPY
	}
	sa := &unix.SockaddrXDP{
		Flags:   bindFlags,
		Ifindex: uint32(ifIndex),
		QueueID: uint32(queueID),
	}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("bind AF_XDP ifindex=%d queue=%d: %w", ifIndex, queueID, err)
	}

	// Enable busy-polling for lower latency on supported kernels.
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL, 50)         // 50µs busy-poll
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PREFER_BUSY_POLL, 1)   // prefer busy-poll
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL_BUDGET, 128) // packets per cycle

	success = true
	return x, nil
}

// refillFillRing moves free frames into the fill ring so the kernel
// has buffers available for receiving packets.
func (x *xdpSocket) refillFillRing() {
	prod := atomic.LoadUint32(x.fillProducer)
	cons := atomic.LoadUint32(x.fillConsumer)
	free := xdpFillRingSize - (prod - cons)

	n := uint32(len(x.freeFrames))
	if n > free {
		n = free
	}
	if n == 0 {
		return
	}

	for i := uint32(0); i < n; i++ {
		idx := (prod + i) & x.fillMask
		x.fillDescs[idx] = x.freeFrames[len(x.freeFrames)-1]
		x.freeFrames = x.freeFrames[:len(x.freeFrames)-1]
	}

	atomic.StoreUint32(x.fillProducer, prod+n)
}

// receive polls the RX ring for incoming packets, parses Ethernet/IP/UDP
// headers, and copies the UDP payload into the provided buffers.
// The epPool provides recycled XDPEndpoint objects to avoid per-packet allocation.
func (x *xdpSocket) receive(bufs [][]byte, sizes []int, eps []Endpoint, epPool *sync.Pool) (int, error) {
	if x.closed.Load() {
		return 0, fmt.Errorf("xdp socket closed: %w", ErrXDPClosed)
	}

	fds := [1]unix.PollFd{{Fd: int32(x.fd), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(fds[:], xdpPollTimeoutMs)
		if err != nil {
			if x.closed.Load() {
				return 0, fmt.Errorf("xdp socket closed: %w", ErrXDPClosed)
			}
			if err == unix.EINTR {
				continue
			}
			return 0, err
		}
		break
	}

	// All mmap'd ring access must be under the mutex so that close()
	// can safely munmap after acquiring it.
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.closed.Load() {
		return 0, fmt.Errorf("xdp socket closed: %w", ErrXDPClosed)
	}

	cons := atomic.LoadUint32(x.rxConsumer)
	prod := atomic.LoadUint32(x.rxProducer)
	avail := prod - cons
	if avail == 0 {
		return 0, nil
	}

	n := int(avail)
	if n > len(bufs) {
		n = len(bufs)
	}
	if n > xdpBatchSize {
		n = xdpBatchSize
	}

	// Batch free frame addresses on the stack to avoid per-iteration append.
	var freed [xdpBatchSize]uint64
	count := 0
	for i := 0; i < n; i++ {
		idx := (cons + uint32(i)) & x.rxMask
		desc := &x.rxDescs[idx]

		frame := x.umem[desc.Addr : desc.Addr+uint64(desc.Len)]
		payload, srcAddr, ok := parseUDPPacket(frame)
		if ok && len(payload) > 0 {
			sz := copy(bufs[count], payload)
			sizes[count] = sz
			ep := epPool.Get().(*XDPEndpoint)
			ep.dst = srcAddr
			ep.src = ep.src[:0]
			eps[count] = ep
			count++
		}

		freed[i] = desc.Addr
	}

	x.freeFrames = append(x.freeFrames, freed[:n]...)
	atomic.StoreUint32(x.rxConsumer, cons+uint32(n))
	x.refillFillRing()

	if count == 0 {
		return 0, nil
	}
	return count, nil
}

// close cleans up the AF_XDP socket and all mmap'd memory.
// It first closes the fd to unblock any Poll() call in receive(),
// then acquires the mutex to ensure no goroutine is accessing
// mmap'd ring memory before munmapping.
func (x *xdpSocket) close() error {
	x.closed.Store(true)
	// Close fd first to unblock Poll() in receive().
	if x.fd > 0 {
		unix.Close(x.fd)
		x.fd = -1
	}
	// Wait for any in-progress receive() to finish ring access.
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.rxRing != nil {
		unix.Munmap(x.rxRing)
		x.rxRing = nil
	}
	if x.fillRing != nil {
		unix.Munmap(x.fillRing)
		x.fillRing = nil
	}
	if x.compRing != nil {
		unix.Munmap(x.compRing)
		x.compRing = nil
	}
	if x.umem != nil {
		unix.Munmap(x.umem)
		x.umem = nil
	}
	return nil
}

// parseUDPPacket extracts the UDP payload and source address from a raw
// Ethernet frame. Returns (payload, srcAddrPort, ok).
func parseUDPPacket(frame []byte) (payload []byte, src netip.AddrPort, ok bool) {
	if len(frame) < ethHeaderLen {
		return nil, netip.AddrPort{}, false
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	ipPayload := frame[ethHeaderLen:]

	switch etherType {
	case 0x0800: // IPv4
		if len(ipPayload) < ipv4HeaderLen {
			return nil, netip.AddrPort{}, false
		}
		ihl := int(ipPayload[0]&0x0f) * 4
		if ihl < ipv4HeaderLen || len(ipPayload) < ihl {
			return nil, netip.AddrPort{}, false
		}
		if ipPayload[9] != 17 { // UDP
			return nil, netip.AddrPort{}, false
		}
		udpData := ipPayload[ihl:]
		if len(udpData) < udpHeaderLen {
			return nil, netip.AddrPort{}, false
		}
		srcPort := binary.BigEndian.Uint16(udpData[0:2])
		srcIP := netip.AddrFrom4([4]byte(ipPayload[12:16]))
		return udpData[udpHeaderLen:], netip.AddrPortFrom(srcIP, srcPort), true

	case 0x86DD: // IPv6
		if len(ipPayload) < ipv6HeaderLen {
			return nil, netip.AddrPort{}, false
		}
		if ipPayload[6] != 17 { // UDP (no extension header chaining)
			return nil, netip.AddrPort{}, false
		}
		udpData := ipPayload[ipv6HeaderLen:]
		if len(udpData) < udpHeaderLen {
			return nil, netip.AddrPort{}, false
		}
		srcPort := binary.BigEndian.Uint16(udpData[0:2])
		srcIP := netip.AddrFrom16([16]byte(ipPayload[8:24]))
		return udpData[udpHeaderLen:], netip.AddrPortFrom(srcIP, srcPort), true
	}

	return nil, netip.AddrPort{}, false
}

// Socket option helpers.

func setsockoptXDPUmemReg(fd int, reg *unix.XDPUmemReg) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(reg)), unsafe.Sizeof(*reg), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func setsockoptUint32(fd int, level, name int, value uint32) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(name),
		uintptr(unsafe.Pointer(&value)), 4, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func getsockoptXDPMmapOffsets(fd int) (*unix.XDPMmapOffsets, error) {
	var offsets unix.XDPMmapOffsets
	optlen := uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)), uintptr(unsafe.Pointer(&optlen)), 0)
	if errno != 0 {
		return nil, errno
	}
	return &offsets, nil
}

// ErrXDPClosed is returned by receive after Close.
var ErrXDPClosed = fmt.Errorf("AF_XDP socket closed")
