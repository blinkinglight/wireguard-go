//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// XDPEndpoint is the Endpoint implementation for AF_XDP receive.
// On the receive path, dst is the remote peer's address (who sent us the packet).
// On the send path, dst is where we want to send (same address, set by SetEndpointFromPacket).
type XDPEndpoint struct {
	dst netip.AddrPort
	src []byte // sticky source (PKTINFO-style, from send socket)
}

var (
	_ Bind     = (*XDPBind)(nil)
	_ Endpoint = (*XDPEndpoint)(nil)
)

func (e *XDPEndpoint) ClearSrc()           { e.src = e.src[:0] }
func (e *XDPEndpoint) DstToString() string { return e.dst.String() }
func (e *XDPEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *XDPEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *XDPEndpoint) SrcToString() string { return "" }

func (e *XDPEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

// XDPBind implements conn.Bind using AF_XDP for zero-copy receive
// and regular UDP sockets for send (which handle routing, ARP, checksums).
// This hybrid approach provides the receive-path performance of AF_XDP
// without the complexity of raw packet construction for send.
type XDPBind struct {
	ifName     string
	ifIndex    int
	zeroCopy   bool
	nativeMode bool
	queueID    int

	mu   sync.Mutex
	port uint16

	// AF_XDP receive path.
	xsk      *xdpSocket
	progFD   int    // loaded XDP BPF program FD
	mapFD    int    // XSKMAP FD
	xdpFlags uint32 // flags used for attachXDP (needed for detach)

	// Regular UDP sockets for send path (same pattern as StdNetBind).
	ipv4Send atomic.Pointer[udpConnState]
	ipv6Send atomic.Pointer[udpConnState]

	// Pools.
	endpointPool    sync.Pool
	stdEndpointPool sync.Pool
	udpAddrPool     sync.Pool
	msgsPool        sync.Pool
}

// XDPBindOpts configures the AF_XDP bind.
type XDPBindOpts struct {
	// InterfaceName is the network interface to attach XDP to (e.g., "eth0").
	InterfaceName string
	// ZeroCopy enables AF_XDP zero-copy mode (requires driver support: mlx5, i40e, ice, etc).
	ZeroCopy bool
	// NativeMode uses XDP_FLAGS_DRV_MODE instead of SKB mode (requires driver XDP support).
	NativeMode bool
	// QueueID is the NIC RX queue to bind to (default: 0).
	QueueID int
}

// NewXDPBind creates a new AF_XDP-accelerated Bind.
// Requires CAP_BPF + CAP_NET_ADMIN or root.
func NewXDPBind(opts XDPBindOpts) Bind {
	return &XDPBind{
		ifName:     opts.InterfaceName,
		zeroCopy:   opts.ZeroCopy,
		nativeMode: opts.NativeMode,
		queueID:    opts.QueueID,
		progFD:     -1,
		mapFD:      -1,
		endpointPool: sync.Pool{
			New: func() any { return &XDPEndpoint{} },
		},
		stdEndpointPool: sync.Pool{
			New: func() any { return &StdNetEndpoint{} },
		},
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},
		msgsPool: sync.Pool{
			New: func() any {
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
}

func (b *XDPBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.xsk != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Resolve interface index.
	iface, err := net.InterfaceByName(b.ifName)
	if err != nil {
		return nil, 0, fmt.Errorf("interface %q: %w", b.ifName, err)
	}
	b.ifIndex = iface.Index

	// Open regular UDP sockets for the send path.
	// This also determines the actual port (if uport == 0).
	var v4conn, v6conn *net.UDPConn
	var v4pc *ipv4.PacketConn
	var v6pc *ipv6.PacketConn
	var tries int

again:
	port := int(uport)
	v4conn, port, err = listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, fmt.Errorf("udp4 listen: %w", err)
	}

	v6conn, port, err = listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		if v4conn != nil {
			v4conn.Close()
		}
		return nil, 0, fmt.Errorf("udp6 listen: %w", err)
	}

	b.port = uint16(port)

	// Configure sockets with GSO/GRO.
	var v4rxOffload, v6rxOffload bool
	if v4conn != nil {
		txOffload, rxOffload := supportsUDPOffload(v4conn)
		v4rxOffload = rxOffload
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
		}
		b.ipv4Send.Store(&udpConnState{
			conn:      v4conn,
			pc:        v4pc,
			txOffload: txOffload,
		})
	}
	if v6conn != nil {
		txOffload, rxOffload := supportsUDPOffload(v6conn)
		v6rxOffload = rxOffload
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
		}
		b.ipv6Send.Store(&udpConnState{
			conn:      v6conn,
			pc:        v6pc,
			txOffload: txOffload,
		})
	}

	// Set up AF_XDP receive path.
	// 1. Create XSKMAP.
	b.mapFD, err = createXSKMap(64) // support up to 64 RX queues
	if err != nil {
		b.closeSendSockets()
		return nil, 0, fmt.Errorf("create XSKMAP: %w", err)
	}

	// 2. Build and load XDP program.
	insns := buildXDPProgram(b.port, b.mapFD)
	insnBytes := marshalBPFInsns(insns)
	b.progFD, err = loadXDPProgram(insnBytes)
	if err != nil {
		b.closeSendSockets()
		unix.Close(b.mapFD)
		b.mapFD = -1
		return nil, 0, fmt.Errorf("load XDP program: %w", err)
	}

	// 3. Create AF_XDP socket.
	b.xsk, err = newXDPSocket(b.ifIndex, b.queueID, b.zeroCopy)
	if err != nil {
		b.closeSendSockets()
		unix.Close(b.progFD)
		unix.Close(b.mapFD)
		b.progFD = -1
		b.mapFD = -1
		return nil, 0, fmt.Errorf("AF_XDP socket: %w", err)
	}

	// 4. Register AF_XDP socket in XSKMAP at key=queueID.
	key := uint32(b.queueID)
	val := uint32(b.xsk.fd)
	if err := bpfMapUpdateElem(b.mapFD, unsafe.Pointer(&key), unsafe.Pointer(&val)); err != nil {
		b.xsk.close()
		b.xsk = nil
		b.closeSendSockets()
		unix.Close(b.progFD)
		unix.Close(b.mapFD)
		b.progFD = -1
		b.mapFD = -1
		return nil, 0, fmt.Errorf("XSKMAP update: %w", err)
	}

	// 5. Attach XDP program to interface.
	xdpFlags := uint32(unix.XDP_FLAGS_SKB_MODE)
	if b.nativeMode {
		xdpFlags = unix.XDP_FLAGS_DRV_MODE
	}
	if err := attachXDP(b.ifIndex, b.progFD, xdpFlags); err != nil {
		b.xsk.close()
		b.xsk = nil
		b.closeSendSockets()
		unix.Close(b.progFD)
		unix.Close(b.mapFD)
		b.progFD = -1
		b.mapFD = -1
		return nil, 0, fmt.Errorf("attach XDP to %s: %w", b.ifName, err)
	}
	b.xdpFlags = xdpFlags

	// Return receive functions: AF_XDP primary + UDP fallback.
	// Packets successfully redirected by XDP go to receiveXDP.
	// Packets that bypass XDP (wrong queue, redirect failure) go to
	// the regular UDP sockets and are caught by the fallback receivers.
	fns := []ReceiveFunc{b.receiveXDP}
	if v4pc != nil {
		fns = append(fns, b.makeReceiveUDP(v4pc, v4conn, v4rxOffload))
	}
	if v6pc != nil {
		fns = append(fns, b.makeReceiveUDP(v6pc, v6conn, v6rxOffload))
	}
	return fns, b.port, nil
}

func (b *XDPBind) receiveXDP(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
	if b.xsk == nil {
		return 0, net.ErrClosed
	}
	n, err := b.xsk.receive(bufs, sizes, eps, &b.endpointPool)
	if err != nil {
		if errors.Is(err, ErrXDPClosed) {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	return n, nil
}

func (b *XDPBind) makeReceiveUDP(br batchReader, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		return b.receiveUDP(br, conn, rxOffload, bufs, sizes, eps)
	}
}

func (b *XDPBind) receiveUDP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (int, error) {
	msgsP := b.msgsPool.Get().(*[]ipv6.Message)
	msgs := *msgsP
	for i := range bufs {
		msgs[i].Buffers[0] = bufs[i]
		msgs[i].OOB = msgs[i].OOB[:cap(msgs[i].OOB)]
	}
	var numMsgs int
	var err error
	if rxOffload {
		readAt := len(msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
		numMsgs, err = br.ReadBatch(msgs[readAt:], 0)
		if err != nil {
			b.putMessages(msgsP, 0)
			return 0, err
		}
		numMsgs, err = splitCoalescedMessages(msgs, readAt, getGSOSize)
		if err != nil {
			b.putMessages(msgsP, 0)
			return 0, err
		}
	} else {
		numMsgs, err = br.ReadBatch(msgs, 0)
		if err != nil {
			b.putMessages(msgsP, 0)
			return 0, err
		}
	}
	for i := 0; i < numMsgs; i++ {
		msg := &msgs[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := b.stdEndpointPool.Get().(*StdNetEndpoint)
		ep.AddrPort = addrPort
		ep.src = ep.src[:0]
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[i] = ep
	}
	b.putMessages(msgsP, numMsgs)
	return numMsgs, nil
}

func (b *XDPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Detach XDP program from interface using the SAME flags as attach.
	//    With flags=0, mlx5 auto-detects DRV mode and misses the SKB program.
	if b.ifIndex > 0 && b.progFD >= 0 {
		attachXDP(b.ifIndex, -1, b.xdpFlags)
	}

	// 2. Remove AF_XDP socket from XSKMAP to release the map's reference.
	if b.mapFD >= 0 {
		key := uint32(b.queueID)
		bpfMapDeleteElem(b.mapFD, unsafe.Pointer(&key))
	}

	// 3. Close BPF program and map BEFORE the AF_XDP socket.
	//    The prog holds an internal ref to the map, and the map entry
	//    holds a ref to the socket. Closing in this order ensures the
	//    kernel fully releases the socket from the device's XDP table.
	if b.progFD >= 0 {
		unix.Close(b.progFD)
		b.progFD = -1
	}
	if b.mapFD >= 0 {
		unix.Close(b.mapFD)
		b.mapFD = -1
	}

	// 4. Close AF_XDP socket (fd close unblocks the receive goroutine).
	if b.xsk != nil {
		b.xsk.close()
		b.xsk = nil
	}

	// 5. Close send sockets.
	b.closeSendSockets()

	return nil
}

func (b *XDPBind) closeSendSockets() {
	if state := b.ipv4Send.Load(); state != nil {
		state.conn.Close()
		b.ipv4Send.Store(nil)
	}
	if state := b.ipv6Send.Load(); state != nil {
		state.conn.Close()
		b.ipv6Send.Store(nil)
	}
}

// Send uses regular UDP sockets with GSO (same approach as StdNetBind).
func (b *XDPBind) Send(bufs [][]byte, ep Endpoint) error {
	var state *udpConnState
	xep, ok := ep.(*XDPEndpoint)
	if !ok {
		// Also accept StdNetEndpoint for compatibility.
		sep, ok := ep.(*StdNetEndpoint)
		if !ok {
			return ErrWrongEndpointType
		}
		if sep.DstIP().Is6() {
			state = b.ipv6Send.Load()
		} else {
			state = b.ipv4Send.Load()
		}
		if state == nil {
			return net.ErrClosed
		}
		return b.sendViaUDP(state, bufs, sep.AddrPort, nil)
	}

	if xep.dst.Addr().Is6() {
		state = b.ipv6Send.Load()
	} else {
		state = b.ipv4Send.Load()
	}
	if state == nil {
		return net.ErrClosed
	}

	return b.sendViaUDP(state, bufs, xep.dst, xep.src)
}

func (b *XDPBind) sendViaUDP(state *udpConnState, bufs [][]byte, dst netip.AddrPort, src []byte) error {
	msgsP := b.msgsPool.Get().(*[]ipv6.Message)
	msgs := *msgsP

	addrP := b.udpAddrPool.Get().(*net.UDPAddr)
	ua := addrP
	ua.IP = ua.IP[:cap(ua.IP)]
	if dst.Addr().Is4() {
		a4 := dst.Addr().As4()
		copy(ua.IP, a4[:])
		ua.IP = ua.IP[:4]
	} else {
		a16 := dst.Addr().As16()
		copy(ua.IP, a16[:])
		ua.IP = ua.IP[:16]
	}
	ua.Port = int(dst.Port())

	// Build messages without GSO coalescing (simple path).
	// GSO coalescing requires StdNetEndpoint; for XDP we send directly.
	n := 0
	for _, buf := range bufs {
		msgs[n].Addr = ua
		msgs[n].Buffers[0] = buf
		msgs[n].OOB = msgs[n].OOB[:0]
		n++
	}

	err := b.send(state, msgs[:n])
	b.udpAddrPool.Put(addrP)
	b.putMessages(msgsP, n)
	return err
}

func (b *XDPBind) send(state *udpConnState, msgs []ipv6.Message) error {
	var err error
	if state.pc != nil {
		for len(msgs) > 0 {
			var n int
			n, err = state.pc.WriteBatch(msgs, 0)
			if err != nil || n == 0 {
				break
			}
			msgs = msgs[n:]
		}
	} else {
		for _, msg := range msgs {
			_, _, err = state.conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
	}
	return err
}

func (b *XDPBind) putMessages(msgs *[]ipv6.Message, n int) {
	for i := 0; i < n; i++ {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i].Buffers[0] = nil
	}
	b.msgsPool.Put(msgs)
}

func (b *XDPBind) SetMark(mark uint32) error {
	var operr error
	if fwmarkIoctl == 0 {
		return nil
	}
	if state := b.ipv4Send.Load(); state != nil {
		fd, err := state.conn.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if state := b.ipv6Send.Load(); state != nil {
		fd, err := state.conn.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (*XDPBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &XDPEndpoint{dst: e}, nil
}

func (*XDPBind) BatchSize() int {
	return IdealBatchSize
}
