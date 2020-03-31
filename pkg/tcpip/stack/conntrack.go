// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"encoding/binary"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// Connection tracking is used to track and manipulate packets for NAT rules.
// The connection is created for a packet if it does not exist. Every connection
// contains two tuples (original and reply). The tuples are manipulated if there
// is a matching NAT rule. The packet is modified by looking at the tuples in the
// Prerouting and Output hooks.

// Direction of the tuple.
type ctDirection int

const (
	ctDirOriginal ctDirection = iota
	ctDirReply
	ctDirMax
)

// Status of connection.
// TODO(gvisor.dev/issue/170): Add other states of connection.
type ctStatus int

const (
	ctNew ctStatus = iota
	ctEstablished
)

// Manipulation type for the connection.
type manipType int

const (
	manipDstPrerouting manipType = iota
	manipDstOutput
)

// connTrackManip is the manipulatable part of the tuple.
type connTrackManip struct {
	// addr is source address of the tuple.
	addr tcpip.Address

	// port is source port of the tuple.
	port uint16

	// protocol is network layer protocol.
	protocol tcpip.NetworkProtocolNumber
}

// connTrackNonManip is the non-manipulatable part of the tuple.
type connTrackNonManip struct {
	// addr is destination address of the tuple.
	addr tcpip.Address

	// direction is direction(original or reply) of the tuple.
	direction ctDirection

	// port is destination port of the tuple.
	port uint16

	// protocol is transport layer protocol.
	protocol tcpip.TransportProtocolNumber
}

// connTrackTuple represents the tuple which is created from the
// packet.
type connTrackTuple struct {
	// dst is non-manipulatable part of the tuple.
	dst connTrackNonManip

	// src is manipulatable part of the tuple.
	src connTrackManip
}

// connTrackTupleHolder is the container of tuple and connection.
type ConnTrackTupleHolder struct {
	// conn is pointer to the connection tracking entry.
	conn *connTrack

	// tuple is original or reply tuple.
	tuple connTrackTuple
}

// connTrack is the connection.
type connTrack struct {
	// tupleHolder contains two tuples one for each direction.`
	tupleHolder [ctDirMax]ConnTrackTupleHolder

	// status indicates connection is new or established.
	status ctStatus

	// timeout indicates the time connection should be active.
	timeout time.Time

	// manip indicates if the packet should be manipulated.
	manip manipType

	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection.
	tcb *tcpconntrack.TCB

	// tcbHook indicates if the packet is inbound or outbound to
	// update the state of tcb.
	tcbHook Hook
}

type ConnTrackTable struct {
	// connTrackTable maintains a map of tuples needed for connection tracking
	// for iptables NAT rules. The key for the map is an integer calculated
	// using seed, source address, destination address, source port and
	// destination port.
	CtMap map[uint32]ConnTrackTupleHolder

	// seed is a one-time random value initialized at stack startup
	// and is used in calculation of hash key for connection tracking
	// table.
	Seed uint32

	// connMu protects connTrackTable.
	connMu sync.RWMutex
}

// parseHeaders sets headers in the packet.
func parseHeaders(pkt PacketBuffer) PacketBuffer {
	newPkt := pkt.Clone()

	// Set network header.
	headerView := newPkt.Data.First()
	netHeader := header.IPv4(headerView)
	newPkt.NetworkHeader = headerView[:header.IPv4MinimumSize]

	hlen := int(netHeader.HeaderLength())
	tlen := int(netHeader.TotalLength())
	newPkt.Data.TrimFront(hlen)
	newPkt.Data.CapLength(tlen - hlen)

	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	protocol := netHeader.TransportProtocol()
	if protocol != header.TCPProtocolNumber {
		return newPkt
	}

	// Set transport header.
	if newPkt.TransportHeader == nil {
		if len(pkt.Data.First()) < header.TCPMinimumSize {
			return newPkt
		}
		newPkt.TransportHeader = buffer.View(header.TCP(newPkt.Data.First()))
	}

	return newPkt
}

// packetToTuple converts packet to tuple.
func packetToTuple(pkt PacketBuffer, hook Hook) (connTrackTuple, *tcpip.Error) {
	var tuple connTrackTuple

	netHeader := header.IPv4(pkt.NetworkHeader)
	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return tuple, tcpip.ErrUnknownProtocol
	}
	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return tuple, tcpip.ErrUnknownProtocol
	}

	tuple.src.addr = netHeader.SourceAddress()
	tuple.src.port = tcpHeader.SourcePort()
	tuple.src.protocol = header.IPv4ProtocolNumber

	tuple.dst.addr = netHeader.DestinationAddress()
	tuple.dst.port = tcpHeader.DestinationPort()

	// TODO(gvisor.dev/issue/170): Need to support other transport protocols.
	tuple.dst.protocol = header.TCPProtocolNumber
	tuple.dst.direction = ctDirOriginal

	return tuple, nil
}

// getConnTrackWithHash returns connection if exists and sets status of connection
// to established if the tuple is reply of an existing connection.
func (ct *ConnTrackTable) getConnTrackWithHash(hash uint32) *connTrack {
	connTrackTable := ct.CtMap
	tupleHolder, ok := connTrackTable[hash]
	if !ok {
		return nil
	}
	if tupleHolder.conn == nil {
		panic("tupleHolder has null connection tracking entry")
	}

	// If this is the reply of new connection, set the connection
	// status as ESTABLISHED.
	conn := tupleHolder.conn
	if conn.status == ctNew && tupleHolder.tuple.dst.direction == ctDirReply {
		conn.status = ctEstablished
	}
	return conn
}

// getInvertTuple creates inverted tuple for the given tuple.
func getInvertTuple(tuple connTrackTuple) connTrackTuple {
	var invertTuple connTrackTuple
	invertTuple.src.addr = tuple.dst.addr
	invertTuple.src.port = tuple.dst.port
	invertTuple.src.protocol = header.IPv4ProtocolNumber
	invertTuple.dst.addr = tuple.src.addr
	invertTuple.dst.port = tuple.src.port
	invertTuple.dst.protocol = tuple.dst.protocol
	invertTuple.dst.direction = ctDirReply
	return invertTuple
}

// makeNewConn creates new connection.
func makeNewConn(tuple, invertTuple connTrackTuple, pkt PacketBuffer) connTrack {
	var conn connTrack
	conn.status = ctNew
	conn.tupleHolder[ctDirOriginal].tuple = tuple
	conn.tupleHolder[ctDirOriginal].conn = &conn
	conn.tupleHolder[ctDirReply].tuple = invertTuple
	conn.tupleHolder[ctDirReply].conn = &conn

	return conn
}

// getTupleHash returns hash of the tuple. The fields used for
// generating hash are seed (generated once for stack), source address,
// destination address, source port and destination ports.
func (ct *ConnTrackTable) getTupleHash(tuple connTrackTuple) uint32 {
	h := jenkins.Sum32(ct.Seed)
	h.Write([]byte(tuple.src.addr))
	h.Write([]byte(tuple.dst.addr))
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, tuple.src.port)
	h.Write([]byte(portBuf))
	binary.LittleEndian.PutUint16(portBuf, tuple.dst.port)
	h.Write([]byte(portBuf))

	return h.Sum32()
}

// GetConnTrack gets connection for the packet.
func (ct *ConnTrackTable) GetConnTrack(pkt PacketBuffer, hook Hook) *connTrack {
	// If the hook is prerouting, headers will not be set.
	// TODO(gvisor.dev/issue/170): Change this after parsing headers code
	// is added.
	if hook == Prerouting {
		pkt = parseHeaders(pkt)
	}

	// Convert the packet to a tuple.
	tuple, err := packetToTuple(pkt, hook)
	if err != nil {
		return nil
	}

	hash := ct.getTupleHash(tuple)
	return ct.getConnTrackWithHash(hash)
}

// SetConnTrack sets connection tracking pointer to packet.
// TODO(gvisor.dev/issue/170): Only TCP packets are supported. Need to support other
// transport protocols.
func (ct *ConnTrackTable) SetConnTrack(pkt PacketBuffer, hook Hook) *connTrack {
	conn := ct.GetConnTrack(pkt, hook)

	// If connection does not exist for the hash, create a new
	// connection.
	if conn == nil {
		// If the hook is prerouting, headers will not be set.
		// TODO(gvisor.dev/issue/170): Change this after parsing headers code
		// is added.
		if hook == Prerouting {
			pkt = parseHeaders(pkt)
		}
		tuple, err := packetToTuple(pkt, hook)
		if err != nil {
			return nil
		}

		hash := ct.getTupleHash(tuple)
		invertTuple := getInvertTuple(tuple)
		replyHash := ct.getTupleHash(invertTuple)
		newConn := makeNewConn(tuple, invertTuple, pkt)
		conn = &newConn

		ct.connMu.Lock()
		defer ct.connMu.Unlock()

		// Add tupleHolders to the map.
		// TODO(gvisor.dev/issue/170): Need to support collisions using linked list.
		ct.CtMap[hash] = conn.tupleHolder[ctDirOriginal]
		ct.CtMap[replyHash] = conn.tupleHolder[ctDirReply]
	}
	return conn
}

// SetNatInfo wil manipulate the tuples according to iptables NAT rules.
func (ct *ConnTrackTable) SetNatInfo(pkt PacketBuffer, rt RedirectTarget, hook Hook) {
	conn := ct.GetConnTrack(pkt, hook)
	if conn == nil {
		return
	}

	invertTuple := conn.tupleHolder[ctDirReply].tuple
	replyHash := ct.getTupleHash(invertTuple)

	// TODO(gvisor.dev/issue/170): Support only redirect of ports. Need to
	// support changing of source and destination address.
	ct.connMu.Lock()
	defer ct.connMu.Unlock()

	conn.tupleHolder[ctDirReply].tuple.src.port = rt.MinPort
	newHash := ct.getTupleHash(conn.tupleHolder[ctDirReply].tuple)
	ct.CtMap[newHash] = conn.tupleHolder[ctDirReply]
	if hook == Output {
		conn.tupleHolder[ctDirReply].conn.manip = manipDstOutput
	}
	delete(ct.CtMap, replyHash)
}

// ManipPacket will manipulate the packet's ports if the connection and
// iptables rule exists.
func (ct *ConnTrackTable) ManipPacket(pkt PacketBuffer, hook Hook, gso *GSO, r *Route) bool {
	if hook != Prerouting && hook != Output {
		return false
	}

	conn := ct.GetConnTrack(pkt, hook)
	// Connection or Rule not found for the packet.
	if conn == nil {
		return false
	}

	// If the hook is prerouting, headers will not be set.
	// TODO(gvisor.dev/issue/170): Change this after parsing headers code
	// is added.
	if hook == Prerouting {
		pkt = parseHeaders(pkt)
	}

	netHeader := header.IPv4(pkt.NetworkHeader)
	// TODO(gvisor.dev/issue/170): Need to support for other transport
	// protocols as well.
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return false
	}

	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return false
	}

	if hook == Prerouting {
		// Manipulate ports.
		if conn.manip == manipDstPrerouting {
			port := conn.tupleHolder[ctDirReply].tuple.src.port
			tcpHeader.SetDestinationPort(port)
		} else {
			port := conn.tupleHolder[ctDirOriginal].tuple.dst.port
			tcpHeader.SetSourcePort(port)
		}
	} else if hook == Output {
		// Manipulate ports.
		if conn.manip == manipDstOutput {
			port := conn.tupleHolder[ctDirReply].tuple.src.port
			tcpHeader.SetDestinationPort(port)
		} else {
			port := conn.tupleHolder[ctDirOriginal].tuple.dst.port
			tcpHeader.SetSourcePort(port)
		}

		// Calculate the TCP checksum and set it.
		tcpHeader.SetChecksum(0)
		hdr := &pkt.Header
		length := uint16(pkt.Data.Size()+hdr.UsedLength()) - uint16(netHeader.HeaderLength())
		xsum := r.PseudoHeaderChecksum(header.TCPProtocolNumber, length)
		if gso != nil && gso.NeedsCsum {
			tcpHeader.SetChecksum(xsum)
		} else if r.Capabilities()&CapabilityTXChecksumOffload == 0 {
			xsum = header.ChecksumVVWithOffset(pkt.Data, xsum, int(tcpHeader.DataOffset()), pkt.Data.Size())
			tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(xsum))
		}
	}

	// Update the state of tcb.
	// TODO(gvisor.dev/issue/170): Add support in tcpcontrack to handle
	// other tcp states.
	var st tcpconntrack.Result
	if conn.tcb == nil {
		conn.tcb = &tcpconntrack.TCB{}
		conn.tcb.Init(header.TCP(pkt.TransportHeader))
		conn.tcbHook = hook
	} else if conn.tcbHook == hook {
		st = conn.tcb.UpdateStateOutbound(tcpHeader)
	} else {
		st = conn.tcb.UpdateStateInbound(tcpHeader)
	}

	// Delete conntrack if tcp connection is closed.
	if st == tcpconntrack.ResultClosedByPeer || st == tcpconntrack.ResultClosedBySelf || st == tcpconntrack.ResultReset {
		ct.DeleteConnTrack(conn)
	}

	return true
}

// DeleteConnTrack deletes the connection.
func (ct *ConnTrackTable) DeleteConnTrack(conn *connTrack) {
	if conn == nil {
		return
	}

	tuple := conn.tupleHolder[ctDirOriginal].tuple
	hash := ct.getTupleHash(tuple)
	invertTuple := conn.tupleHolder[ctDirReply].tuple
	replyHash := ct.getTupleHash(invertTuple)

	ct.connMu.Lock()
	defer ct.connMu.Unlock()

	delete(ct.CtMap, hash)
	delete(ct.CtMap, replyHash)
}
