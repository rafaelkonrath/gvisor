// Copyright 2018 The gVisor Authors.
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

package ipv6

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, pkt stack.PacketBuffer) {
	h := header.IPv6(pkt.Data.First())

	// We don't use IsValid() here because ICMP only requires that up to
	// 1280 bytes of the original packet be included. So it's likely that it
	// is truncated, which would cause IsValid to return false.
	//
	// Drop packet if it doesn't have the basic IPv6 header or if the
	// original source address doesn't match the endpoint's address.
	if len(h) < header.IPv6MinimumSize || h.SourceAddress() != e.id.LocalAddress {
		return
	}

	// Skip the IP header, then handle the fragmentation header if there
	// is one.
	pkt.Data.TrimFront(header.IPv6MinimumSize)
	p := h.TransportProtocol()
	if p == header.IPv6FragmentHeader {
		f := header.IPv6Fragment(pkt.Data.First())
		if !f.IsValid() || f.FragmentOffset() != 0 {
			// We can't handle fragments that aren't at offset 0
			// because they don't have the transport headers.
			return
		}

		// Skip fragmentation header and find out the actual protocol
		// number.
		pkt.Data.TrimFront(header.IPv6FragmentHeaderSize)
		p = f.TransportProtocol()
	}

	// Deliver the control packet to the transport endpoint.
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
}

func (e *endpoint) handleICMP(r *stack.Route, netHeader buffer.View, pkt stack.PacketBuffer, hasFragmentHeader bool) {
	stats := r.Stats().ICMP
	sent := stats.V6PacketsSent
	received := stats.V6PacketsReceived
	v := pkt.Data.First()
	if len(v) < header.ICMPv6MinimumSize {
		received.Invalid.Increment()
		return
	}
	h := header.ICMPv6(v)
	iph := header.IPv6(netHeader)

	// Validate ICMPv6 checksum before processing the packet.
	//
	// Only the first view in vv is accounted for by h. To account for the
	// rest of vv, a shallow copy is made and the first view is removed.
	// This copy is used as extra payload during the checksum calculation.
	payload := pkt.Data.Clone(nil)
	payload.RemoveFirst()
	if got, want := h.Checksum(), header.ICMPv6Checksum(h, iph.SourceAddress(), iph.DestinationAddress(), payload); got != want {
		received.Invalid.Increment()
		return
	}

	isNDPValid := func() bool {
		// As per RFC 4861 sections 4.1 - 4.5, 6.1.1, 6.1.2, 7.1.1, 7.1.2 and
		// 8.1, nodes MUST silently drop NDP packets where the Hop Limit field
		// in the IPv6 header is not set to 255, or the ICMPv6 Code field is not
		// set to 0.
		//
		// As per RFC 6980 section 5, nodes MUST silently drop NDP messages if the
		// packet includes a fragmentation header.
		return !hasFragmentHeader && iph.HopLimit() == header.NDPHopLimit && h.Code() == 0
	}

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv6PacketTooBig:
		received.PacketTooBig.Increment()
		if len(v) < header.ICMPv6PacketTooBigMinimumSize {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6PacketTooBigMinimumSize)
		mtu := h.MTU()
		e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), pkt)

	case header.ICMPv6DstUnreachable:
		received.DstUnreachable.Increment()
		if len(v) < header.ICMPv6DstUnreachableMinimumSize {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6DstUnreachableMinimumSize)
		switch h.Code() {
		case header.ICMPv6PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, pkt)
		}

	case header.ICMPv6NeighborSolicit:
		received.NeighborSolicit.Increment()
		if len(v) < header.ICMPv6NeighborSolicitMinimumSize || !isNDPValid() {
			received.Invalid.Increment()
			return
		}

		ns := header.NDPNeighborSolicit(h.NDPPayload())
		targetAddr := ns.TargetAddress()
		s := r.Stack()
		if isTentative, err := s.IsAddrTentative(e.nicID, targetAddr); err != nil {
			// We will only get an error if the NIC is unrecognized, which should not
			// happen. For now, drop this packet.
			//
			// TODO(b/141002840): Handle this better?
			return
		} else if isTentative {
			// If the target address is tentative and the source of the packet is a
			// unicast (specified) address, then the source of the packet is
			// attempting to perform address resolution on the target. In this case,
			// the solicitation is silently ignored, as per RFC 4862 section 5.4.3.
			//
			// If the target address is tentative and the source of the packet is the
			// unspecified address (::), then we know another node is also performing
			// DAD for the same address (since the target address is tentative for us,
			// we know we are also performing DAD on it). In this case we let the
			// stack know so it can handle such a scenario and do nothing further with
			// the NS.
			if r.RemoteAddress == header.IPv6Any {
				s.DupTentativeAddrDetected(e.nicID, targetAddr)
			}

			// Do not handle neighbor solicitations targeted to an address that is
			// tentative on the NIC any further.
			return
		}

		// At this point we know that the target address is not tentative on the NIC
		// so the packet is processed as defined in RFC 4861, as per RFC 4862
		// section 5.4.3.

		// Is the NS targeting us?
		if s.CheckLocalAddress(e.nicID, ProtocolNumber, targetAddr) == 0 {
			return
		}

		it, err := ns.Options().Iter(false)
		if err != nil {
			// If we have a malformed NDP NS option, drop the packet.
			received.Invalid.Increment()
			return
		}

		var sourceLinkAddr tcpip.LinkAddress

		for {
			opt, done, err := it.Next()
			if err != nil {
				// If we have a malformed NDP NS option, drop the packet.
				received.Invalid.Increment()
				return
			}
			if done {
				break
			}

			switch opt := opt.(type) {
			case header.NDPSourceLinkLayerAddressOption:
				// No RFCs define what to do when an NS message has multiple Source
				// Link-Layer Address options. Since no interface can have multiple
				// link-layer addresses, we consider such messages invalid.
				if len(sourceLinkAddr) != 0 {
					received.Invalid.Increment()
					return
				}

				sourceLinkAddr = opt.EthernetAddress()
			}
		}

		unspecifiedSource := r.RemoteAddress == header.IPv6Any

		// As per RFC 4861 section 4.3, the Source Link-Layer Address Option MUST
		// NOT be included when the source IP address is the unspecified address.
		// Otherwise, on link layers that have addresses this option MUST be
		// included in multicast solicitations and SHOULD be included in unicast
		// solicitations.
		if len(sourceLinkAddr) == 0 {
			if header.IsV6MulticastAddress(r.LocalAddress) && !unspecifiedSource {
				received.Invalid.Increment()
				return
			}
		} else if unspecifiedSource {
			received.Invalid.Increment()
			return
		} else {
			e.nud.HandleProbe(r.RemoteAddress, r.LocalAddress, header.IPv6ProtocolNumber, sourceLinkAddr)
		}

		// ICMPv6 Neighbor Solicit messages are always sent to
		// specially crafted IPv6 multicast addresses. As a result, the
		// route we end up with here has as its LocalAddress such a
		// multicast address. It would be nonsense to claim that our
		// source address is a multicast address, so we manually set
		// the source address to the target address requested in the
		// solicit message. Since that requires mutating the route, we
		// must first clone it.
		r := r.Clone()
		defer r.Release()
		r.LocalAddress = targetAddr

		// As per RFC 4861 section 7.2.4, if the the source of the solicitation is
		// the unspecified address, the node MUST set the Solicited flag to zero and
		// multicast the advertisement to the all-nodes address.
		solicited := true
		if unspecifiedSource {
			solicited = false
			r.RemoteAddress = header.IPv6AllNodesMulticastAddress
		}

		// If the NS has a source link-layer option, use the link address it
		// specifies as the remote link address for the response instead of the
		// source link address of the packet.
		//
		// TODO(#2401): As per RFC 4861 section 7.2.4 we should consult our link
		// address cache for the right destination link address instead of manually
		// patching the route with the remote link address if one is specified in a
		// Source Link-Layer Address option.
		if len(sourceLinkAddr) != 0 {
			r.RemoteLinkAddress = sourceLinkAddr
		}

		optsSerializer := header.NDPOptionsSerializer{
			header.NDPTargetLinkLayerAddressOption(r.LocalLinkAddress),
		}
		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborAdvertMinimumSize + int(optsSerializer.Length()))
		packet := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
		packet.SetType(header.ICMPv6NeighborAdvert)
		na := header.NDPNeighborAdvert(packet.NDPPayload())
		na.SetSolicitedFlag(solicited)
		na.SetOverrideFlag(true)
		na.SetTargetAddress(targetAddr)
		opts := na.Options()
		opts.Serialize(optsSerializer)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		// RFC 4861 Neighbor Discovery for IP version 6 (IPv6)
		//
		// 7.1.2. Validation of Neighbor Advertisements
		//
		// The IP Hop Limit field has a value of 255, i.e., the packet
		// could not possibly have been forwarded by a router.
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: stack.DefaultTOS}, stack.PacketBuffer{
			Header: hdr,
		}); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.NeighborAdvert.Increment()

	case header.ICMPv6NeighborAdvert:
		received.NeighborAdvert.Increment()
		if len(v) < header.ICMPv6NeighborAdvertSize || !isNDPValid() {
			received.Invalid.Increment()
			return
		}

		na := header.NDPNeighborAdvert(h.NDPPayload())
		it, err := na.Options().Iter(true)
		if err != nil {
			// If we have a malformed NDP NA option, drop the packet.
			received.Invalid.Increment()
			return
		}

		targetAddr := na.TargetAddress()
		s := r.Stack()
		rxNICID := r.NICID()

		if isTentative, err := s.IsAddrTentative(rxNICID, targetAddr); err != nil {
			// We will only get an error if rxNICID is unrecognized,
			// which should not happen. For now short-circuit this
			// packet.
			//
			// TODO(b/141002840): Handle this better?
			return
		} else if isTentative {
			// We just got an NA from a node that owns an address we
			// are performing DAD on, implying the address is not
			// unique. In this case we let the stack know so it can
			// handle such a scenario and do nothing furthur with
			// the NDP NA.
			s.DupTentativeAddrDetected(rxNICID, targetAddr)
			return
		}

		// At this point we know that the targetAddress is not tentative
		// on rxNICID. However, targetAddr may still be assigned to
		// rxNICID but not tentative (it could be permanent). Such a
		// scenario is beyond the scope of RFC 4862. As such, we simply
		// ignore such a scenario for now and proceed as normal.
		//
		// If the NA message has the target link layer option, update the link
		// address cache with the link address for the target of the message.
		//
		// TODO(b/143147598): Handle the scenario described above. Also
		// inform the netstack integration that a duplicate address was
		// detected outside of DAD.
		//
		// TODO(b/148429853): Properly process the NA message and do Neighbor
		// Unreachability Detection.
		for {
			opt, done, err := it.Next()
			if err != nil {
				// This option is not valid as per the wire format, silently drop the packet.
				received.Invalid.Increment()
				return
			}
			if done {
				break
			}

			switch opt := opt.(type) {
			case header.NDPTargetLinkLayerAddressOption:
				linkAddr := opt.EthernetAddress()
				e.nud.HandleConfirmation(targetAddr, linkAddr, stack.ReachabilityConfirmationFlags{
					Solicited: na.SolicitedFlag(),
					Override:  na.OverrideFlag(),
					IsRouter:  na.RouterFlag(),
				})
			}
		}

	case header.ICMPv6EchoRequest:
		received.EchoRequest.Increment()
		if len(v) < header.ICMPv6EchoMinimumSize {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6EchoMinimumSize)
		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize)
		packet := header.ICMPv6(hdr.Prepend(header.ICMPv6EchoMinimumSize))
		copy(packet, h)
		packet.SetType(header.ICMPv6EchoReply)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, pkt.Data))
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}, stack.PacketBuffer{
			Header: hdr,
			Data:   pkt.Data,
		}); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.EchoReply.Increment()

	case header.ICMPv6EchoReply:
		received.EchoReply.Increment()
		if len(v) < header.ICMPv6EchoMinimumSize {
			received.Invalid.Increment()
			return
		}
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv6ProtocolNumber, pkt)

	case header.ICMPv6TimeExceeded:
		received.TimeExceeded.Increment()

	case header.ICMPv6ParamProblem:
		received.ParamProblem.Increment()

	case header.ICMPv6RouterSolicit:
		received.RouterSolicit.Increment()
		if !isNDPValid() {
			received.Invalid.Increment()
			return
		}

		//
		// Validate the RS as per RFC 4861 section 6.1.1.
		//

		stack := r.Stack()

		// Is the NIC acting as a router?
		if !stack.Forwarding() {
			// ... No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		p := h.NDPPayload()

		// Is the NDP payload of sufficient size to hold a Router
		// Solicitation?
		if len(p) < header.NDPRSMinimumSize {
			// ... No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		rs := header.NDPRouterSolicit(p)
		it, err := rs.Options().Iter(false)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		// If the RS has the source link layer option, update the link address
		// cache with the link address for the sender.
		for {
			opt, done, err := it.Next()
			if err != nil {
				// Options are not valid as per the wire format, silently drop the packet.
				received.Invalid.Increment()
				return
			}
			if done {
				break
			}

			switch opt := opt.(type) {
			case header.NDPSourceLinkLayerAddressOption:
				sourceAddr := iph.SourceAddress()

				// Is the source IP address unspecified?
				if len(sourceAddr) == 0 {
					// ... Yes, silently drop the packet.
					return
				}

				// A RS with a specified source IP address modifies the NUD state
				// machine in the same way a reachability probe would.
				e.nud.HandleProbe(sourceAddr, r.LocalAddress, header.IPv6ProtocolNumber, opt.EthernetAddress())
			}
		}

		//
		// At this point, we have a valid Router Solicitation, as far
		// as RFC 4861 section 6.1.1 is concerned.
		//

	case header.ICMPv6RouterAdvert:
		received.RouterAdvert.Increment()

		p := h.NDPPayload()
		if len(p) < header.NDPRAMinimumSize || !isNDPValid() {
			received.Invalid.Increment()
			return
		}

		routerAddr := iph.SourceAddress()

		//
		// Validate the RA as per RFC 4861 section 6.1.2.
		//

		// Is the IP Source Address a link-local address?
		if !header.IsV6LinkLocalAddress(routerAddr) {
			// ...No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		ra := header.NDPRouterAdvert(p)
		it, err := ra.Options().Iter(false)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		//
		// At this point, we have a valid Router Advertisement, as far
		// as RFC 4861 section 6.1.2 is concerned.
		//

		// Tell the NIC to handle the RA.
		stack := r.Stack()
		rxNICID := r.NICID()
		stack.HandleNDPRA(rxNICID, routerAddr, ra)

		// If the RA has the source link layer option, update the link address
		// cache with the link address for the advertised router.
		for {
			opt, done, err := it.Next()
			if err != nil {
				// This option is not valid as per the wire format, silently drop the packet.
				received.Invalid.Increment()
				return
			}
			if done {
				break
			}

			switch opt := opt.(type) {
			case header.NDPSourceLinkLayerAddressOption:
				e.nud.HandleProbe(routerAddr, r.LocalAddress, header.IPv6ProtocolNumber, opt.EthernetAddress())
			}
		}

	case header.ICMPv6RedirectMsg:
		// TODO(gvisor.dev/issue/2285): Call `e.nud.HandleProbe` after validating
		// this redirect message, as per RFC 4871 section 7.3.3:
		//
		//    "A Neighbor Cache entry enters the STALE state when created as a
		//    result of receiving packets other than solicited Neighbor
		//    Advertisements (i.e., Router Solicitations, Router Advertisements,
		//    Redirects, and Neighbor Solicitations).  These packets contain the
		//    link-layer address of either the sender or, in the case of Redirect,
		//    the redirection target.  However, receipt of these link-layer
		//    addresses does not confirm reachability of the forward-direction path
		//    to that node.  Placing a newly created Neighbor Cache entry for which
		//    the link-layer address is known in the STALE state provides assurance
		//    that path failures are detected quickly. In addition, should a cached
		//    link-layer address be modified due to receiving one of the above
		//    messages, the state SHOULD also be set to STALE to provide prompt
		//    verification that the path to the new link-layer address is working."
		received.RedirectMsg.Increment()
		if !isNDPValid() {
			received.Invalid.Increment()
			return
		}

	default:
		received.Invalid.Increment()
	}
}

const (
	ndpSolicitedFlag = 1 << 6
	ndpOverrideFlag  = 1 << 5

	ndpOptSrcLinkAddr = 1
	ndpOptDstLinkAddr = 2

	icmpV6FlagOffset   = 4
	icmpV6OptOffset    = 24
	icmpV6LengthOffset = 25
)

var broadcastMAC = tcpip.LinkAddress([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

var _ stack.LinkAddressResolver = (*protocol)(nil)

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress, linkEP stack.LinkEndpoint) *tcpip.Error {
	snaddr := header.SolicitedNodeAddr(addr)

	// TODO(b/148672031): Use stack.FindRoute instead of manually creating the
	// route here. Note, we would need the nicID to do this properly so the right
	// NIC (associated to linkEP) is used to send the NDP NS message.
	r := &stack.Route{
		LocalAddress:      localAddr,
		RemoteAddress:     snaddr,
		RemoteLinkAddress: linkAddr,
	}
	if len(r.RemoteLinkAddress) == 0 {
		r.RemoteLinkAddress = header.EthernetAddressFromMulticastIPv6Address(snaddr)
	}

	hdr := buffer.NewPrependable(int(linkEP.MaxHeaderLength()) + header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	copy(pkt[icmpV6OptOffset-len(addr):], addr)
	pkt[icmpV6OptOffset] = ndpOptSrcLinkAddr
	pkt[icmpV6LengthOffset] = 1
	copy(pkt[icmpV6LengthOffset+1:], linkEP.LinkAddress())
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	length := uint16(hdr.UsedLength())
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: length,
		NextHeader:    uint8(header.ICMPv6ProtocolNumber),
		HopLimit:      header.NDPHopLimit,
		SrcAddr:       r.LocalAddress,
		DstAddr:       r.RemoteAddress,
	})

	// TODO(stijlist): count this in ICMP stats.
	return linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, stack.PacketBuffer{
		Header: hdr,
	})
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}
