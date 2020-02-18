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

package arp_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	nicID         = 1
	stackLinkAddr = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c")
	stackAddr     = tcpip.Address("\x0a\x00\x00\x01")

	randomAddr     = tcpip.Address("\x0a\x00\x00\x02")
	randomLinkAddr = tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06")

	unknownAddr = tcpip.Address("\x0a\x00\x00\x03")
)

type eventType uint8

const (
	entryAdded eventType = iota
	entryStateChange
	entryRemoved
)

func (t eventType) String() string {
	switch t {
	case entryAdded:
		return "add"
	case entryStateChange:
		return "change"
	case entryRemoved:
		return "remove"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

type eventInfo struct {
	eventType eventType
	nicID     tcpip.NICID
	addr      tcpip.Address
	linkAddr  tcpip.LinkAddress
	state     stack.NeighborState
}

func (e eventInfo) String() string {
	switch e.eventType {
	case entryAdded:
		return fmt.Sprintf("add event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.nicID, e.addr, e.linkAddr, e.state)
	case entryStateChange:
		return fmt.Sprintf("change event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.nicID, e.addr, e.linkAddr, e.state)
	case entryRemoved:
		return fmt.Sprintf("remove event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.nicID, e.addr, e.linkAddr, e.state)
	default:
		return fmt.Sprintf("unknown event (%d)", e.eventType)
	}
}

// arpDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type arpDispatcher struct {
	// C is where events are queued
	C chan eventInfo
}

var _ stack.NUDDispatcher = (*arpDispatcher)(nil)

func (d *arpDispatcher) OnNeighborAdded(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state stack.NeighborState, updatedAt time.Time) {
	e := eventInfo{
		eventType: entryAdded,
		nicID:     nicID,
		addr:      addr,
		linkAddr:  linkAddr,
		state:     state,
	}
	d.C <- e
}

func (d *arpDispatcher) OnNeighborStateChange(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state stack.NeighborState, updatedAt time.Time) {
	e := eventInfo{
		eventType: entryStateChange,
		nicID:     nicID,
		addr:      addr,
		linkAddr:  linkAddr,
		state:     state,
	}
	d.C <- e
}

func (d *arpDispatcher) OnNeighborRemoved(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state stack.NeighborState, updatedAt time.Time) {
	e := eventInfo{
		eventType: entryRemoved,
		nicID:     nicID,
		addr:      addr,
		linkAddr:  linkAddr,
		state:     state,
	}
	d.C <- e
}

func expectEvents(t *testing.T, d *arpDispatcher, events []eventInfo) {
	for _, wantEvent := range events {
		select {
		case gotEvent := <-d.C:
			if got, want := gotEvent.eventType, wantEvent.eventType; got != want {
				t.Errorf("got event.eventType=%q, want=%q", got, want)
			}
			if got, want := gotEvent.nicID, wantEvent.nicID; got != want {
				t.Errorf("got event.nicID=%q, want=%q", got, want)
			}
			if got, want := gotEvent.addr, wantEvent.addr; got != want {
				t.Errorf("got event.addr=%q, want=%q", got, want)
			}
			if got, want := gotEvent.linkAddr, wantEvent.linkAddr; got != want {
				t.Errorf("got event.linkAddr=%q, want=%q", got, want)
			}
			if got, want := gotEvent.state, wantEvent.state; got != want {
				t.Errorf("got event.state=%q, want=%q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s event not dispatched after one second", wantEvent.eventType)
		}
	}
	if len(d.C) > 0 {
		message := fmt.Sprintf("expect no more events dispatched, got %d more:", len(d.C))
		close(d.C)
		for e := range d.C {
			message += "\n" + e.String()
		}
		t.Fatal(message)
	}
}

type testContext struct {
	s       *stack.Stack
	linkEP  *channel.Endpoint
	nudDisp *arpDispatcher
}

func newTestContext(t *testing.T) *testContext {
	c := stack.DefaultNUDConfigurations()
	// Transition from Reachable to Stale almost immediately to test if receiving
	// probes refreshes positive reachability.
	c.BaseReachableTime = time.Microsecond

	d := arpDispatcher{
		C: make(chan eventInfo, 300),
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), arp.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol4()},
		NUDConfigs:         c,
		NUDDisp:            &d,
	})

	const defaultMTU = 65536
	ep := channel.New(256, defaultMTU, stackLinkAddr)
	wep := stack.LinkEndpoint(ep)

	if testing.Verbose() {
		wep = sniffer.New(ep)
	}
	if err := s.CreateNIC(nicID, wep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(nicID, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(nicID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		t.Fatalf("AddAddress for arp failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	return &testContext{
		s:       s,
		linkEP:  ep,
		nudDisp: &d,
	}
}

func (c *testContext) cleanup() {
	c.linkEP.Close()
}

func TestDirectRequest(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	tests := []struct {
		name           string
		senderAddr     tcpip.Address
		senderLinkAddr tcpip.LinkAddress
		targetAddr     tcpip.Address
		isValid        bool
	}{
		{
			name:           "Loopback",
			senderAddr:     stackAddr,
			senderLinkAddr: stackLinkAddr,
			targetAddr:     stackAddr,
			isValid:        true,
		},
		{
			name:           "Remote",
			senderAddr:     randomAddr,
			senderLinkAddr: randomLinkAddr,
			targetAddr:     stackAddr,
			isValid:        true,
		},
		{
			name:           "RemoteInvalidTarget",
			senderAddr:     randomAddr,
			senderLinkAddr: randomLinkAddr,
			targetAddr:     unknownAddr,
			isValid:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Inject an incoming ARP request.
			v := make(buffer.View, header.ARPSize)
			h := header.ARP(v)
			h.SetIPv4OverEthernet()
			h.SetOp(header.ARPRequest)
			copy(h.HardwareAddressSender(), test.senderLinkAddr)
			copy(h.ProtocolAddressSender(), test.senderAddr)
			copy(h.ProtocolAddressTarget(), test.targetAddr)
			c.linkEP.InjectInbound(arp.ProtocolNumber, stack.PacketBuffer{
				Data: v.ToVectorisedView(),
			})

			if !test.isValid {
				// Sleep tests are gross, but this will only potentially flake if
				// there's a bug. If there is no bug this will reliably succeed.
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				if pkt, ok := c.linkEP.ReadContext(ctx); ok {
					t.Errorf("stackAddrBad: unexpected packet sent, Proto=%v", pkt.Proto)
				}
				return
			}

			// Verify an ARP response was sent.
			pi, _ := c.linkEP.ReadContext(context.Background())
			if pi.Proto != arp.ProtocolNumber {
				t.Fatalf("expected ARP response, got network protocol number %d", pi.Proto)
			}
			rep := header.ARP(pi.Pkt.Header.View())
			if !rep.IsValid() {
				t.Fatalf("invalid ARP response pi.Pkt.Header.UsedLength()=%d", pi.Pkt.Header.UsedLength())
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressSender()), stackLinkAddr; got != want {
				t.Errorf("got HardwareAddressSender = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressSender()), tcpip.Address(h.ProtocolAddressTarget()); got != want {
				t.Errorf("got ProtocolAddressSender = %s, want = %s", got, want)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress(h.HardwareAddressSender()); got != want {
				t.Errorf("got HardwareAddressTarget = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressTarget()), tcpip.Address(h.ProtocolAddressSender()); got != want {
				t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, want)
			}

			// Verify the sender was saved in the neighbor cache.
			expectEvents(t, c.nudDisp, []eventInfo{
				{
					eventType: entryAdded,
					nicID:     nicID,
					addr:      test.senderAddr,
					linkAddr:  tcpip.LinkAddress(test.senderLinkAddr),
					state:     stack.Stale,
				},
			})

			neighbors, err := c.s.Neighbors(nicID)
			if err != nil {
				t.Fatalf("c.s.Neighbors(%d): %s", nicID, err)
			}

			neighborByAddr := make(map[tcpip.Address]stack.NeighborEntry)
			for _, n := range neighbors {
				if existing, ok := neighborByAddr[n.Addr]; ok {
					if diff := cmp.Diff(existing, n); diff != "" {
						t.Fatalf("duplicate neighbor entry found (-existing +got):\n%s", diff)
					} else {
						t.Fatalf("exact neighbor entry duplicate found for addr=%s", n.Addr)
					}
				}
				neighborByAddr[n.Addr] = n
			}

			neigh, ok := neighborByAddr[test.senderAddr]
			if !ok {
				t.Fatalf("expected neighbor entry with Addr = %s", test.senderAddr)
			}
			if got, want := neigh.LinkAddr, test.senderLinkAddr; got != want {
				t.Errorf("got neighbor LinkAddr = %s, want = %s", got, want)
			}
			if got, want := neigh.LocalAddr, stackAddr; got != want {
				t.Errorf("got neighbor LocalAddr = %s, want = %s", got, want)
			}
			if got, want := neigh.State, stack.Stale; got != want {
				t.Errorf("got neighbor State = %s, want = %s", got, want)
			}
		})
	}
}
