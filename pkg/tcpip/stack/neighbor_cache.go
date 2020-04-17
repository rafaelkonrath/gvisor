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
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const neighborCacheSize = 512 // max entries per interface

// neighborCache maps IP addresses to link addresses. It uses the Least
// Recently Used (LRU) eviction strategy to implement a bounded cache for
// dynmically acquired entries. It contains the state machine and configuration
// for running Neighbor Unreachability Detection (NUD).
//
// There are two types of entries in the neighbor cache:
//  1. Dynamic entries are discovered automatically by neighbor discovery
//     protocols (e.g. ARP, NDP). These protocols will attempt to reconfirm
//     reachability with the device once the entry's state becomes Stale.
//  2. Static entries are explicitly added by a user and have no expiration.
//     Their state is always Static. The amount of static entries stored in the
//     cache is unbounded.
//
// neighborCache implements NUDHandler.
type neighborCache struct {
	nic   *NIC
	state *NUDState
	mu    struct {
		sync.RWMutex

		cache map[tcpip.Address]*neighborEntry
		lru   neighborEntryList

		// dynamicEntryCount tracks the amount of dynamic entries in the cache.
		// This is needed since static entries do not count towards the LRU
		// eviction strategy.
		dynamicEntryCount uint16
	}
}

var _ NUDHandler = (*neighborCache)(nil)

// getOrCreateEntry retrieves a cache entry associated with addr. The
// returned entry is always refreshed in the cache (it is reachable via the
// map, and its place is bumped in LRU).
//
// If a matching entry exists in the cache, it is returned. If no matching
// entry exists and the cache is full, an existing entry is evicted via LRU,
// reset to state incomplete, and returned. If no matching entry exists and the
// cache is not full, a new entry with state incomplete is allocated and
// returnedh
func (n *neighborCache) getOrCreateEntry(remoteAddr, localAddr tcpip.Address, linkRes LinkAddressResolver) *neighborEntry {
	n.mu.Lock()
	entry, ok := n.mu.cache[remoteAddr]
	defer n.mu.Unlock()

	if ok {
		n.mu.lru.Remove(entry)
		n.mu.lru.PushFront(entry)
		return entry
	}

	entry = newNeighborEntry(n.nic, remoteAddr, localAddr, n.state, linkRes)
	if n.mu.dynamicEntryCount == neighborCacheSize {
		e := n.mu.lru.Back()
		e.mu.Lock()

		delete(n.mu.cache, e.mu.neigh.Addr)
		n.mu.lru.Remove(e)
		n.mu.dynamicEntryCount--

		e.dispatchRemoveEventLocked()
		e.setStateLocked(Unknown)
		e.notifyWakersLocked()
		e.mu.Unlock()
	}
	n.mu.cache[remoteAddr] = entry
	n.mu.lru.PushFront(entry)
	n.mu.dynamicEntryCount++
	return entry
}

// entry looks up the neighbor cache for translating address to link address
// (e.g. IP -> MAC). If the LinkEndpoint requests address resolution and there
// is a LinkAddressResolver registered with the network protocol, the cache
// attempts to resolve the address and returns ErrWouldBlock. Waker is notified
// when address resolution is complete (success or not).
//
// If address resolution is required, ErrNoLinkAddress and a notification
// channel is returned for the top level caller to block. Channel is closed
// once address resolution is complete (success or not).
func (n *neighborCache) entry(remoteAddr, localAddr tcpip.Address, linkRes LinkAddressResolver, w *sleep.Waker) (NeighborEntry, <-chan struct{}, *tcpip.Error) {
	if linkRes != nil {
		if linkAddr, ok := linkRes.ResolveStaticAddress(remoteAddr); ok {
			e := NeighborEntry{
				Addr:      remoteAddr,
				LocalAddr: localAddr,
				LinkAddr:  linkAddr,
				State:     Static,
				UpdatedAt: time.Now(),
			}
			return e, nil, nil
		}
	}

	entry := n.getOrCreateEntry(remoteAddr, localAddr, linkRes)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	switch s := entry.mu.neigh.State; s {
	case Reachable, Static:
		return entry.mu.neigh, nil, nil

	case Unknown, Incomplete, Stale, Delay, Probe:
		if w != nil {
			if entry.mu.wakers == nil {
				entry.mu.wakers = make(map[*sleep.Waker]struct{})
			}
			entry.mu.wakers[w] = struct{}{}
		}

		if entry.mu.done == nil {
			// Address resolution needs to be initiated.
			if linkRes == nil {
				return entry.mu.neigh, nil, tcpip.ErrNoLinkAddress
			}
			entry.mu.done = make(chan struct{})
		}

		entry.handlePacketQueuedLocked(linkRes)
		return entry.mu.neigh, entry.mu.done, tcpip.ErrWouldBlock

	case Failed:
		return entry.mu.neigh, nil, tcpip.ErrNoLinkAddress

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", s))
	}
}

// removeWaker removes a waker that has been added in Entry().
func (n *neighborCache) removeWaker(addr tcpip.Address, waker *sleep.Waker) {
	n.mu.Lock()
	if entry, ok := n.mu.cache[addr]; ok {
		delete(entry.mu.wakers, waker)
	}
	n.mu.Unlock()
}

// entries returns a slice of all entries in the neighbor cache.
func (n *neighborCache) entries() []NeighborEntry {
	entries := []NeighborEntry{}
	n.mu.RLock()
	for _, entry := range n.mu.cache {
		entry.mu.RLock()
		entries = append(entries, entry.mu.neigh)
		entry.mu.RUnlock()
	}
	n.mu.RUnlock()
	return entries
}

// addStaticEntry adds a static entry to the neighbor cache, mapping an IP
// address to a link address. If an entry exists in the neighbor cache with the
// same address, it will be replaced with this static entry.
func (n *neighborCache) addStaticEntry(addr tcpip.Address, linkAddr tcpip.LinkAddress) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if entry, ok := n.mu.cache[addr]; ok {
		n.mu.lru.Remove(entry)
		entry.mu.Lock()
		entry.dispatchRemoveEventLocked()
		entry.mu.Unlock()
	}
	entry := newStaticNeighborEntry(n.nic, addr, linkAddr, n.state)
	n.mu.cache[addr] = entry
}

// removeEntry removes a dynamic or static entry from the neighbor cache.
// Returns true if the entry was found and deleted.
func (n *neighborCache) removeEntry(addr tcpip.Address) bool {
	n.mu.RLock()
	entry, ok := n.mu.cache[addr]
	n.mu.RUnlock()

	if !ok {
		return false
	}

	entry.mu.Lock()
	entry.dispatchRemoveEventLocked()
	entry.setStateLocked(Unknown)
	entry.notifyWakersLocked()
	entry.mu.Unlock()

	n.mu.Lock()
	delete(n.mu.cache, addr)
	n.mu.lru.Remove(entry)
	n.mu.dynamicEntryCount--
	n.mu.Unlock()
	return true
}

// clear removes all dynamic or static entries from the neighbor cache.
func (n *neighborCache) clear() {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, entry := range n.mu.cache {
		entry.mu.Lock()
		entry.dispatchRemoveEventLocked()
		entry.setStateLocked(Unknown)
		entry.notifyWakersLocked()
		entry.mu.Unlock()
	}

	n.mu.lru = neighborEntryList{}
	n.mu.cache = make(map[tcpip.Address]*neighborEntry, neighborCacheSize)
	n.mu.dynamicEntryCount = 0
}

// config returns the NUD configuration.
func (n *neighborCache) config() NUDConfigurations {
	return n.state.Config()
}

// setConfig changes the NUD configuration.
//
// If config contains invalid NUD configuration values, it will be fixed to
// use default values for the erroneous values.
func (n *neighborCache) setConfig(config NUDConfigurations) {
	n.state.SetConfig(config.resetInvalidFields())
}

// HandleProbe implements NUDHandler.HandleProbe by following the logic defined
// in RFC 4861 section 7.2.3.
func (n *neighborCache) HandleProbe(remoteAddr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, remoteLinkAddr tcpip.LinkAddress) {
	if header.IsV4MulticastAddress(remoteAddr) {
		return
	}
	if header.IsV6MulticastAddress(remoteAddr) || remoteAddr == header.IPv6Any {
		return
	}

	entry := n.getOrCreateEntry(remoteAddr, localAddr, nil)
	entry.mu.Lock()
	entry.handleProbeLocked(remoteLinkAddr)
	entry.mu.Unlock()
}

// HandleConfirmation implements NUDHandler.HandleConfirmation by following the
// logic defined in RFC 4861 section 7.2.5.
//
// TODO(gvisor.dev/issue/2277): To protect against ARP poisoning and other
// attacks against NDP functions, Secure Neighbor Discovery (SEND) Protocol
// should be deployed where preventing access to the broadcast segment might
// not be possible. SEND uses RSA key pairs to produce cryptographically
// generated addresses, as defined in RFC 3972, Cryptographically Generated
// Addresses (CGA). This ensures that the claimed source of an NDP message is
// the owner of the claimed address.
func (n *neighborCache) HandleConfirmation(addr tcpip.Address, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) {
	n.mu.RLock()
	entry, ok := n.mu.cache[addr]
	n.mu.RUnlock()
	if ok {
		entry.mu.Lock()
		entry.handleConfirmationLocked(linkAddr, flags)
		entry.mu.Unlock()
	}
	// The confirmation SHOULD be silently discarded if the recipient did not
	// initiate any communication with the target. This is indicated if there is
	// no matching entry for the remote address.
}

// HandleUpperLevelConfirmation implements
// NUDHandler.HandleUpperLevelConfirmation by following the logic defined in
// RFC 4861 section 7.3.1.
func (n *neighborCache) HandleUpperLevelConfirmation(addr tcpip.Address) {
	n.mu.RLock()
	entry, ok := n.mu.cache[addr]
	n.mu.RUnlock()
	if ok {
		entry.mu.Lock()
		entry.handleUpperLevelConfirmationLocked()
		entry.mu.Unlock()
	}
}
