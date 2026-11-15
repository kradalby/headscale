package mapper

import (
	"maps"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
)

// peerHistoryModel is a client-possibility ledger, independent of Hub storage.
// Callers supply unique session tokens, immutable views consistent within each
// revision, and at most one pending write per session. Attempt precedes Delivered;
// a failed write ends its session. Retired tokens remain valid inputs for late
// callbacks. Capacity eviction is deliberately tested by the focused driver.
type peerHistoryModel struct {
	limit    int
	ttl      time.Duration
	sessions map[uint64]types.NodeID
	owners   map[uint64]types.NodeID
	order    []uint64
	history  map[types.NodeID]*peerHistoryEntry
	closed   bool
}

type peerHistoryEntry struct {
	peers   map[types.NodeID]bool
	rev     uint64
	offline time.Time
}

func newPeerHistoryModel(sessionLimit int, ttl time.Duration) *peerHistoryModel {
	return &peerHistoryModel{
		limit: sessionLimit, ttl: ttl,
		sessions: map[uint64]types.NodeID{},
		owners:   map[uint64]types.NodeID{},
		history:  map[types.NodeID]*peerHistoryEntry{},
	}
}

// Join returns the tokens whose oldest sessions admission evicted.
func (m *peerHistoryModel) Join(token uint64, node types.NodeID, now time.Time) []uint64 {
	if m.closed {
		return nil
	}

	m.Expire(now)

	if h := m.history[node]; h != nil {
		h.offline = time.Time{}
	}

	var active []uint64

	for _, old := range m.order {
		if id, ok := m.sessions[old]; ok && id == node {
			active = append(active, old)
		}
	}

	var evicted []uint64
	if len(active) >= m.limit {
		evicted = active[:len(active)-m.limit+1]
		for _, old := range evicted {
			delete(m.sessions, old)
		}
	}

	m.sessions[token] = node
	m.owners[token] = node
	m.order = append(m.order, token)

	return evicted
}

// Leave returns whether another session still serves the token's node. The
// owners map retains retired tokens so repeated leaves have the same owner.
func (m *peerHistoryModel) Leave(token uint64, now time.Time) bool {
	node, known := m.owners[token]
	if !known {
		return false
	}

	delete(m.sessions, token)

	for _, id := range m.sessions {
		if id == node {
			return true
		}
	}

	m.Expire(now)

	if h := m.history[node]; h != nil && h.offline.IsZero() {
		h.offline = now
	}

	return false
}

func (m *peerHistoryModel) Attempt(token, rev uint64, ids []types.NodeID) {
	node, live := m.sessions[token]
	if !live {
		return
	}

	h := m.history[node]
	if h == nil {
		h = &peerHistoryEntry{peers: map[types.NodeID]bool{}}
		m.history[node] = h
	}

	for _, id := range ids {
		h.peers[id] = true
	}

	h.rev = max(h.rev, rev)
}

func (m *peerHistoryModel) Delivered(token, rev uint64, ids []types.NodeID) {
	node, live := m.sessions[token]
	if !live {
		return
	}

	h := m.history[node]
	if h != nil && h.rev > rev {
		return
	}

	peers := map[types.NodeID]bool{}
	for _, id := range ids {
		peers[id] = true
	}

	m.history[node] = &peerHistoryEntry{peers: peers, rev: rev}
}

// Forget returns live tokens stopped by deletion, in admission order.
func (m *peerHistoryModel) Forget(node types.NodeID) []uint64 {
	var stopped []uint64

	for _, token := range m.order {
		if id, live := m.sessions[token]; live && id == node {
			stopped = append(stopped, token)
			delete(m.sessions, token)
		}
	}

	delete(m.history, node)

	return stopped
}

func (m *peerHistoryModel) Expire(now time.Time) {
	for id, h := range m.history {
		if !h.offline.IsZero() && now.Sub(h.offline) >= m.ttl {
			delete(m.history, id)
		}
	}
}

// Possible returns an owned sorted set, including peers of unconfirmed writes.
func (m *peerHistoryModel) Possible(node types.NodeID) []types.NodeID {
	if h := m.history[node]; h != nil {
		return slices.Sorted(maps.Keys(h.peers))
	}

	return nil
}

func (m *peerHistoryModel) Live(token uint64) bool {
	_, ok := m.sessions[token]
	return ok
}

func (m *peerHistoryModel) HasHistory(node types.NodeID) bool {
	_, ok := m.history[node]
	return ok
}

// Close retires all live tokens but does not discard history on shutdown.
func (m *peerHistoryModel) Close() []uint64 {
	m.closed = true

	var stopped []uint64

	for _, token := range m.order {
		if m.Live(token) {
			stopped = append(stopped, token)
		}
	}

	clear(m.sessions)

	return stopped
}
