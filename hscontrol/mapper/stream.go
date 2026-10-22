package mapper

import (
	"slices"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// Stream turns world snapshots into the map responses one map session
// writes. It holds the netMap the client was last sent; every update is
// the difference between that and a fresh render, so a long-lived stream
// converges on exactly what a new stream would be sent.
type Stream struct {
	cfg    *types.Config
	hub    *Hub
	nodeID types.NodeID
	r      *renderer
	sent   *netMap
}

// NewStream returns a stream for nodeID speaking capVer.
func NewStream(cfg *types.Config, hub *Hub, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *Stream {
	return &Stream{
		cfg:    cfg,
		hub:    hub,
		nodeID: nodeID,
		r:      newRenderer(cfg, nodeID, capVer),
	}
}

// Initial returns the responses that open the stream: the full map, then
// the peers removed while the node had no stream, which clients that only
// learn removals from deltas would otherwise miss.
func (st *Stream) Initial(snap *state.Snapshot) ([]*tailcfg.MapResponse, error) {
	nm, err := st.r.render(snap)
	if err != nil {
		return nil, err
	}

	out := []*tailcfg.MapResponse{fullResponse(st.cfg, nm)}

	var removed []tailcfg.NodeID

	for _, id := range st.hub.lastPeers(st.nodeID) {
		if _, ok := nm.peers[id]; !ok {
			removed = append(removed, id)
		}
	}

	if len(removed) > 0 {
		out = append(out, &tailcfg.MapResponse{PeersRemoved: removed})
	}

	st.sent = nm
	st.hub.setLastPeers(st.nodeID, peerIDs(nm))
	st.dump(out)

	return out, nil
}

// Update returns the responses that bring the client from what it was
// last sent to snap, or nil when nothing it sees changed.
func (st *Stream) Update(snap *state.Snapshot) ([]*tailcfg.MapResponse, error) {
	nm, err := st.r.render(snap)
	if err != nil {
		return nil, err
	}

	out := diff(st.sent, nm)
	st.sent = nm

	if len(out) > 0 {
		st.hub.setLastPeers(st.nodeID, peerIDs(nm))
		st.dump(out)
	}

	return out, nil
}

func (st *Stream) dump(resps []*tailcfg.MapResponse) {
	if debugDumpMapResponsePath == "" {
		return
	}

	for _, r := range resps {
		writeDebugMapResponse(r, st.nodeID)
	}
}

// Hub tracks every live map session so the server can tell whether a node
// is connected, deliver pings to it and end its sessions on shutdown.
type Hub struct {
	mu       sync.Mutex
	sessions map[types.NodeID]map[*Session]struct{}

	// sentPeers is the peer set each node was last sent, kept across its
	// sessions so a reconnect can announce peers removed in between.
	// ponytail: one ID slice per node ever connected; bounded by nodes.
	sentPeers map[types.NodeID][]tailcfg.NodeID

	closed bool
}

// Session is one live map stream of a node.
type Session struct {
	NodeID  types.NodeID
	Created time.Time

	pings chan *tailcfg.PingRequest
	stop  func()
}

// Pings delivers ping requests for the session's node.
func (s *Session) Pings() <-chan *tailcfg.PingRequest { return s.pings }

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{
		sessions:  make(map[types.NodeID]map[*Session]struct{}),
		sentPeers: make(map[types.NodeID][]tailcfg.NodeID),
	}
}

// Join registers a session of nodeID. stop ends the session; the hub calls
// it on shutdown. It returns nil once the hub is closed.
func (h *Hub) Join(nodeID types.NodeID, stop func()) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	s := &Session{
		NodeID:  nodeID,
		Created: time.Now(),
		pings:   make(chan *tailcfg.PingRequest, 8), //nolint:mnd
		stop:    stop,
	}

	if h.sessions[nodeID] == nil {
		h.sessions[nodeID] = make(map[*Session]struct{})
	}

	h.sessions[nodeID][s] = struct{}{}

	return s
}

// Leave unregisters s and reports whether the node still has other
// sessions.
func (h *Hub) Leave(s *Session) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	set := h.sessions[s.NodeID]
	delete(set, s)

	if len(set) == 0 {
		delete(h.sessions, s.NodeID)

		return false
	}

	return true
}

// IsConnected reports whether nodeID has a live session.
func (h *Hub) IsConnected(nodeID types.NodeID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.sessions[nodeID]) > 0
}

// Connected returns the nodes with a live session and how many each has.
func (h *Hub) Connected() map[types.NodeID]int {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make(map[types.NodeID]int, len(h.sessions))
	for id, set := range h.sessions {
		out[id] = len(set)
	}

	return out
}

// Ping asks every session of nodeID to send pr. It reports whether one
// accepted it; a session with a full ping queue drops it.
func (h *Hub) Ping(nodeID types.NodeID, pr *tailcfg.PingRequest) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	sent := false

	for s := range h.sessions[nodeID] {
		select {
		case s.pings <- pr:
			sent = true
		default:
		}
	}

	return sent
}

// Close ends every session and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true

	var stops []func()

	for _, set := range h.sessions {
		for s := range set {
			stops = append(stops, s.stop)
		}
	}
	h.mu.Unlock()

	for _, stop := range stops {
		stop()
	}
}

func (h *Hub) lastPeers(nodeID types.NodeID) []tailcfg.NodeID {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.sentPeers[nodeID])
}

func (h *Hub) setLastPeers(nodeID types.NodeID, ids []tailcfg.NodeID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sentPeers[nodeID] = ids
}
