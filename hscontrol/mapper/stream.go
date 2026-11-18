package mapper

import (
	"container/list"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
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
	// sent is what the responses last returned carry, set before they are
	// written: the next diff starts from it. So a write that fails must end
	// the session, as poll does; diffing on would skip what never arrived.
	sent *netMap

	// pending is the peer view the responses last returned carry, recorded
	// as the node's by [Stream.Delivered] once they are written.
	pending *sentView

	// sess is the hub session the stream writes for, see [Stream.Attach].
	sess *Session
}

// Attach ties st to its hub session: once the session has left the hub,
// or its node was deleted, st records no peer history, which nothing
// would clear again. A stream with no session always records.
func (st *Stream) Attach(s *Session) { st.sess = s }

// NewStream returns a stream for nodeID speaking capVer.
func NewStream(cfg *types.Config, hub *Hub, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *Stream {
	return &Stream{
		cfg:    cfg,
		hub:    hub,
		nodeID: nodeID,
		r:      newRenderer(cfg, hub, nodeID, capVer),
	}
}

// rendered tells the hub the session's render of snap ended, failed when
// err is set: a failed render leaves the session holding what it held. It
// runs before [Stream.record] publishes the render to the route audit, so
// a session the render log wakes again is due to render before the audit
// can hold it to what it just rendered.
func (st *Stream) rendered(snap *state.Snapshot, err error) {
	if st.sess == nil {
		return
	}

	if rev, again := st.hub.renders.end(st.sess, snap, err == nil); again {
		st.hub.rewake(st.sess, rev)
	}
}

// Initial returns the responses that open the stream: the full map, then
// the peers removed while the node had no stream, which clients that only
// learn removals from deltas would otherwise miss. A node whose history the
// hub dropped (see [Hub.Join]) gets the full map alone.
func (st *Stream) Initial(snap *state.Snapshot) ([]*tailcfg.MapResponse, error) {
	snap, previous := st.hub.initialState(st.nodeID, snap)

	nm, err := st.r.render(snap)
	if err != nil {
		st.rendered(snap, err)

		return nil, err
	}

	out := []*tailcfg.MapResponse{fullResponse(st.cfg, nm)}

	var removed []tailcfg.NodeID

	for _, id := range previous {
		if _, ok := nm.peer(id.NodeID()); !ok && id != st.nodeID {
			removed = append(removed, id.NodeID())
		}
	}

	if len(removed) > 0 {
		out = append(out, &tailcfg.MapResponse{PeersRemoved: removed, ControlTime: out[0].ControlTime})
	}

	st.sent = nm
	nm.base = nil

	st.rendered(snap, nil)
	st.record(snap)

	st.pending = &sentView{ids: st.r.lastPeerIDs, rev: snap.Rev()}
	st.hub.mayHavePeers(st.sess, st.nodeID, *st.pending)
	st.dump(out)

	return out, nil
}

// Update returns the responses that bring the client from what it was
// last sent to snap, or nil when nothing it sees changed.
func (st *Stream) Update(snap *state.Snapshot) ([]*tailcfg.MapResponse, error) {
	st.hub.observe(snap)

	nm, err := st.r.render(snap)
	if err != nil {
		st.rendered(snap, err)

		return nil, err
	}

	out := diff(st.sent, nm, &st.hub.frames)
	for i, resp := range out {
		out[i] = st.hub.frames.share(resp)
	}

	peersMoved := peerSetChanged(nm)
	st.sent = nm

	// base was only for this diff; keeping it would chain every render
	// this stream ever made.
	nm.base = nil

	st.rendered(snap, nil)
	st.record(snap)

	if len(out) > 0 {
		if peersMoved {
			st.pending = &sentView{ids: st.r.lastPeerIDs, rev: snap.Rev()}
			st.hub.mayHavePeers(st.sess, st.nodeID, *st.pending)
		}

		st.dump(out)
	}

	return out, nil
}

// record keeps, under the policy audit, what the session now holds for
// the hub's route audit.
func (st *Stream) record(snap *state.Snapshot) {
	if st.sess != nil && state.PolicyAudit() {
		st.sess.sent.Store(&sentRecord{nm: st.sent, rev: snap.Rev(), cfg: st.cfg, capVer: st.r.capVer})
	}
}

// peerSetChanged reports whether nm sees other peers than its base.
func peerSetChanged(nm *netMap) bool {
	if nm.base == nil || len(nm.removed) > 0 {
		return true
	}

	for _, id := range nm.changed {
		if _, ok := nm.base.peer(id); !ok {
			return true
		}
	}

	return false
}

// Ping returns the response carrying pr, counted and dumped as every
// response the stream sends is.
func (st *Stream) Ping(pr *tailcfg.PingRequest) []*tailcfg.MapResponse {
	resps := []*tailcfg.MapResponse{{PingRequest: pr}}
	st.dump(resps)

	return resps
}

func (st *Stream) dump(resps []*tailcfg.MapResponse) {
	for _, r := range resps {
		mapResponseGenerated.WithLabelValues(responseType(r)).Inc()

		if debugDumpMapResponsePath != "" {
			writeDebugMapResponse(r, st.nodeID)
		}
	}
}

var mapResponseGenerated = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "headscale",
	Name:      "mapresponse_generated_total",
	Help:      "total count of mapresponses generated by response type",
}, []string{"response_type"})

// responseType names what a response carries, as a bounded metric label.
func responseType(r *tailcfg.MapResponse) string {
	switch {
	case len(r.Peers) > 0:
		return "full"
	case len(r.PeersChanged) > 0 || len(r.PeersRemoved) > 0:
		return "peers"
	case r.PacketFilters != nil || r.SSHPolicy != nil:
		return "policy"
	case len(r.PeersChangedPatch) > 0:
		return "patch"
	case r.Node != nil:
		return "self"
	case r.DERPMap != nil || r.DNSConfig != nil || r.Domain != "":
		return "config"
	case len(r.UserProfiles) > 0:
		return "profiles"
	case r.PingRequest != nil:
		return "ping"
	default:
		return "unknown"
	}
}

// Hub tracks every live map session so the server can tell whether a node
// is connected, deliver pings to it and end its sessions on shutdown.
type Hub struct {
	mu         sync.Mutex
	sessions   map[types.NodeID]map[*Session]struct{}
	admitted   uint64
	latest     *state.Snapshot
	watchState *state.State

	// firstMaps bounds the first maps rendering at once: after a restart
	// every node reconnects and asks for a full map together.
	firstMaps chan struct{}

	// sentPeers is the peer view each node was last sent, kept across its
	// sessions so a reconnect can announce peers removed in between. Views
	// are the snapshot's, shared by every node seeing the same peers, so
	// this costs no copy per node within one generation. Offline nodes can
	// pin different generations, O(nodes²) in aggregate, so their entries
	// are bounded (see offline): a node back after its entry was dropped
	// gets the full map alone.
	sentPeers map[types.NodeID]sentView

	// versions indexes the render caches by the version they render for,
	// weakly: they live as long as a renderer of the version does.
	versions map[tailcfg.CapabilityVersion]weak.Pointer[versionCache]
	// rev and peersRev are the newest snapshot the watcher advanced the
	// caches to. A new cache starts there, so a render of an older
	// snapshot cannot admit a node or class cleanup already dropped.
	rev, peersRev uint64

	// offline lists, oldest first, the nodes whose history outlived their
	// last session, and offlineAt indexes it. Their history is dropped
	// after peerHistoryTTL, or oldest first while retained exceeds
	// maxHistoryIDs.
	offline   list.List
	offlineAt map[types.NodeID]*list.Element
	// views counts the offline histories holding each view, so a view
	// shared by many nodes counts once in retained.
	views map[viewKey]int
	// retained is what the history beyond each connected node's shared
	// views costs, in IDs of backing arrays: one per offline history and
	// the views it holds, and the folded attempts of connected nodes, which
	// no snapshot shares.
	retained int

	// frames is shared by every session's encoder.
	frames frameCache

	// renders are what sessions rendered and failed to since the last
	// routing, for the commits a routing compares end to end.
	renders renderLog

	closed bool
	// done ends [Hub.Watch].
	done chan struct{}

	now           func() time.Time
	maxHistoryIDs int

	// beforeRoute and routed are test hooks, set before [Hub.Watch].
	// beforeRoute runs before the watcher takes a commit's snapshot, so a
	// slow one lets commits coalesce; routed runs once the watcher woke what
	// a routing from revision from to revision to reached, with how many of
	// those only the render log named.
	beforeRoute func()
	routed      func(from, to uint64, between int)
}

// peerHistoryTTL is how long a node's peer history outlives its last
// session, as upstream kept a disconnected node's sent peers.
const peerHistoryTTL = 15 * time.Minute

// peerHistorySweep is how often [Hub.Watch] drops expired history when no
// reconnect does, as often as upstream swept.
const peerHistorySweep = 5 * time.Minute

// maxPeerHistoryIDs bounds the peer IDs offline histories retain: the TTL
// alone lets a burst of churn pin one generation per offline node.
const maxPeerHistoryIDs = 1 << 19

// offlineHistory is the history of a node with no session, and the views
// it was counted with.
type offlineHistory struct {
	id    types.NodeID
	since time.Time
	views [][]types.NodeID
}

// viewKey identifies a view by its backing array.
type viewKey struct {
	first *types.NodeID
	n     int
}

// expireHistory drops the peer history of nodes offline for longer than
// [peerHistoryTTL].
func (h *Hub) expireHistory() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.expireLocked()
}

func (h *Hub) expireLocked() {
	now := h.now()
	for e := h.offline.Front(); e != nil; e = h.offline.Front() {
		o, _ := e.Value.(*offlineHistory)
		if now.Sub(o.since) < peerHistoryTTL {
			return
		}

		h.dropHistoryLocked(o.id)
	}
}

// offlineLocked starts bounding nodeID's history: its last session left.
func (h *Hub) offlineLocked(nodeID types.NodeID) {
	h.expireLocked()

	cur, ok := h.sentPeers[nodeID]
	if _, listed := h.offlineAt[nodeID]; !ok || listed {
		return
	}

	// Its folded attempts are counted as a view now.
	h.retained -= foldedCost(cur)

	o := &offlineHistory{id: nodeID, since: h.now(), views: append([][]types.NodeID{cur.ids}, cur.attempts...)}
	for _, v := range o.views {
		h.holdView(v, 1)
	}

	// The entry itself costs, so histories with no IDs are bounded too.
	h.retained++
	h.offlineAt[nodeID] = h.offline.PushBack(o)

	h.boundLocked(nodeID)
}

// boundLocked drops histories, oldest offline first, while retained is
// over the cap; when none is offline, nodeID's goes, as the node whose
// history just grew. A node whose history is dropped gets its next full
// map alone.
func (h *Hub) boundLocked(nodeID types.NodeID) {
	for h.retained > h.maxHistoryIDs {
		e := h.offline.Front()
		if e == nil {
			if _, ok := h.sentPeers[nodeID]; ok {
				h.dropHistoryLocked(nodeID)
			}

			return
		}

		oldest, _ := e.Value.(*offlineHistory)
		h.dropHistoryLocked(oldest.id)
	}
}

// foldedCost is what v's folded attempts cost while its node is connected:
// their union is the node's own, unlike the snapshot views attempts share.
func foldedCost(v sentView) int {
	if !v.folded {
		return 0
	}

	return cap(v.ids)
}

// onlineLocked stops bounding nodeID's history: it has a session again,
// or its history goes.
func (h *Hub) onlineLocked(nodeID types.NodeID) {
	e, ok := h.offlineAt[nodeID]
	if !ok {
		return
	}

	h.offline.Remove(e)
	delete(h.offlineAt, nodeID)

	o, _ := e.Value.(*offlineHistory)
	for _, v := range o.views {
		h.holdView(v, -1)
	}

	h.retained--
	h.retained += foldedCost(h.sentPeers[nodeID])
}

func (h *Hub) dropHistoryLocked(nodeID types.NodeID) {
	h.onlineLocked(nodeID)
	h.retained -= foldedCost(h.sentPeers[nodeID])
	delete(h.sentPeers, nodeID)
}

// holdView adds delta offline holders to v, counting its backing array in
// retained while it has any: a view pins all of it.
func (h *Hub) holdView(v []types.NodeID, delta int) {
	if len(v) == 0 {
		return
	}

	k := viewKey{first: &v[0], n: len(v)}
	before := h.views[k]

	switch after := before + delta; {
	case after == 0:
		delete(h.views, k)
		h.retained -= cap(v)
	case before == 0:
		h.views[k] = after
		h.retained += cap(v)
	default:
		h.views[k] = after
	}
}

// renderLog is what the hub knows of the renders that end around its
// routings. A routing from a to c compares a and c only, which is exact for
// a session holding a's render; one whose render was of a snapshot x
// strictly between can hold what neither end has, and needs waking exactly
// when the change from x to c reaches it, which [Route] over x and c says.
// A render reports the snapshot it rendered as it ends: before the routing
// past it, it is left for that routing to weigh; after, the render itself
// asks [Route] up to where the hub has routed. A session woken but not yet
// rendering takes a snapshot at least as new as every routing so far, so
// nothing is kept for it but what its earlier renders left. The log is kept
// in shards, by session, so renders ending together seldom wait on one
// another.
type renderLog struct {
	shards [renderShards]renderShard

	// reach is, per revision rendered and revision routed to, whom the
	// change between them reaches: the renders of one commit, the hub's
	// weighing of them and the routing's own answer are worked out once,
	// whatever snapshot of the commit each holds. A routing drops the
	// pairs of the routings before it.
	reachMu sync.Mutex
	reach   map[[2]uint64]*reachSet

	// hook, set by tests, runs at the points renderPoint names, in the
	// shard named, so a test can put a routing, or a render's end, exactly
	// there.
	hook func(renderPoint, *renderShard)
}

// reachSet is [Route] over a pair of snapshots, worked out once. ok is set
// when it was: a Route that panicked leaves it unset, and a session asking
// is then woken rather than left.
type reachSet struct {
	once sync.Once
	ok   bool
	all  bool
	wake map[types.NodeID]struct{}
}

const renderShards = 16

// renderPoint names a point in [renderLog.end] or [renderLog.between] for
// its test hook.
type renderPoint int

const (
	// renderDecided is where end has read how far its shard was routed and
	// chosen what to do, before it records anything.
	renderDecided renderPoint = iota
	// routingDrained is where a routing has taken a shard's renders and
	// not yet moved the shard on.
	routingDrained
)

type renderShard struct {
	mu sync.Mutex
	// routed is the snapshot the last routing went to.
	routed *state.Snapshot
	// done are the renders finished since then, of snapshots past it, for
	// the next routings to weigh.
	done []renderDone
	// failed are the nodes whose render failed since then, of a snapshot no
	// routing has gone past. They hold what they held before, which no
	// routing describes, so the next routing wakes them whatever it names:
	// only a new snapshot can render otherwise.
	//
	// TODO(kradalby): overwake/failed-render-rewake: a session whose render
	// keeps failing is woken and renders again at every routing, whatever
	// the routing names, until a render succeeds (a node whose own stored
	// data fails to render). Safe: it costs a render per routing and keeps
	// the session converging once it can. Fixing it takes waking it only
	// when the routing's change reaches what failed, or backing off. No
	// test bounds it: the hub properties hold convergence only. No upstream
	// reference: headscale's own hub.
	failed []types.NodeID
}

type renderDone struct {
	id   types.NodeID
	snap *state.Snapshot
}

func (l *renderLog) shard(s *Session) *renderShard { return &l.shards[s.admitted%renderShards] }

func (l *renderLog) at(p renderPoint, sh *renderShard) {
	if l.hook != nil {
		l.hook(p, sh)
	}
}

// end records that s rendered snap, or failed to, and reports whether s
// must be woken again now, and up to which revision the hub routed. A
// render of the snapshot its shard was routed to is exact and leaves
// nothing. If a routing has gone past snap, nothing will weigh the render
// but this: s is woken again when the change from snap to where the hub
// routed reaches it, or when the render failed, since a newer snapshot may
// render. A failed render of the routed snapshot is left for the next
// routing, which a newer snapshot comes with.
func (l *renderLog) end(s *Session, snap *state.Snapshot, ok bool) (uint64, bool) {
	sh := l.shard(s)
	sh.mu.Lock()

	routed := sh.routed
	past := routed != nil && routed.Rev() > snap.Rev()

	l.at(renderDecided, sh)

	switch {
	case past:
	case !ok:
		sh.failed = append(sh.failed, s.NodeID)
	case routed == nil || routed.Rev() != snap.Rev():
		sh.done = append(sh.done, renderDone{id: s.NodeID, snap: snap})
	}

	sh.mu.Unlock()

	if !past {
		return 0, false
	}

	return routed.Rev(), !ok || l.set(snap.Rev(), routed.Rev()).has(snap, routed, s.NodeID)
}

// set returns the reach set of revisions from and to, made if need be.
func (l *renderLog) set(from, to uint64) *reachSet {
	key := [2]uint64{from, to}

	l.reachMu.Lock()
	defer l.reachMu.Unlock()

	r, ok := l.reach[key]
	if !ok {
		if l.reach == nil {
			l.reach = make(map[[2]uint64]*reachSet)
		}

		r = &reachSet{}
		l.reach[key] = r
	}

	return r
}

// routing starts the routing from a to c: it drops the reach sets of the
// routings before and keeps the routing's own, all and wake, for the
// renders of a that end after it.
func (l *renderLog) routing(a, c *state.Snapshot, all bool, wake map[types.NodeID]struct{}) {
	l.reachMu.Lock()
	defer l.reachMu.Unlock()

	for key := range l.reach {
		if key[1] != c.Rev() {
			delete(l.reach, key)
		}
	}

	if a == nil {
		return
	}

	r := &reachSet{ok: true, all: all, wake: wake}
	r.once.Do(func() {})

	if l.reach == nil {
		l.reach = make(map[[2]uint64]*reachSet)
	}

	l.reach[[2]uint64{a.Rev(), c.Rev()}] = r
}

func (r *reachSet) has(old, cur *state.Snapshot, id types.NodeID) bool {
	r.once.Do(func() {
		r.all, r.wake = Route(old, cur, cur.Since(old))
		r.ok = true
	})

	_, named := r.wake[id]

	return !r.ok || r.all || named
}

// between returns the nodes whose sessions a routing from snapshot from to
// snapshot to must wake besides those it names: a session whose render
// failed, and one that rendered a snapshot strictly between the two that
// the change from it to the routing's end reaches, weighed unless the
// routing wakes every session anyway. Every shard moves to that end;
// renders of snapshots past it are kept for the next routing.
func (l *renderLog) between(from, to *state.Snapshot, all bool) []types.NodeID {
	var (
		out   []types.NodeID
		weigh []renderDone
	)

	for i := range l.shards {
		out, weigh = l.shards[i].between(l, out, weigh, from, to)
	}

	if all {
		return out
	}

	sets := map[uint64]*reachSet{}

	for _, d := range weigh {
		r, ok := sets[d.snap.Rev()]
		if !ok {
			r = l.set(d.snap.Rev(), to.Rev())
			sets[d.snap.Rev()] = r
		}

		if r.has(d.snap, to, d.id) {
			out = append(out, d.id)
		}
	}

	return out
}

func (sh *renderShard) between(l *renderLog, out []types.NodeID, weigh []renderDone, from, to *state.Snapshot) ([]types.NodeID, []renderDone) {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	out = append(out, sh.failed...)
	sh.failed = nil

	kept := sh.done[:0]

	// TODO(kradalby): overwake/render-log-stale-entries: every render a
	// session ended since the last routing is weighed, also one older than
	// a later render of the same session, which can wake it again for a
	// change its later render already holds (a session woken twice between
	// two routings). Safe: a render that sends nothing. Fixing it takes
	// keeping each session's latest render only. No test bounds it: the
	// hub properties hold convergence only. No upstream reference:
	// headscale's own hub.
	for _, d := range sh.done {
		switch rev := d.snap.Rev(); {
		case rev > to.Rev():
			kept = append(kept, d)
		case rev == to.Rev(), from != nil && rev == from.Rev():
			// A routing's end: compared from or to, exactly.
		default:
			weigh = append(weigh, d)
		}
	}

	clear(sh.done[len(kept):])
	sh.done = kept

	l.at(routingDrained, sh)

	sh.routed = to

	return out, weigh
}

// Session is one live map stream of a node.
type Session struct {
	NodeID types.NodeID

	pings chan *tailcfg.PingRequest
	wakes chan struct{}
	stop  func()

	// left is set, under the hub's lock, once the session left the hub or
	// its node was deleted; a write still in flight then records nothing.
	left     bool
	admitted uint64

	// woken is, under the policy audit and the hub's lock, the latest
	// commit that woke the session; sent what its stream last rendered.
	woken uint64
	sent  atomic.Pointer[sentRecord]
}

// sentRecord is what a session's stream rendered, at which commit, for
// the route audit.
type sentRecord struct {
	nm     *netMap
	rev    uint64
	cfg    *types.Config
	capVer tailcfg.CapabilityVersion
}

// Pings delivers ping requests for the session's node.
func (s *Session) Pings() <-chan *tailcfg.PingRequest { return s.pings }

// Wakes receives when a commit may have changed what the session's node
// is sent; at most one wake-up is pending.
func (s *Session) Wakes() <-chan struct{} { return s.wakes }

func (s *Session) wake() {
	select {
	case s.wakes <- struct{}{}:
	default:
	}
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{
		sessions:  make(map[types.NodeID]map[*Session]struct{}),
		sentPeers: make(map[types.NodeID]sentView),
		versions:  make(map[tailcfg.CapabilityVersion]weak.Pointer[versionCache]),
		offlineAt: make(map[types.NodeID]*list.Element),
		views:     make(map[viewKey]int),
		done:      make(chan struct{}),
		firstMaps: make(chan struct{}, runtime.GOMAXPROCS(0)),

		now:           time.Now,
		maxHistoryIDs: maxPeerHistoryIDs,
	}
}

// RenderFirst waits for a slot to render a session's first map and
// returns its release, or false when done or stop closes first, or the
// hub does: a session that ended while queued renders nothing.
func (h *Hub) RenderFirst(done, stop <-chan struct{}) (func(), bool) {
	select {
	case h.firstMaps <- struct{}{}:
		return func() { <-h.firstMaps }, true
	case <-done:
		return nil, false
	case <-stop:
		return nil, false
	case <-h.done:
		return nil, false
	}
}

// Watch follows s until the hub closes. After each commit it wakes the
// sessions [Route] names, and those the render log does: sessions that
// rendered between commits it routed together and whom the rest reaches,
// and sessions whose render failed. It ends the sessions of nodes that were
// deleted, even a session whose write is blocked, which its own loop cannot
// notice. It subscribes before returning: a session that renders after
// Watch returns is woken for every later commit.
// A Hub belongs to exactly one State, including after that State closes.
// Reconstructed worlds start their revisions over and require a fresh Hub.
func (h *Hub) Watch(s *state.State) {
	first := s.Snapshot()

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}

	if h.watchState != nil {
		same := h.watchState == s
		h.mu.Unlock()

		if !same {
			panic(hubWorldMismatch)
		}

		return
	}

	if h.latest != nil && !h.latest.SameWorld(first) {
		h.mu.Unlock()
		panic(hubWorldMismatch)
	}

	h.watchState = s
	h.mu.Unlock()

	sub := s.Subscribe()
	last := s.Snapshot()

	h.observe(last)
	go h.watch(s, sub, last)
}

func (h *Hub) watch(s *state.State, sub *graph.Subscription, last *state.Snapshot) {
	defer sub.Close()

	expire := time.NewTicker(peerHistorySweep)
	defer expire.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-expire.C:
			h.expireHistory()

			continue
		case <-sub.C:
		}

		if h.beforeRoute != nil {
			h.beforeRoute()
		}

		snap := s.Snapshot()
		from := last.Rev()
		change, all, wake, between := h.route(last, snap)
		last = snap

		h.advance(snap)
		cleanup := snap

		if change.Resync {
			// The edit log can no longer name transient deleted nodes.
			// Check only state retained by the hub, not the whole tailnet.
			h.mu.Lock()
			for id := range h.sessions {
				change.Nodes = append(change.Nodes, id)
			}

			for id := range h.sentPeers {
				change.Nodes = append(change.Nodes, id)
			}
			h.mu.Unlock()

			for _, vc := range h.caches() {
				vc.renders.m.Range(func(id, _ any) bool {
					change.Nodes = append(change.Nodes, id.(types.NodeID)) //nolint:forcetypeassert // keyed by NodeID
					return true
				})
			}
			// A retained session may have joined after snap was read.
			cleanup = s.Snapshot()
			h.advance(cleanup)
		}

		slices.Sort(change.Nodes)

		change.Nodes = slices.Compact(change.Nodes)
		for _, id := range change.Nodes {
			if _, live := cleanup.GetNode(id); !live {
				h.forget(id)
			}
		}

		if !state.PolicyAudit() {
			h.wake(all, wake)
		} else {
			h.wakeAt(all, wake, snap.Rev())

			if !all {
				h.auditRoutes(snap, wake)
			}
		}

		if h.routed != nil {
			h.routed(from, snap.Rev(), between)
		}
	}
}

// route returns what changed from last to snap and the sessions it
// reaches, as [Route], and how many of those the render log alone named.
// Wakes coalesce: snap can be several commits past last, and Since covers
// them all for a session holding last's render; a session that rendered a
// snapshot in between is woken again when the rest reaches it.
func (h *Hub) route(last, snap *state.Snapshot) (state.Change, bool, map[types.NodeID]struct{}, int) {
	change := snap.Since(last)
	all, wake := Route(last, snap, change)

	h.renders.routing(last, snap, all, wake)
	between := h.renders.between(last, snap, all)

	if all || len(between) == 0 {
		return change, all, wake, 0
	}

	// wake is the reach set renders of last now read: wake a copy.
	wake = maps.Clone(wake)
	added := 0

	for _, id := range between {
		if _, ok := wake[id]; !ok {
			wake[id] = struct{}{}
			added++
		}
	}

	return change, all, wake, added
}

// cache returns the render caches of capVer, made anew once no renderer
// holds them.
func (h *Hub) cache(capVer tailcfg.CapabilityVersion) *versionCache {
	h.mu.Lock()
	defer h.mu.Unlock()

	if vc := h.versions[capVer].Value(); vc != nil {
		return vc
	}

	vc := &versionCache{}
	vc.renders.floor, vc.classes.pruned = h.rev, h.peersRev
	w := weak.Make(vc)
	h.versions[capVer] = w

	// The index entry goes with the cache, so versions a client merely
	// named cost nothing once its sessions are gone.
	runtime.AddCleanup(vc, func(w weak.Pointer[versionCache]) {
		h.mu.Lock()
		if h.versions[capVer] == w {
			delete(h.versions, capVer)
		}
		h.mu.Unlock()
	}, w)

	return vc
}

// caches returns the render caches some renderer still holds.
func (h *Hub) caches() []*versionCache {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]*versionCache, 0, len(h.versions))
	for _, w := range h.versions {
		if vc := w.Value(); vc != nil {
			out = append(out, vc)
		}
	}

	return out
}

// advance moves every render cache to snap, and starts the caches made
// from now on there. The watcher calls it before deletion cleanup, even
// when a resync finds no retained IDs.
func (h *Hub) advance(snap *state.Snapshot) {
	h.mu.Lock()
	if h.latest != nil && !h.latest.SameWorld(snap) {
		h.mu.Unlock()
		panic(hubWorldMismatch)
	}

	if h.latest == nil || h.latest.Rev() < snap.Rev() {
		h.latest = snap
	}

	h.rev, h.peersRev = max(h.rev, snap.Rev()), max(h.peersRev, snap.PeersRev())
	h.mu.Unlock()

	for _, vc := range h.caches() {
		vc.renders.advance(snap.Rev())
		vc.classes.advance(snap)
	}

	h.frames.release(snap.Time())
}

// Route returns the nodes whose sessions a change from old to cur can
// reach: all of them, or those in wake. A node's map holds itself, its
// peers and what every map reads, so a change reaches
//   - every node, when something every map reads changed;
//   - a node, when it changed, gained or lost a primary route, its peers
//     or its policy capabilities changed, its packet filter or SSH policy
//     can have changed, or its side set or side facts did, which the
//     routes every peer offers it read;
//   - the nodes that see a node before and after, when it changed, its
//     primary routes moved, its capabilities changed, or it serves a route
//     whose cover moved, which the routes it offers them read;
//   - the nodes that see any node serving routes, when what every route
//     reads moved.
//
// Peer visibility is not symmetric: an exit node sees every source of a
// capability grant whose destination reaches the internet, which does not
// see it. So the nodes a change reaches are the node's readers
// ([state.Snapshot.PeerReaders]), not its own view. An online flip needs no
// check of the node's role (router, relay, via): a peer's map reads the
// node's online state only through the node's own entry and the primaries,
// and both wake the peer.
func Route(old, cur *state.Snapshot, c state.Change) (bool, map[types.NodeID]struct{}) {
	if old == nil || c.Global {
		return true, nil
	}

	wake := make(map[types.NodeID]struct{})

	add := func(ids []types.NodeID) {
		for _, id := range ids {
			wake[id] = struct{}{}
		}
	}

	// A node whose change no map renders wakes nobody; its health reaches
	// the election, and so Primaries, on its own.
	//
	// TODO(kradalby): overwake/announce-readers: SameRender reads the node's
	// own render and its peer render as one, so a change only its own map
	// shows (the routes it announces, which no peer render carries) wakes
	// every node that sees it for nothing. Safe: wakes that send nothing.
	// Fixing it takes telling the node's own render from its peer render
	// here: the node itself for the first, its viewers for the second.
	// Tolerated by the woken-with-nothing-to-send ceiling of
	// TestSessionsFollowGeneratedScenarios. No upstream reference: the
	// render split is headscale's.
	nodes := slices.DeleteFunc(slices.Clone(c.Nodes), func(id types.NodeID) bool {
		was, wasOK := old.GetNode(id)
		is, isOK := cur.GetNode(id)

		return cur.Rev() == old.Rev()+1 && wasOK && isOK && was.SameRender(is)
	})

	add(nodes)
	add(c.Primaries)
	add(c.PeerSets)
	add(c.Filters)
	add(c.Caps)
	add(c.RouteViewers)

	// TODO(kradalby): overwake/stamp-viewers, overwake/routers-cover,
	// overwake/all-routers: every node that sees a node of Caps, Routers, or,
	// with AllRouters, any routed node, is woken whole, whether or not what
	// it is sent of that node moved; see those keys at their sources
	// (PeerCapMap, Sides.RoutersMovedSince, Snapshot.Since). Readers woken
	// so are a large part of the sessions woken for nothing between
	// neighbouring commits, which the ceiling of
	// TestSessionsFollowGeneratedScenarios pins. No upstream reference:
	// headscale's own routing.
	viewed := [][]types.NodeID{nodes, c.Primaries, c.Caps, c.Routers}

	if c.AllRouters {
		viewed = append(viewed, old.RoutedNodes(), cur.RoutedNodes())
	}

	for _, v := range reachedViews(old, cur, viewed...) {
		add(v)
	}

	return false, wake
}

// reachedViews returns, as distinct lists, the nodes that see a node of ids
// before and after. The lists are shared holder lists, so a change of many
// nodes walks each once rather than once per node.
func reachedViews(old, cur *state.Snapshot, ids ...[]types.NodeID) [][]types.NodeID {
	type viewKey struct {
		first *types.NodeID
		n     int
	}

	seen := make(map[viewKey]struct{})

	var out [][]types.NodeID

	for _, group := range ids {
		for _, id := range group {
			for _, v := range slices.Concat(old.PeerReaders(id), cur.PeerReaders(id)) {
				if len(v) == 0 {
					continue
				}

				if _, ok := seen[viewKey{&v[0], len(v)}]; ok {
					continue
				}

				seen[viewKey{&v[0], len(v)}] = struct{}{}
				out = append(out, v)
			}
		}
	}

	return out
}

// wake wakes every session, or the sessions of the nodes in ids.
func (h *Hub) wake(all bool, ids map[types.NodeID]struct{}) { h.wakeAt(all, ids, 0) }

// rewake wakes s again for the render log, the hub having routed to rev:
// under the audit s is then due to render rev, as a routing's wake makes
// it, so the route audit does not hold it to the render it just ended.
func (h *Hub) rewake(s *Session, rev uint64) {
	if state.PolicyAudit() {
		h.mu.Lock()
		s.woken = max(s.woken, rev)
		h.mu.Unlock()
	}

	s.wake()
}

// wakeAt is [Hub.wake] for commit rev, which the route audit tells the
// sessions still to render it by; zero, as without the audit, records
// nothing.
func (h *Hub) wakeAt(all bool, ids map[types.NodeID]struct{}, rev uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	woke := func(s *Session) {
		if rev != 0 {
			s.woken = max(s.woken, rev)
		}

		s.wake()
	}

	if all {
		for _, set := range h.sessions {
			for s := range set {
				woke(s)
			}
		}

		return
	}

	for id := range ids {
		for s := range h.sessions[id] {
			woke(s)
		}
	}
}

var (
	routeAuditRuns     atomic.Uint64
	routeAuditFailures atomic.Uint64
)

// RouteAuditRuns counts the sessions the route audit rendered afresh.
func RouteAuditRuns() uint64 { return routeAuditRuns.Load() }

// RouteAuditFailures counts the sessions the route audit found holding a
// map other than a fresh render's.
func RouteAuditFailures() uint64 { return routeAuditFailures.Load() }

// auditRoutes holds routing to the snapshot, under the policy audit: every
// session [Route] did not wake for snap, single or coalesced, and that
// rendered no earlier than it was last woken, must hold what a fresh render
// of snap gives, or a write it was never told of left it stale. A change
// that wakes everyone is not audited: coalesced commits that moved anything
// a map renders besides the nodes are such a change, so under load, when
// commits coalesce, fewer are audited.
//
// A fresh render has render caches of its own and filters cut afresh, none
// carried over on routing's word, and reads SSH without filling the
// compile's caches, which SSH routing reads; it shares only the snapshot's
// lazily built values, which no routing decision reads. What sessions hold
// is immutable once recorded, and the renders run on the hub's goroutine,
// after waking, under no lock commits wait on.
func (h *Hub) auditRoutes(snap *state.Snapshot, woken map[types.NodeID]struct{}) {
	type held struct {
		id  types.NodeID
		rec *sentRecord
	}

	var todo []held

	h.mu.Lock()

	for id, set := range h.sessions {
		if _, ok := woken[id]; ok {
			continue
		}

		for s := range set {
			if rec := s.sent.Load(); !s.left && rec != nil && rec.rev >= s.woken && rec.rev <= snap.Rev() {
				todo = append(todo, held{id: id, rec: rec})
			}
		}
	}

	h.mu.Unlock()

	if len(todo) == 0 {
		return
	}

	fresh := snap.Uncached()
	caches := map[tailcfg.CapabilityVersion]*versionCache{}

	for _, t := range todo {
		pcv := peerCapVer(t.rec.capVer)
		if caches[pcv] == nil {
			caches[pcv] = &versionCache{}
		}

		out, err := freshDiff(t.rec.cfg, fresh, t.id, t.rec.capVer, t.rec.nm, caches[pcv])
		if errors.Is(err, ErrNodeGone) {
			continue
		}

		routeAuditRuns.Add(1)

		if err != nil {
			log.Error().Err(err).Uint64(zf.NodeID, t.id.Uint64()).Msg("policy audit: route: rendering afresh")

			continue
		}

		if len(out) > 0 {
			routeAuditFailures.Add(1)
			log.Error().Uint64(zf.NodeID, t.id.Uint64()).Uint64("sent.rev", t.rec.rev).Uint64("rev", snap.Rev()).
				Str("diff", describeResponses(out)).Msg("policy audit: route: a session routing did not wake holds a stale map")
		}
	}
}

// freshDiff renders node's map from snap with caches of its own, vc, and
// returns what would bring a client holding sent to it: nothing when sent
// is what the session should hold.
func freshDiff(cfg *types.Config, snap *state.Snapshot, node types.NodeID, capVer tailcfg.CapabilityVersion, sent *netMap, vc *versionCache) ([]*tailcfg.MapResponse, error) {
	r := &renderer{cfg: cfg, nodeID: node, capVer: capVer, peerCapVer: peerCapVer(capVer), renders: &vc.renders, classes: &vc.classes}

	nm, err := r.render(snap)
	if err != nil {
		return nil, err
	}

	return diff(sent, nm, nil), nil
}

// describeResponses names what responses carry, for a log line.
func describeResponses(resps []*tailcfg.MapResponse) string {
	var parts []string

	for _, r := range resps {
		if r.Node != nil {
			parts = append(parts, "self")
		}

		if r.PacketFilters != nil {
			parts = append(parts, "filter")
		}

		if r.SSHPolicy != nil {
			parts = append(parts, "ssh")
		}

		if r.DNSConfig != nil {
			parts = append(parts, "dns")
		}

		if r.DERPMap != nil {
			parts = append(parts, "derp")
		}

		if len(r.UserProfiles) > 0 {
			parts = append(parts, "profiles")
		}

		for _, ids := range [][]tailcfg.NodeID{peerIDsOf(r.Peers), peerIDsOf(r.PeersChanged), r.PeersRemoved} {
			if len(ids) > 0 {
				parts = append(parts, fmt.Sprintf("peers%v", ids))
			}
		}

		for _, p := range r.PeersChangedPatch {
			parts = append(parts, fmt.Sprintf("patch[%d]", p.NodeID))
		}
	}

	return strings.Join(parts, " ")
}

func peerIDsOf(nodes []*tailcfg.Node) []tailcfg.NodeID {
	ids := make([]tailcfg.NodeID, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}

	return ids
}

// forget ends the sessions of a deleted node and drops its hub state.
func (h *Hub) forget(id types.NodeID) {
	h.mu.Lock()

	stops := make([]func(), 0, len(h.sessions[id]))
	for s := range h.sessions[id] {
		s.left = true
		stops = append(stops, s.stop)
	}

	delete(h.sessions, id)

	h.dropHistoryLocked(id)
	h.mu.Unlock()

	for _, vc := range h.caches() {
		vc.renders.forget(id)
	}

	for _, stop := range stops {
		stop()
	}
}

// maxConcurrentMapSessionsPerNode bounds overlapping authenticated map requests.
const maxConcurrentMapSessionsPerNode = 4

// Join registers a session of nodeID, keeping its peer history unless the
// node was offline longer than [peerHistoryTTL]. stop ends the session;
// the hub calls it on shutdown. It returns nil once the hub is closed.
func (h *Hub) Join(nodeID types.NodeID, stop func()) *Session {
	h.mu.Lock()

	if h.closed {
		h.mu.Unlock()
		return nil
	}

	// Expired first: a node back after the TTL must not replay it.
	h.expireLocked()
	h.onlineLocked(nodeID)

	h.admitted++
	s := &Session{
		NodeID:   nodeID,
		admitted: h.admitted,
		pings:    make(chan *tailcfg.PingRequest, 8), //nolint:mnd
		wakes:    make(chan struct{}, 1),
		stop:     stop,
	}

	if h.sessions[nodeID] == nil {
		h.sessions[nodeID] = make(map[*Session]struct{})
	}

	var evicted *Session

	if len(h.sessions[nodeID]) >= maxConcurrentMapSessionsPerNode {
		for current := range h.sessions[nodeID] {
			if evicted == nil || current.admitted < evicted.admitted {
				evicted = current
			}
		}

		delete(h.sessions[nodeID], evicted)
		evicted.left = true
	}

	h.sessions[nodeID][s] = struct{}{}
	h.mu.Unlock()

	if evicted != nil {
		evicted.stop()
	}

	return s
}

// Leave unregisters s and reports whether the node still has other
// sessions.
func (h *Hub) Leave(s *Session) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	s.left = true

	set := h.sessions[s.NodeID]
	delete(set, s)

	if len(set) == 0 {
		delete(h.sessions, s.NodeID)
		h.offlineLocked(s.NodeID)

		return false
	}

	return true
}

// HasPeerHistoryForTest reports whether the hub keeps peer history for
// nodeID.
func (h *Hub) HasPeerHistoryForTest(nodeID types.NodeID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	_, ok := h.sentPeers[nodeID]

	return ok
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

// Done is closed once the hub is closed, when the server is stopping.
func (h *Hub) Done() <-chan struct{} { return h.done }

// Close ends every session and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}

	close(h.done)
	h.closed = true

	var stops []func()

	for _, set := range h.sessions {
		for s := range set {
			s.left = true
			stops = append(stops, s.stop)
		}
	}

	h.sessions = make(map[types.NodeID]map[*Session]struct{})
	h.mu.Unlock()

	for _, stop := range stops {
		stop()
	}
}

// lastPeers returns the peer view nodeID was last sent; it may hold the
// node itself.
func (h *Hub) lastPeers(nodeID types.NodeID) []types.NodeID {
	h.mu.Lock()
	cur := h.sentPeers[nodeID]
	h.mu.Unlock()

	if len(cur.attempts) == 0 {
		return cur.ids
	}

	return mergeViews(cur)
}

const hubWorldMismatch = "mapper: a Hub belongs to one State; use a new Hub for a reconstructed State"

// initialState captures history with the newest snapshot the hub observed.
// An obsolete initial snapshot must neither remove future peers nor lose an
// older removal when a newer attempted write failed before its removal frame.
func (h *Hub) initialState(nodeID types.NodeID, snap *state.Snapshot) (*state.Snapshot, []types.NodeID) {
	h.mu.Lock()
	if h.latest != nil && !h.latest.SameWorld(snap) {
		h.mu.Unlock()
		panic(hubWorldMismatch)
	}

	if h.latest == nil || h.latest.Rev() < snap.Rev() {
		h.latest = snap
	} else {
		snap = h.latest
	}

	cur := h.sentPeers[nodeID]
	h.mu.Unlock()

	if len(cur.attempts) == 0 {
		return snap, cur.ids
	}

	return snap, mergeViews(cur)
}

func (h *Hub) observe(snap *state.Snapshot) {
	h.mu.Lock()
	if h.latest != nil && !h.latest.SameWorld(snap) {
		h.mu.Unlock()
		panic(hubWorldMismatch)
	}

	if h.latest == nil || h.latest.Rev() < snap.Rev() {
		h.latest = snap
	}
	h.mu.Unlock()
}

// setLastPeers records v as nodeID's last delivered view, unless a newer
// one was: a write finishing late on an old session must not roll the
// history back.
func (h *Hub) setLastPeers(by *Session, nodeID types.NodeID, v sentView) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if by != nil && by.left {
		return
	}

	// Only an older render is refused. Two renders of one revision carry
	// the same view (a snapshot's views are fixed), so an equal one is the
	// same history, and its delivery must still clear the attempts.
	cur, ok := h.sentPeers[nodeID]
	if ok && cur.rev > v.rev {
		return
	}

	h.retained -= foldedCost(cur)
	h.sentPeers[nodeID] = v
}

// mayHavePeers widens nodeID's history by v, a view about to be written:
// a write that fails part way can still deliver some of it, and a later
// reconnect must announce the removal of any peer the client may hold.
// [Stream.Delivered] narrows it back to what was written.
// Views are kept as they are, shared, and merged only when a reconnect
// reads them.
func (h *Hub) mayHavePeers(by *Session, nodeID types.NodeID, v sentView) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if by != nil && by.left {
		return
	}

	cur := h.sentPeers[nodeID]
	cur.attempts = append(slices.Clip(cur.attempts), v.ids)
	cur.rev = max(cur.rev, v.rev)

	// A node that keeps failing folds its attempts into one view. The
	// union is its own and only grows while nothing is delivered, though
	// the node never leaves, so it counts against the cap.
	if len(cur.attempts) > maxPeerAttempts {
		h.retained -= foldedCost(cur)
		cur.ids, cur.attempts, cur.folded = mergeViews(cur), nil, true
		h.retained += foldedCost(cur)
		h.sentPeers[nodeID] = cur
		h.boundLocked(nodeID)

		return
	}

	h.sentPeers[nodeID] = cur
}

// maxPeerAttempts bounds the unconfirmed views kept per node.
const maxPeerAttempts = 8

// mergeViews returns the sorted union of v's confirmed and attempted views,
// in an array of its own size: a kept union must not pin the concatenation.
func mergeViews(v sentView) []types.NodeID {
	union := slices.Concat(append([][]types.NodeID{v.ids}, v.attempts...)...)
	slices.Sort(union)
	union = slices.Compact(union)

	out := make([]types.NodeID, len(union))
	copy(out, union)

	return out
}

// sentView is a peer view delivered to a node, and the snapshot revision
// it was rendered from.
type sentView struct {
	ids []types.NodeID
	rev uint64
	// attempts are the views written since ids was confirmed, which a
	// failed write may have delivered in part.
	attempts [][]types.NodeID
	// folded is set when ids is the union of attempts, not a delivered
	// snapshot view.
	folded bool
}

// Delivered records that the responses the stream last returned were
// written to the client. Until then a reconnect still announces the peers
// they removed: a removal written to a broken connection is not lost.
func (st *Stream) Delivered() {
	if st.pending != nil {
		st.hub.setLastPeers(st.sess, st.nodeID, *st.pending)
		st.pending = nil
	}
}

// frameCache lets sessions that send the same update share one response
// and one encoding of it. Under endpoint churn every viewer of a node is
// sent the same single patch at the same commit time; encoding it once
// instead of once per viewer is most of what sending it costs. A shared
// response and its encoding must not be modified.
type frameCache struct {
	mu sync.Mutex

	// at is the commit time the cache is for. Only sessions sending the
	// same commit share, so a later one starts the cache over: what an
	// earlier commit's entries hold, superseded renders among them, is
	// garbage by then.
	at time.Time

	// patches holds the patch between two shared renders, so sessions
	// sending it hold the same one.
	patches map[[2]*tailcfg.Node]patchResult

	// frames holds the shared response by what it carries: its one patch
	// or its DERP map.
	frames map[any]*sharedFrame
	byResp map[*tailcfg.MapResponse]*sharedFrame
}

// advance moves the cache to commit time at, starting it over when at is
// later, and reports whether at is the cache's: a session late with an
// older commit shares nothing. The caller holds mu.
func (fc *frameCache) advance(at time.Time) bool {
	if at.Before(fc.at) {
		return false
	}

	if fc.frames == nil || at.After(fc.at) {
		fc.at = at
		fc.patches = map[[2]*tailcfg.Node]patchResult{}
		fc.frames = map[any]*sharedFrame{}
		fc.byResp = map[*tailcfg.MapResponse]*sharedFrame{}
	}

	return true
}

// release drops the entries of commits before at. Only a session sharing
// a frame starts the cache over, so without this a commit that shares
// nothing (a removal, say) would leave the earlier commit's patches, and
// the renders they hold, rooted until the next shared frame.
func (fc *frameCache) release(at time.Time) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if at.After(fc.at) {
		fc.at = at
		fc.patches, fc.frames, fc.byResp = nil, nil, nil
	}
}

type patchResult struct {
	patch     *tailcfg.PeerChange
	patchable bool
}

// maxSharedPatches bounds the patch cache within one commit; it starts
// over when full.
const maxSharedPatches = 1 << 14

type sharedFrame struct {
	resp    *tailcfg.MapResponse
	once    [2]sync.Once // per compression
	encoded [2][]byte
	err     [2]error
}

// patch is [peerPatch], shared between sessions sending the same renders
// at commit time at.
func (fc *frameCache) patch(at time.Time, before, after *tailcfg.Node) (*tailcfg.PeerChange, bool) {
	if fc == nil {
		return peerPatch(before, after)
	}

	key := [2]*tailcfg.Node{before, after}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	if !fc.advance(at) {
		return peerPatch(before, after)
	}

	if r, ok := fc.patches[key]; ok {
		return r.patch, r.patchable
	}

	if len(fc.patches) >= maxSharedPatches {
		fc.patches = map[[2]*tailcfg.Node]patchResult{}
	}

	p, ok := peerPatch(before, after)
	fc.patches[key] = patchResult{patch: p, patchable: ok}

	return p, ok
}

// share returns the response all sessions with resp's content send: one
// holding just a single shared patch and a ControlTime is shared, any
// other is returned as is.
func (fc *frameCache) share(resp *tailcfg.MapResponse) *tailcfg.MapResponse {
	var p any

	switch {
	case patchOnly(resp):
		p = resp.PeersChangedPatch[0]
	case derpOnly(resp):
		p = resp.DERPMap
	default:
		return resp
	}

	at := *resp.ControlTime

	fc.mu.Lock()
	defer fc.mu.Unlock()

	if !fc.advance(at) {
		return resp
	}

	if f, ok := fc.frames[p]; ok {
		return f.resp
	}

	f := &sharedFrame{resp: resp}
	fc.frames[p] = f
	fc.byResp[resp] = f

	return resp
}

// derpOnly reports whether resp holds a DERP map and its time and nothing
// else; every session is sent the snapshot's.
func derpOnly(resp *tailcfg.MapResponse) bool {
	if resp.ControlTime == nil || resp.DERPMap == nil {
		return false
	}

	rest := *resp
	rest.DERPMap, rest.ControlTime = nil, nil

	// Check every remaining field, including future MapResponse additions.
	return reflect.ValueOf(rest).IsZero()
}

// patchOnly reports whether resp holds a single patch and its time and
// nothing else.
func patchOnly(resp *tailcfg.MapResponse) bool {
	if resp.ControlTime == nil || len(resp.PeersChangedPatch) != 1 {
		return false
	}

	rest := *resp
	rest.PeersChangedPatch, rest.ControlTime = nil, nil

	return reflect.ValueOf(rest).IsZero()
}

// Encode returns resp encoded by encode: once for a response sessions
// share, per compression. The bytes may be shared; callers copy them.
func (h *Hub) Encode(
	resp *tailcfg.MapResponse,
	compress bool,
	encode func(*tailcfg.MapResponse, bool) ([]byte, error),
) ([]byte, error) {
	h.frames.mu.Lock()
	f := h.frames.byResp[resp]
	h.frames.mu.Unlock()

	if f == nil {
		return encode(resp, compress)
	}

	i := 0
	if compress {
		i = 1
	}

	f.once[i].Do(func() { f.encoded[i], f.err[i] = encode(resp, compress) })

	return f.encoded[i], f.err[i]
}

// Marshal encodes resp as [encoding/json.Marshal] does, writing each node
// it holds from the encoding cached for that render: a peer's render is
// shared by every session that sees it and never changes, so its JSON is
// made once for all the maps that carry it.
func Marshal(resp *tailcfg.MapResponse) ([]byte, error) {
	return jsonv2.Marshal(resp, jsonv1.DefaultOptionsV1(), nodeMarshalers)
}

// MarshalTo writes the same JSON as [Marshal] to w, which may receive partial
// output on error. A caller with a reusable buffer avoids Marshal's output copy.
func MarshalTo(w io.Writer, resp *tailcfg.MapResponse) error {
	return jsonv2.MarshalWrite(w, resp, jsonv1.DefaultOptionsV1(), nodeMarshalers)
}

var (
	nodeMarshalers = jsonv2.WithMarshalers(jsonv2.MarshalToFunc(marshalNode))

	// nodeJSON holds the encoding of each node render while the render
	// lives, by a weak pointer to it. It is right only because a render is
	// never modified once built: a change is always a new *tailcfg.Node.
	nodeJSON sync.Map
)

func marshalNode(enc *jsontext.Encoder, n *tailcfg.Node) error {
	key := weak.Make(n)
	if b, ok := nodeJSON.Load(key); ok {
		return enc.WriteValue(b.(jsontext.Value)) //nolint:forcetypeassert // only values stored
	}

	b, err := jsonv2.Marshal(n, jsonv1.DefaultOptionsV1())
	if err != nil {
		return err
	}

	if _, loaded := nodeJSON.LoadOrStore(key, jsontext.Value(b)); !loaded {
		runtime.AddCleanup(n, func(k weak.Pointer[tailcfg.Node]) { nodeJSON.Delete(k) }, key)
	}

	return enc.WriteValue(b)
}
