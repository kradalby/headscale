package mapper

import (
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

type hubModelSession struct {
	session   *Session
	stream    *Stream
	token     uint64
	stops     int
	wantStops int
	pending   *sentView
	wake      bool
	pings     []*tailcfg.PingRequest
}

// TestHubRapidLifecycle models what a client might hold, without the hub's
// shared slices or folding. Only a confirmed view at least as new as every
// attempted view may discard possible peers. TTL expiry and deletion are the
// other reset points; capacity eviction is tested separately below.
func TestHubRapidLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		h := NewHub()
		defer h.Close()

		now := time.Unix(1, 0)
		h.now = func() time.Time { return now }

		var sessions []*hubModelSession

		model := newPeerHistoryModel(maxConcurrentMapSessionsPerNode, peerHistoryTTL)
		current := sentView{rev: 1}
		views := [][]types.NodeID{nil}

		var reads [][2][]types.NodeID

		live := func(id types.NodeID) []*hubModelSession {
			var out []*hubModelSession

			for _, s := range sessions {
				if model.Live(s.token) && s.session.NodeID == id {
					out = append(out, s)
				}
			}

			return out
		}
		pick := func(t *rapid.T) *hubModelSession {
			if len(sessions) == 0 {
				t.Skip("no admitted session yet")
			}

			return sessions[rapid.IntRange(0, len(sessions)-1).Draw(t, "session")]
		}
		node := func(t *rapid.T) types.NodeID { return types.NodeID(rapid.Uint64Range(1, 3).Draw(t, "node")) }

		t.Repeat(map[string]func(*rapid.T){
			"join": func(t *rapid.T) {
				id := node(t)

				token := uint64(len(sessions) + 1)
				for _, evicted := range model.Join(token, id, now) {
					sessions[evicted-1].wantStops++
				}

				s := &hubModelSession{token: token}
				s.session = h.Join(id, func() { s.stops++ })
				require.NotNil(t, s.session)
				s.stream = &Stream{hub: h, nodeID: id}
				s.stream.Attach(s.session)
				sessions = append(sessions, s)
			},
			"leave": func(t *rapid.T) {
				s := pick(t)
				require.Equal(t, model.Leave(s.token, now), h.Leave(s.session))
			},
			"revision": func(t *rapid.T) {
				current.rev++
				if rapid.Bool().Draw(t, "restoreView") {
					current.ids = rapid.SampledFrom(views).Draw(t, "oldView")
				} else {
					current.ids = hubRapidView(t)
					views = append(views, current.ids)
				}
			},
			"attempt": func(t *rapid.T) {
				s := pick(t)
				if s.pending != nil {
					t.Skip("a stream finishes its write before rendering again")
				}

				v := current
				s.pending = &v
				s.stream.pending = &v
				h.mayHavePeers(s.session, s.session.NodeID, v)
				model.Attempt(s.token, v.rev, v.ids)
			},
			"deliver": func(t *rapid.T) {
				s := pick(t)
				if s.pending != nil {
					model.Delivered(s.token, s.pending.rev, s.pending.ids)
				}

				s.stream.Delivered()
				s.pending = nil
				require.Nil(t, s.stream.pending)
			},
			"forget": func(t *rapid.T) {
				id := node(t)
				for _, token := range model.Forget(id) {
					sessions[token-1].wantStops++
				}

				h.forget(id)
			},
			"clock": func(t *rapid.T) {
				now = now.Add(rapid.SampledFrom([]time.Duration{0, time.Nanosecond, peerHistoryTTL - time.Nanosecond, peerHistoryTTL}).Draw(t, "elapsed"))
				if rapid.Bool().Draw(t, "sweep") {
					model.Expire(now)
					h.expireHistory()
				}
			},
			"wake": func(t *rapid.T) {
				id, all := node(t), rapid.Bool().Draw(t, "all")
				h.wake(all, map[types.NodeID]struct{}{id: {}})

				for _, s := range sessions {
					if model.Live(s.token) && (all || s.session.NodeID == id) {
						s.wake = true
					}
				}
			},
			"ping": func(t *rapid.T) {
				id := node(t)
				for range rapid.IntRange(1, 12).Draw(t, "burst") {
					pr := &tailcfg.PingRequest{URL: "http://example.test/ping"}
					accepted := false

					for _, s := range live(id) {
						if len(s.pings) < 8 {
							s.pings = append(s.pings, pr)
							accepted = true
						}
					}

					require.Equal(t, accepted, h.Ping(id, pr))
				}
			},
			"drain": func(t *rapid.T) {
				s := pick(t)
				if s.wake {
					select {
					case <-s.session.Wakes():
					default:
						t.Fatal("missing wake")
					}

					s.wake = false
				}

				for _, pr := range s.pings {
					select {
					case got := <-s.session.Pings():
						require.Same(t, pr, got)
					default:
						t.Fatal("missing ping")
					}
				}

				s.pings = nil
			},
			"": func(t *rapid.T) {
				connected := map[types.NodeID]int{}

				for id := types.NodeID(1); id <= 3; id++ {
					if n := len(live(id)); n > 0 {
						connected[id] = n
					}

					require.Equal(t, connected[id] > 0, h.IsConnected(id))
					require.Equal(t, model.HasHistory(id), h.HasPeerHistoryForTest(id), "node %d", id)
					want := model.Possible(id)
					got := h.lastPeers(id)
					require.True(t, slices.Equal(want, got), "node %d: want %v, got %v", id, want, got)
					reads = append(reads, [2][]types.NodeID{got, slices.Clone(got)})
				}

				require.Equal(t, connected, h.Connected())

				for _, s := range sessions {
					require.Equal(t, !model.Live(s.token), s.session.left)
					require.Equal(t, s.wantStops, s.stops)
					require.Equal(t, s.wake, len(s.session.Wakes()) == 1)
					require.Len(t, s.session.Pings(), len(s.pings))
				}

				for _, read := range reads {
					require.Equal(t, read[1], read[0], "a retained peer view changed")
				}

				hubRapidAccounting(t, h)
			},
		})

		for _, token := range model.Close() {
			sessions[token-1].wantStops++
		}

		h.Close()
		require.Empty(t, model.Close())
		h.Close()
		require.Empty(t, h.Connected())
		require.Nil(t, h.Join(1, func() { t.Fatal("rejected join called stop") }))
		require.False(t, h.Ping(1, &tailcfg.PingRequest{}))

		select {
		case <-h.Done():
		default:
			t.Fatal("closed hub did not signal Done")
		}

		for _, s := range sessions {
			require.Equal(t, s.wantStops, s.stops)
			before := slices.Clone(h.lastPeers(s.session.NodeID))
			s.stream.Delivered()
			h.mayHavePeers(s.session, s.session.NodeID, current)
			require.True(t, slices.Equal(before, h.lastPeers(s.session.NodeID)))
		}
	})
}

func hubRapidView(t *rapid.T) []types.NodeID {
	ids := rapid.SliceOfNDistinct(rapid.Uint64Range(10, 30), 0, 8, func(id uint64) uint64 { return id }).Draw(t, "peers")

	view := make([]types.NodeID, len(ids), len(ids)+rapid.IntRange(0, 3).Draw(t, "spareCapacity"))
	for i, id := range ids {
		view[i] = types.NodeID(id)
	}

	slices.Sort(view)

	return view
}

// Recount storage from the histories, without using the maintained counters,
// linked list, holdView, foldedCost, or mergeViews.
func hubRapidAccounting(t *rapid.T, h *Hub) {
	t.Helper()

	cost := len(h.offlineAt)
	refs := map[viewKey]int{}
	arrays := map[*types.NodeID]int{}

	for id, v := range h.sentPeers {
		require.LessOrEqual(t, len(v.attempts), maxPeerAttempts)

		if _, offline := h.offlineAt[id]; offline {
			for _, ids := range append([][]types.NodeID{v.ids}, v.attempts...) {
				if len(ids) > 0 {
					arrays[&ids[0]] = cap(ids)
					refs[viewKey{first: &ids[0], n: len(ids)}]++
				}
			}
		} else if v.folded {
			cost += cap(v.ids)
		}
	}

	for _, capacity := range arrays {
		cost += capacity
	}

	require.Equal(t, refs, h.views)
	require.Equal(t, cost, h.retained)
	require.LessOrEqual(t, cost, h.maxHistoryIDs)
	require.Equal(t, len(h.offlineAt), h.offline.Len())
}

// The FIFO oracle counts view identities supplied by the generator, not the
// hub's counters or backing-array keys. Empty histories still cost one entry.
func TestHubRapidOfflineCapacity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		h := NewHub()
		defer h.Close()

		h.now = func() time.Time { return time.Unix(1, 0) }
		h.maxHistoryIDs = rapid.IntRange(0, 60).Draw(t, "limit")
		views := [][]types.NodeID{nil, hubRapidView(t), hubRapidView(t), hubRapidView(t)}

		type entry struct {
			node types.NodeID
			view int
		}

		var offline []entry

		cost := func() int {
			total := len(offline)

			seen := map[int]bool{}
			for _, e := range offline {
				if !seen[e.view] && len(views[e.view]) > 0 {
					total += cap(views[e.view])
					seen[e.view] = true
				}
			}

			return total
		}

		count := rapid.IntRange(1, 30).Draw(t, "nodes")
		for i := range count {
			id := types.NodeID(i + 1)
			view := rapid.IntRange(0, len(views)-1).Draw(t, "view")
			session := h.Join(id, func() {})
			v := sentView{ids: views[view], rev: 1}
			h.mayHavePeers(session, id, v)

			if rapid.Bool().Draw(t, "confirmed") {
				stream := &Stream{hub: h, nodeID: id, sess: session, pending: &v}
				stream.Delivered()
			}

			if rapid.Bool().Draw(t, "overlap") {
				other := h.Join(id, func() {})
				require.True(t, h.Leave(session))
				require.Equal(t, cost(), h.retained, "history is still online")

				session = other
			}

			require.False(t, h.Leave(session))
			require.False(t, h.Leave(session))

			offline = append(offline, entry{node: id, view: view})
			for cost() > h.maxHistoryIDs {
				offline = offline[1:]
			}

			for old := types.NodeID(1); old <= id; old++ {
				index := slices.IndexFunc(offline, func(e entry) bool { return e.node == old })
				require.Equal(t, index >= 0, h.HasPeerHistoryForTest(old), "node %d", old)

				if index >= 0 {
					require.True(t, slices.Equal(views[offline[index].view], h.lastPeers(old)))
				}
			}

			require.Equal(t, cost(), h.retained)
			hubRapidAccounting(t, h)
		}
		// Removing shared holders must release a backing array only after the last.
		for _, e := range slices.Clone(offline) {
			h.forget(e.node)

			offline = offline[1:]

			require.Equal(t, cost(), h.retained)
			hubRapidAccounting(t, h)
		}

		require.Empty(t, h.sentPeers)
	})
}

func TestHubRapidConnectedCapacity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		h := NewHub()
		defer h.Close()

		h.maxHistoryIDs = rapid.IntRange(0, 24).Draw(t, "limit")
		keeper := h.Join(1, func() {})

		count := rapid.IntRange(10, 60).Draw(t, "attempts")
		possible := make([]types.NodeID, 0, count)
		unfolded := 0

		for i := range count {
			// A second connection keeps the node online while each failed writer
			// leaves. Each new peer disappears before the next attempted view.
			s := h.Join(1, func() {})
			peer := types.NodeID(i + 100)
			v := sentView{ids: []types.NodeID{peer}, rev: uint64(i + 1)}
			h.mayHavePeers(s, 1, v)

			possible = append(possible, peer)

			unfolded++
			if unfolded > maxPeerAttempts {
				unfolded = 0

				if len(possible) > h.maxHistoryIDs {
					possible = nil
				}
			}

			require.True(t, slices.Equal(possible, h.lastPeers(1)))
			require.True(t, h.Leave(s))
			hubRapidAccounting(t, h)
		}

		require.False(t, h.Leave(keeper))
		hubRapidAccounting(t, h)
	})
}

func TestHubRapidExpiryBoundary(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		h := NewHub()
		defer h.Close()

		now := time.Unix(1, 0)
		h.now = func() time.Time { return now }
		model := newPeerHistoryModel(maxConcurrentMapSessionsPerNode, peerHistoryTTL)
		view := hubRapidView(t)

		model.Join(1, 1, now)
		s := h.Join(1, func() {})

		model.Attempt(1, 1, view)
		h.mayHavePeers(s, 1, sentView{ids: view, rev: 1})
		require.Equal(t, model.Leave(1, now), h.Leave(s))
		now = now.Add(peerHistoryTTL - time.Nanosecond)
		// A repeated Leave must not extend the original offline deadline.
		require.Equal(t, model.Leave(1, now), h.Leave(s))
		h.expireHistory()
		model.Expire(now)
		require.True(t, h.HasPeerHistoryForTest(1))

		if rapid.Bool().Draw(t, "reconnect") {
			model.Join(2, 1, now)
			s = h.Join(1, func() {})
			require.True(t, slices.Equal(model.Possible(1), h.lastPeers(1)))

			now = now.Add(2 * peerHistoryTTL)

			h.expireHistory()
			model.Expire(now)
			require.True(t, h.HasPeerHistoryForTest(1), "online history does not expire")
			require.Equal(t, model.Leave(2, now), h.Leave(s))
			now = now.Add(peerHistoryTTL - time.Nanosecond)
		}

		now = now.Add(time.Nanosecond)
		if rapid.Bool().Draw(t, "lazyExpiry") {
			model.Join(3, 1, now)
			h.Join(1, func() {})
		} else {
			model.Expire(now)
			h.expireHistory()
		}

		require.False(t, model.HasHistory(1))
		require.False(t, h.HasPeerHistoryForTest(1))
		hubRapidAccounting(t, h)
	})
}

// Barriers put a completion after retirement and optional readmission. There is
// no claim about scheduler-dependent ordering between concurrent operations.
func TestHubRapidRetiredCompletion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		h := NewHub()
		defer h.Close()

		model := newPeerHistoryModel(maxConcurrentMapSessionsPerNode, peerHistoryTTL)
		now := time.Unix(1, 0)
		model.Join(1, 1, now)
		s := h.Join(1, func() {})
		v := sentView{ids: hubRapidView(t), rev: 1}
		h.mayHavePeers(s, 1, v)
		model.Attempt(1, 1, v.ids)
		stream := &Stream{hub: h, nodeID: 1, sess: s, pending: &v}

		mode := rapid.SampledFrom([]string{"leave", "forget", "close", "admission"}).Draw(t, "retire")
		switch mode {
		case "leave":
			model.Leave(1, now)
			h.Leave(s)
		case "forget":
			model.Forget(1)
			h.forget(1)
		case "close":
			model.Close()
			h.Close()
		case "admission":
			for token := uint64(2); token <= uint64(maxConcurrentMapSessionsPerNode+1); token++ {
				model.Join(token, 1, now)
				h.Join(1, func() {})
			}
		}

		if mode != "close" {
			model.Join(10, 1, now)
			fresh := h.Join(1, func() {})

			model.Attempt(10, 2, nil)
			model.Delivered(10, 2, nil)
			h.mayHavePeers(fresh, 1, sentView{rev: 2})
			(&Stream{hub: h, nodeID: 1, sess: fresh, pending: &sentView{rev: 2}}).Delivered()
		}

		release, done := make(chan struct{}), make(chan struct{})
		go func() {
			<-release
			stream.Delivered()
			h.mayHavePeers(s, 1, v)
			close(done)
		}()

		model.Delivered(1, 1, v.ids)
		model.Attempt(1, 1, v.ids)
		close(release)
		<-done
		require.False(t, model.Live(1))
		require.Equal(t, model.HasHistory(1), h.HasPeerHistoryForTest(1))
		require.True(t, slices.Equal(model.Possible(1), h.lastPeers(1)))
	})
}

func TestPeerHistoryModelOwnership(t *testing.T) {
	now := time.Unix(1, 0)
	m := newPeerHistoryModel(1, time.Second)
	m.Join(1, 1, now)

	ids := []types.NodeID{2}
	m.Attempt(1, 1, ids)
	m.Delivered(1, 1, ids)
	ids[0] = 3

	require.Equal(t, []types.NodeID{2}, m.Possible(1))
	m.Attempt(1, 2, ids)
	m.Delivered(1, 2, ids)
	ids[0] = 4
	read := m.Possible(1)
	read[0] = 5

	require.Equal(t, []types.NodeID{3}, m.Possible(1))
	require.Equal(t, []uint64{1}, m.Join(2, 1, now))
	require.False(t, m.Live(1))
	require.False(t, m.Leave(2, now))
	m.Expire(now.Add(time.Second))
	require.False(t, m.HasHistory(1))
	m.Close()
	m.Join(3, 1, now)
	require.False(t, m.Live(3))
}
