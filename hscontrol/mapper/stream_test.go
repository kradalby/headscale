package mapper

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const capVer = tailcfg.CurrentCapabilityVersion

// streamTestState returns a State with users u1, u2 and nodes n1, n1b
// (u1) and n2 (u2), under policy (allow-all when empty).
func streamTestState(t *testing.T, policy string) (*types.Config, *state.State, [3]types.NodeID) {
	t.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: t.TempDir() + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		ServerURL:    "https://headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	u1 := database.CreateUserForTest("u1")
	u2 := database.CreateUserForTest("u2")
	n1 := database.CreateRegisteredNodeForTest(u1, "n1")
	n1b := database.CreateRegisteredNodeForTest(u1, "n1b")
	n2 := database.CreateRegisteredNodeForTest(u2, "n2")
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	s.SetDERPMap(&tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
	})

	if policy != "" {
		_, err = s.SetPolicy([]byte(policy))
		require.NoError(t, err)
	}

	return cfg, s, [3]types.NodeID{n1.ID, n1b.ID, n2.ID}
}

const ownUserOnly = `{"acls":[
	{"action":"accept","src":["u1@"],"dst":["u1@:*"]},
	{"action":"accept","src":["u2@"],"dst":["u2@:*"]}
]}`

func peerSet(resp *tailcfg.MapResponse) map[tailcfg.NodeID]bool {
	out := make(map[tailcfg.NodeID]bool)
	for _, p := range resp.Peers {
		out[p.ID] = true
	}

	return out
}

// mentions reports whether any response names peer id.
func mentions(resps []*tailcfg.MapResponse, id types.NodeID) bool {
	for _, r := range resps {
		for _, p := range r.Peers {
			if p.ID == id.NodeID() {
				return true
			}
		}

		for _, p := range r.PeersChanged {
			if p.ID == id.NodeID() {
				return true
			}
		}

		for _, p := range r.PeersChangedPatch {
			if p.NodeID == id.NodeID() {
				return true
			}
		}

		for _, p := range r.PeersRemoved {
			if p == id.NodeID() {
				return true
			}
		}
	}

	return false
}

func TestStreamInitialIsFullAndThenQuiet(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	st := NewStream(cfg, NewHub(), ids[0], capVer)

	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, initial, 1)

	full := initial[0]
	require.NotNil(t, full.Node)
	assert.NotNil(t, full.SSHPolicy, "a full map always carries an SSH policy")
	assert.NotNil(t, full.DERPMap)
	assert.Equal(t, map[tailcfg.NodeID]bool{ids[1].NodeID(): true, ids[2].NodeID(): true}, peerSet(full))

	again, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	assert.Empty(t, again, "nothing changed")
}

func TestStreamPeerChangesAreDeltas(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	gen := s.Connect(ids[1])
	require.NotZero(t, gen)

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, resps, 1)
	require.Len(t, resps[0].PeersChangedPatch, 1, "coming online is a patch")
	assert.Equal(t, ids[1].NodeID(), resps[0].PeersChangedPatch[0].NodeID)
	assert.Nil(t, resps[0].Node, "the viewer itself did not change")

	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	resps, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, resps, 1)
	assert.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, resps[0].PeersRemoved)
}

func TestStreamNeverMentionsInvisiblePeers(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	assert.False(t, mentions(initial, ids[2]), "n2 is another user's node")

	_ = s.Connect(ids[2])
	_ = s.Connect(ids[1])
	_, err = s.RenameNode(ids[2], "renamed")
	require.NoError(t, err)

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	assert.False(t, mentions(resps, ids[2]), "changes to an invisible node must not leak")
	assert.True(t, mentions(resps, ids[1]), "changes to a visible node are delivered")
}

// TestStreamConvergesOnFreshMap applies the deltas a long-lived stream
// sends and checks they arrive at what a new stream is sent.
func TestStreamConvergesOnFreshMap(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	long := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := long.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])

	steps := []func(){
		func() { _ = s.Connect(ids[1]) },
		func() { _, _ = s.RenameNode(ids[2], "n2-renamed") },
		func() {
			expiry := time.Now().Add(-time.Minute)
			_, _ = s.SetNodeExpiry(ids[1], &expiry)
		},
		func() { _, _ = s.SetPolicy([]byte(ownUserOnly)) },
		func() { _, _ = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)) },
		func() { require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2]))) },
	}

	for i, step := range steps {
		step()

		resps, err := long.Update(s.Snapshot())
		require.NoError(t, err)

		for _, r := range resps {
			client.apply(r)
		}

		fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
		require.NoError(t, err)

		want := newModelClient(fresh[0])
		if !reflect.DeepEqual(want.peers, client.peers) {
			t.Fatalf("step %d: long-lived peers %v, fresh %v", i, keys(client.peers), keys(want.peers))
		}

		assert.True(t, reflect.DeepEqual(want.filter, client.filter), "step %d: filter differs", i)
	}
}

func TestStreamReconnectAnnouncesMissedRemoval(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()

	_, err := NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)

	// n1 is offline while n1b is deleted.
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	resps, err := NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, resps, 2, "full map, then the removal it missed")
	assert.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, resps[1].PeersRemoved)
}

func TestStreamEndsWhenNodeDeleted(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[0])))

	_, err = st.Update(s.Snapshot())
	require.ErrorIs(t, err, ErrNodeGone)
}

func mustNode(t *testing.T, s *state.State, id types.NodeID) types.NodeView {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	return nv
}

// modelClient applies map responses the way a client does, for the
// fields these tests compare.
type modelClient struct {
	peers  map[tailcfg.NodeID]*tailcfg.Node
	filter []tailcfg.FilterRule
}

func newModelClient(full *tailcfg.MapResponse) *modelClient {
	c := &modelClient{peers: make(map[tailcfg.NodeID]*tailcfg.Node)}
	c.apply(full)

	return c
}

func (c *modelClient) apply(r *tailcfg.MapResponse) {
	if len(r.Peers) > 0 {
		c.peers = make(map[tailcfg.NodeID]*tailcfg.Node)
		for _, p := range r.Peers {
			c.peers[p.ID] = p.Clone()
		}
	}

	for _, p := range r.PeersChanged {
		c.peers[p.ID] = p.Clone()
	}

	for _, id := range r.PeersRemoved {
		delete(c.peers, id)
	}

	for _, pc := range r.PeersChangedPatch {
		p := c.peers[pc.NodeID]
		if p == nil {
			continue
		}

		if pc.DERPRegion != 0 {
			p.HomeDERP = pc.DERPRegion
		}

		if pc.Endpoints != nil {
			p.Endpoints = pc.Endpoints
		}

		if pc.Key != nil {
			p.Key = *pc.Key
		}

		if pc.DiscoKey != nil {
			p.DiscoKey = *pc.DiscoKey
		}

		if pc.Online != nil {
			p.Online = new(*pc.Online)
			// The client keeps a LastSeen the patch cannot clear; compare
			// what it acts on.
			if *pc.Online {
				p.LastSeen = nil
			}
		}

		if pc.LastSeen != nil {
			p.LastSeen = new(*pc.LastSeen)
		}

		if pc.KeyExpiry != nil {
			p.KeyExpiry = *pc.KeyExpiry
		}

		if pc.CapMap != nil {
			p.CapMap = pc.CapMap
		}
	}

	if f, ok := r.PacketFilters["base"]; ok {
		c.filter = f
	}
}

func keys(m map[tailcfg.NodeID]*tailcfg.Node) []tailcfg.NodeID {
	out := make([]tailcfg.NodeID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}

	return out
}

// BenchmarkStreamUpdateEndpointChurn measures one session's update after a
// tenth of its peers moved endpoints, the common write under load.
func BenchmarkStreamUpdateEndpointChurn(b *testing.B) {
	for _, n := range []int{100, 500} {
		b.Run(fmt.Sprintf("peers=%d", n), func(b *testing.B) {
			cfg, s := benchState(b, n)
			ids := s.ListNodes()
			viewer := ids.At(0).ID()

			st := NewStream(cfg, NewHub(), viewer, capVer)
			_, err := st.Initial(s.Snapshot())
			require.NoError(b, err)

			port := uint16(1)

			b.ReportAllocs()

			for b.Loop() {
				b.StopTimer()

				for i := 1; i < ids.Len(); i += 10 {
					n := ids.At(i).AsStruct()
					n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
					s.PutNodeInStoreForTest(*n)
				}

				port++

				b.StartTimer()

				_, err := st.Update(s.Snapshot())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchState(b *testing.B, n int) (*types.Config, *state.State) {
	b.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: b.TempDir() + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		ServerURL:    "https://headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(b, err)

	u := database.CreateUserForTest("u1")
	database.CreateRegisteredNodesForTest(u, n, "bench")
	require.NoError(b, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(b, err)
	b.Cleanup(func() { _ = s.Close() })

	return cfg, s
}

// BenchmarkStreamsUpdateEndpointChurn measures every session's update after
// a tenth of the nodes moved endpoints: the cost of one write burst across
// the tailnet.
func BenchmarkStreamsUpdateEndpointChurn(b *testing.B) {
	const n = 200

	cfg, s := benchState(b, n)
	ids := s.ListNodes()
	hub := NewHub()

	streams := make([]*Stream, 0, ids.Len())
	for _, nv := range ids.All() {
		st := NewStream(cfg, hub, nv.ID(), capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(b, err)

		streams = append(streams, st)
	}

	port := uint16(1)

	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()

		for i := 0; i < ids.Len(); i += 10 {
			n := ids.At(i).AsStruct()
			n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
			s.PutNodeInStoreForTest(*n)
		}

		port++
		snap := s.Snapshot()

		b.StartTimer()

		for _, st := range streams {
			_, err := st.Update(snap)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// TestStreamConvergesUnderRandomWrites drives random writes, most of them
// payload-only so renders take the change-log fast path, and checks after
// each that a long-lived stream's client equals a fresh stream's.
func TestStreamConvergesUnderRandomWrites(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	long := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := long.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])
	r := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // deterministic test input
	gens := map[types.NodeID]uint64{}

	for step := range 300 {
		id := ids[1+r.IntN(2)]
		nv, ok := s.GetNodeByID(id)

		switch op := r.IntN(10); {
		case !ok:
			// Deleted earlier; bring it back as a fresh node.
			u := s.CreateUserForTest(fmt.Sprintf("u-%d", step))
			ids[1] = s.CreateRegisteredNodeForTest(u, fmt.Sprintf("back-%d", step)).ID
		case op < 5:
			n := nv.AsStruct()
			n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(step))} //nolint:gosec // small
			s.PutNodeInStoreForTest(*n)
		case op < 7:
			if gen, ok := gens[id]; ok {
				_ = s.Disconnect(id, gen)
				delete(gens, id)
			} else {
				gens[id] = s.Connect(id)
			}
		case op < 8:
			_, _ = s.RenameNode(id, fmt.Sprintf("r%d", step))
		case op < 9:
			_, _ = s.SetPolicy([]byte(fmt.Sprintf(`{"acls":[{"action":"accept","src":["*"],"dst":["*:%d"]}]}`, 1+step%3)))
		default:
			require.NoError(t, s.DeleteNode(nv))
		}

		resps, err := long.Update(s.Snapshot())
		require.NoError(t, err)

		for _, resp := range resps {
			client.apply(resp)
		}

		fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
		require.NoError(t, err)

		want := newModelClient(fresh[0])
		require.True(t, reflect.DeepEqual(want.peers, client.peers),
			"step %d: long-lived peers %v, fresh %v", step, keys(client.peers), keys(want.peers))
		require.True(t, reflect.DeepEqual(want.filter, client.filter), "step %d: filter differs", step)
	}
}

// BenchmarkStreamsRetainedHeap reports the heap every session keeps per
// peer after a few updates: per-viewer state must stay a small constant
// per pair, and nothing may accumulate across renders.
func BenchmarkStreamsRetainedHeap(b *testing.B) {
	const n = 200

	cfg, s := benchState(b, n)
	ids := s.ListNodes()

	for b.Loop() {
		hub := NewHub()

		runtime.GC()

		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		streams := make([]*Stream, 0, ids.Len())
		for _, nv := range ids.All() {
			st := NewStream(cfg, hub, nv.ID(), capVer)
			_, err := st.Initial(s.Snapshot())
			require.NoError(b, err)

			streams = append(streams, st)
		}

		for round := range 10 {
			for i := round; i < ids.Len(); i += 10 {
				n := ids.At(i).AsStruct()
				n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(round))} //nolint:gosec // small
				s.PutNodeInStoreForTest(*n)
			}

			for _, st := range streams {
				_, err := st.Update(s.Snapshot())
				require.NoError(b, err)
			}
		}

		runtime.GC()

		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(n*n), "B/pair")
		runtime.KeepAlive(streams)
	}
}
