package mapper

import (
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
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
	self     *tailcfg.Node
	peers    map[tailcfg.NodeID]*tailcfg.Node
	filter   []tailcfg.FilterRule
	ssh      *tailcfg.SSHPolicy
	dns      *tailcfg.DNSConfig
	derp     *tailcfg.DERPMap
	profiles map[tailcfg.UserID]tailcfg.UserProfile
}

func newModelClient(full *tailcfg.MapResponse) *modelClient {
	c := &modelClient{
		peers:    make(map[tailcfg.NodeID]*tailcfg.Node),
		profiles: make(map[tailcfg.UserID]tailcfg.UserProfile),
	}
	c.apply(full)

	return c
}

func (c *modelClient) apply(r *tailcfg.MapResponse) {
	if r.Node != nil {
		c.self = r.Node.Clone()
	}

	if r.SSHPolicy != nil {
		c.ssh = r.SSHPolicy
	}

	if r.DNSConfig != nil {
		c.dns = r.DNSConfig
	}

	if r.DERPMap != nil {
		c.derp = r.DERPMap
	}

	// Clients keep every profile they were sent; the protocol has no
	// removal.
	for _, p := range r.UserProfiles {
		c.profiles[p.ID] = p
	}

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

// sameAs reports how c differs from fresh, a client that only saw a new
// session's full map, or "" when it does not. Profiles may be a superset.
func (c *modelClient) sameAs(fresh *modelClient) string {
	switch {
	case !reflect.DeepEqual(fresh.self, c.self):
		return "self"
	case !reflect.DeepEqual(fresh.peers, c.peers):
		return fmt.Sprintf("peers: have %v, want %v", keys(c.peers), keys(fresh.peers))
	case !reflect.DeepEqual(fresh.filter, c.filter):
		return "filter"
	case !reflect.DeepEqual(fresh.ssh, c.ssh):
		return "ssh"
	case !reflect.DeepEqual(fresh.dns, c.dns):
		return "dns"
	case !reflect.DeepEqual(fresh.derp, c.derp):
		return "derp"
	}

	for id, p := range fresh.profiles {
		if have, ok := c.profiles[id]; !ok || !reflect.DeepEqual(have, p) {
			return fmt.Sprintf("profile %d", id)
		}
	}

	return ""
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

// BenchmarkScalingOneEndpointWrite measures the total cost of one node
// moving its endpoint, every connected session included, across tailnet
// sizes: how the common write scales with N.
func BenchmarkScalingOneEndpointWrite(b *testing.B) {
	for _, n := range []int{100, 200, 400, 800} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			cfg, s := benchState(b, n)
			ids := s.ListNodes()
			hub := NewHub()

			streams := make([]*Stream, 0, n)

			for _, nv := range ids.All() {
				st := NewStream(cfg, hub, nv.ID(), capVer)
				_, err := st.Initial(s.Snapshot())
				require.NoError(b, err)

				streams = append(streams, st)
			}

			port := uint16(1)
			for b.Loop() {
				node := ids.At(int(port) % n).AsStruct()
				node.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
				s.PutNodeInStoreForTest(*node)

				port++

				snap := s.Snapshot()
				for _, st := range streams {
					_, err := st.Update(snap)
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// oracleSession is one long-lived session and the client it feeds.
type oracleSession struct {
	st     *Stream
	client *modelClient
}

// TestStreamsConvergeUnderRandomWrites drives random writes of every kind
// against a session per node and checks after each write that every
// session's client equals a fresh session's. Only the sessions [Route]
// names are updated, so a session it skips must already be up to date.
func TestStreamsConvergeUnderRandomWrites(t *testing.T) {
	for seed := range uint64(6) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			testStreamsConverge(t, rand.New(rand.NewPCG(seed, 6))) //nolint:gosec // deterministic test input
		})
	}
}

func testStreamsConverge(t *testing.T, r *rand.Rand) {
	t.Helper()

	cfg, s, _ := streamTestState(t, "")
	hub := NewHub()

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	// addNode registers a node in the database and in memory.
	addNode := func(name string) types.NodeID {
		n := s.CreateRegisteredNodeForTest(u1, name)
		s.PutNodeInStoreForTest(*n)

		return n.ID
	}

	for i := range 3 {
		addNode(fmt.Sprintf("extra-%d", i))
	}

	route := netip.MustParsePrefix("10.0.0.0/24")
	policies := []string{
		"",
		ownUserOnly,
		`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		  "acls":[{"action":"accept","src":["tag:a"],"dst":["tag:b:*"]},
		          {"action":"accept","src":["u1@"],"dst":["u1@:*","10.0.0.0/24:*"]}],
		  "ssh":[{"action":"accept","src":["u1@"],"dst":["tag:b"],"users":["root"]}]}`,
		`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
	}

	sessions := map[types.NodeID]*oracleSession{}
	open := func(id types.NodeID) {
		st := NewStream(cfg, hub, id, capVer)
		resps, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		c := newModelClient(resps[0])
		for _, resp := range resps[1:] {
			c.apply(resp)
		}

		sessions[id] = &oracleSession{st: st, client: c}
	}

	for _, nv := range s.ListNodes().All() {
		open(nv.ID())
	}

	// wake returns the sessions the write from last to snap reaches, as
	// the hub routes it.
	last := s.Snapshot()
	wake := func(snap *state.Snapshot) []types.NodeID {
		all, ids := Route(last, snap, snap.Since(last))
		last = snap

		var out []types.NodeID

		for id := range sessions {
			if _, ok := ids[id]; all || ok {
				out = append(out, id)
			}
		}

		return out
	}

	gens := map[types.NodeID]uint64{}

	for step := range 400 {
		nodes := s.ListNodes()
		nv := nodes.At(r.IntN(nodes.Len()))
		id := nv.ID()

		switch op := r.IntN(16); op {
		case 0, 1, 2:
			n := nv.AsStruct()
			n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(step))} //nolint:gosec // small
			s.PutNodeInStoreForTest(*n)
		case 3, 4:
			if gen, ok := gens[id]; ok {
				_ = s.Disconnect(id, gen)
				delete(gens, id)
			} else {
				gens[id] = s.Connect(id)
			}
		case 5:
			_, _ = s.RenameNode(id, fmt.Sprintf("r%d", step))
		case 6:
			_, _ = s.SetNodeTags(id, [][]string{nil, {"tag:a"}, {"tag:b"}, {"tag:a", "tag:b"}}[r.IntN(4)])
		case 7:
			n := nv.AsStruct()

			n.Hostinfo = n.Hostinfo.Clone()
			if n.Hostinfo == nil {
				n.Hostinfo = &tailcfg.Hostinfo{}
			}

			n.Hostinfo.RoutableIPs = []netip.Prefix{route}
			s.PutNodeInStoreForTest(*n)
			_, _ = s.SetApprovedRoutes(id, []netip.Prefix{route})
		case 8:
			_, _ = s.SetApprovedRoutes(id, nil)
		case 9:
			_ = s.SetNodeHealth(id, r.IntN(2) == 0)
		case 10:
			_, _ = s.SetPolicy([]byte(policies[r.IntN(len(policies))]))
		case 11:
			s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
				tailcfg.DERPRegionID(900 + r.IntN(3)): {RegionID: tailcfg.DERPRegionID(900 + r.IntN(3))},
			}})
		case 12:
			s.SetExtraRecords([]tailcfg.DNSRecord{{Name: fmt.Sprintf("x%d.headscale.test", r.IntN(3)), Value: "100.64.0.99"}})
		case 13:
			expiry := time.Now().Add([]time.Duration{-time.Hour, time.Hour}[r.IntN(2)])
			_, _ = s.SetNodeExpiry(id, &expiry)
		case 14:
			users, err := s.ListAllUsers()
			require.NoError(t, err)

			u := users[r.IntN(len(users))]
			_, err = s.RenameUser(types.UserID(u.ID), fmt.Sprintf("user-%d", step))
			require.NoError(t, err)
		case 15:
			if nodes.Len() > 3 {
				require.NoError(t, s.DeleteNode(nv))
				delete(gens, id)
			} else {
				open(addNode(fmt.Sprintf("new-%d", step)))
			}
		}

		snap := s.Snapshot()

		for _, id := range wake(snap) {
			sess := sessions[id]

			resps, err := sess.st.Update(snap)
			if errors.Is(err, ErrNodeGone) {
				delete(sessions, id)

				continue
			}

			require.NoError(t, err)

			for _, resp := range resps {
				sess.client.apply(resp)
			}
		}

		for id, sess := range sessions {
			fresh, err := NewStream(cfg, NewHub(), id, capVer).Initial(snap)
			require.NoError(t, err)

			if diff := sess.client.sameAs(newModelClient(fresh[0])); diff != "" {
				t.Fatalf("step %d: session %d differs from a fresh one: %s", step, id, diff)
			}
		}
	}
}

// scalingPolicies are the policy shapes the scaling benchmarks run under,
// for a tailnet of 10 users whose nodes, for "tags", carry one of 20 tags.
var scalingPolicies = map[string]string{
	"allow-all": "",
	"users": func() string {
		acls := make([]string, 0, 10)
		for u := range 10 {
			acls = append(acls, fmt.Sprintf(`{"action":"accept","src":["u%d@"],"dst":["u%d@:*"]}`, u, u))
		}

		return `{"acls":[` + strings.Join(acls, ",") + `]}`
	}(),
	"tags": func() string {
		owners, acls := make([]string, 0, 20), make([]string, 0, 20)
		for t := range 20 {
			owners = append(owners, fmt.Sprintf(`"tag:t%d":["u0@"]`, t))
			acls = append(acls, fmt.Sprintf(`{"action":"accept","src":["tag:t%d"],"dst":["tag:t%d:*"]}`, t, (t+1)%20))
		}

		return `{"tagOwners":{` + strings.Join(owners, ",") + `},"acls":[` + strings.Join(acls, ",") + `]}`
	}(),
	"self": `{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
}

// scalingTailnet returns a tailnet of n nodes spread over 10 users under
// the named policy shape, with a session for every node.
func scalingTailnet(b *testing.B, n int, shape string) (*state.State, []*Stream) {
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

	users := database.CreateUsersForTest(10, "u")
	for i, u := range users {
		database.CreateRegisteredNodesForTest(u, n/10+min(1, max(0, n%10-i)), u.Name)
	}

	require.NoError(b, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(b, err)
	b.Cleanup(func() { _ = s.Close() })

	// CreateUsersForTest names users "u-0"; the policies say "u0@".
	for i, u := range users {
		_, err := s.RenameUser(types.UserID(u.ID), fmt.Sprintf("u%d", i))
		require.NoError(b, err)
	}

	if shape == "tags" {
		for i, nv := range s.ListNodes().All() {
			node := nv.AsStruct()
			node.Tags = []string{fmt.Sprintf("tag:t%d", i%20)}
			s.PutNodeInStoreForTest(*node)
		}
	}

	_, err = s.SetPolicy([]byte(scalingPolicies[shape]))
	require.NoError(b, err)

	hub := NewHub()
	streams := make([]*Stream, 0, n)

	for _, nv := range s.ListNodes().All() {
		st := NewStream(cfg, hub, nv.ID(), capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(b, err)

		streams = append(streams, st)
	}

	return s, streams
}

// scalingWrites are the writes the scaling benchmarks measure; each makes
// one change through State, given the iteration number.
var scalingWrites = map[string]func(b *testing.B, s *state.State, i int){
	"endpoint": func(_ *testing.B, s *state.State, i int) {
		nodes := s.ListNodes()
		node := nodes.At(i % nodes.Len()).AsStruct()
		node.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i))} //nolint:gosec // small
		s.PutNodeInStoreForTest(*node)
	},
	"online": func(_ *testing.B, s *state.State, i int) {
		nodes := s.ListNodes()
		nv := nodes.At(i % nodes.Len())

		if nv.IsOnline().Valid() && nv.IsOnline().Get() {
			_ = s.Disconnect(nv.ID(), nv.SessionEpoch())
		} else {
			_ = s.Connect(nv.ID())
		}
	},
	"rejoin": func(_ *testing.B, s *state.State, i int) {
		nodes := s.ListNodes()
		node := nodes.At(i % nodes.Len()).AsStruct()
		s.DeleteNodeFromStoreForTest(node.ID)
		s.PutNodeInStoreForTest(*node)
	},
	"rename": func(b *testing.B, s *state.State, i int) {
		b.Helper()

		nodes := s.ListNodes()
		_, err := s.RenameNode(nodes.At(i%nodes.Len()).ID(), fmt.Sprintf("renamed-%d", i))
		require.NoError(b, err)
	},
	"policy": func(b *testing.B, s *state.State, i int) {
		b.Helper()

		_, err := s.SetPolicy([]byte(fmt.Sprintf(`{"acls":[{"action":"accept","src":["*"],"dst":["*:%d"]}]}`, 1+i%2)))
		require.NoError(b, err)
	},
	"derp": func(_ *testing.B, s *state.State, i int) {
		s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			tailcfg.DERPRegionID(900 + i%2): {RegionID: tailcfg.DERPRegionID(900 + i%2)},
		}})
	},
}

// BenchmarkScalingWrites measures one write and the updates of the
// sessions the hub routes it to, across write kinds, policy shapes and
// tailnet sizes. woken/op counts the sessions routed, updates/op those
// with something to send: the work a write needs. peer-renders/op counts
// the peers they rendered.
func BenchmarkScalingWrites(b *testing.B) {
	sizes := []int{100, 400, 1000}
	if testing.Short() {
		sizes = []int{100}
	}

	for _, kind := range slices.Sorted(maps.Keys(scalingWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			for _, n := range sizes {
				b.Run(fmt.Sprintf("%s/%s/nodes=%d", kind, shape, n), func(b *testing.B) {
					s, streams := scalingTailnet(b, n, shape)
					write := scalingWrites[kind]

					var i, updates, rendered, woken int

					last := s.Snapshot()

					for b.Loop() {
						write(b, s, i)
						i++

						snap := s.Snapshot()
						all, wake := Route(last, snap, snap.Since(last))
						last = snap

						for _, st := range streams {
							if _, ok := wake[st.nodeID]; !all && !ok {
								continue
							}

							woken++
							before := st.r.rendered

							out, err := st.Update(snap)
							if err != nil {
								b.Fatal(err)
							}

							if len(out) > 0 {
								updates++
							}

							rendered += st.r.rendered - before
						}
					}

					b.ReportMetric(float64(woken)/float64(i), "woken/op")
					b.ReportMetric(float64(updates)/float64(i), "updates/op")
					b.ReportMetric(float64(rendered)/float64(i), "peer-renders/op")
				})
			}
		}
	}
}

// TestRouteWakesNewPrimary fails over a route between two routers that
// cannot see each other: the one taking the route did not change, and no
// node it sees changed, yet its own map now carries the route.
func TestRouteWakesNewPrimary(t *testing.T) {
	_, s, ids := streamTestState(t, `{"acls":[{"action":"accept","src":["u2@"],"dst":["u1@:*","10.0.0.0/24:*"]}]}`)
	r1, r2 := ids[0], ids[1]

	route := netip.MustParsePrefix("10.0.0.0/24")
	gens := map[types.NodeID]uint64{}

	for _, id := range []types.NodeID{r1, r2} {
		n := mustNode(t, s, id).AsStruct()
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		s.PutNodeInStoreForTest(*n)

		_, err := s.SetApprovedRoutes(id, []netip.Prefix{route})
		require.NoError(t, err)

		gens[id] = s.Connect(id)
	}

	require.NotContains(t, s.Snapshot().PeerIDs(r1), r2, "the routers must not see each other")

	before := s.Snapshot()
	primary, _ := before.PrimaryRouteFor(route)
	require.Equal(t, r1, primary)

	require.NoError(t, s.Disconnect(r1, gens[r1]))

	after := s.Snapshot()
	primary, _ = after.PrimaryRouteFor(route)
	require.Equal(t, r2, primary)

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all)
	assert.Contains(t, wake, r2, "the new primary's own map changed")
}
