package mapper

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/zstdframe"
)

const capVer = tailcfg.CurrentCapabilityVersion

// streamTestState returns a State with users u1, u2 and nodes n1, n1b
// (u1) and n2 (u2), under policy (allow-all when empty).
func streamTestState(tb testing.TB, policy string, configure ...func(*types.Config)) (*types.Config, *state.State, [3]types.NodeID) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		ServerURL:    "https://headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
	}

	for _, f := range configure {
		f(cfg)
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	u1 := database.CreateUserForTest("u1")
	u2 := database.CreateUserForTest("u2")
	n1 := database.CreateRegisteredNodeForTest(u1, "n1")
	n1b := database.CreateRegisteredNodeForTest(u1, "n1b")
	n2 := database.CreateRegisteredNodeForTest(u2, "n2")
	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = s.Close() })

	s.SetDERPMap(&tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
	})

	if policy != "" {
		_, err = s.SetPolicy([]byte(policy))
		require.NoError(tb, err)
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

	first := NewStream(cfg, hub, ids[0], capVer)
	_, err := first.Initial(s.Snapshot())
	require.NoError(t, err)
	first.Delivered()

	// n1 is offline while n1b is deleted.
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	resps, err := NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, resps, 2, "full map, then the removal it missed")
	assert.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, resps[1].PeersRemoved)
	assert.NotNil(t, resps[1].ControlTime, "every response carries a control time")
}

// TestStreamRemovalSurvivesFailedWrite deletes a peer and loses the frames
// announcing it, first the initial map's and then an update's: the next
// session must still send the removal, since the client never got it.
func TestStreamRemovalSurvivesFailedWrite(t *testing.T) {
	removed := func(resps []*tailcfg.MapResponse) []tailcfg.NodeID {
		var out []tailcfg.NodeID
		for _, r := range resps {
			out = append(out, r.PeersRemoved...)
		}

		return out
	}

	t.Run("initial map lost", func(t *testing.T) {
		cfg, s, ids := streamTestState(t, "")
		hub := NewHub()

		first := NewStream(cfg, hub, ids[0], capVer)
		_, err := first.Initial(s.Snapshot())
		require.NoError(t, err)
		first.Delivered()

		require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

		// This session's frames, the removal among them, never arrive.
		resps, err := NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
		require.NoError(t, err)
		require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, removed(resps))

		resps, err = NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
		require.NoError(t, err)
		assert.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, removed(resps), "the removal was never delivered")
	})

	t.Run("update lost", func(t *testing.T) {
		cfg, s, ids := streamTestState(t, "")
		hub := NewHub()

		st := NewStream(cfg, hub, ids[0], capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		st.Delivered()

		require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

		// The update carrying the removal fails to write; the session ends.
		resps, err := st.Update(s.Snapshot())
		require.NoError(t, err)
		require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, removed(resps))

		for _, r := range resps {
			assert.NotNil(t, r.ControlTime, "every response carries a control time")
		}

		resps, err = NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
		require.NoError(t, err)
		assert.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, removed(resps), "the removal was never delivered")
	})
}

// TestStreamHistoryIgnoresStaleDelivery has two sessions of one node: the
// old one is blocked writing an old map while the new one delivers a newer
// one, then the old write finishes. The node's history must keep the newer
// view, or a later reconnect would announce no removals it missed.
func TestStreamHistoryIgnoresStaleDelivery(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()

	old := NewStream(cfg, hub, ids[0], capVer)
	_, err := old.Initial(s.Snapshot())
	require.NoError(t, err)

	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	cur := NewStream(cfg, hub, ids[0], capVer)
	_, err = cur.Initial(s.Snapshot())
	require.NoError(t, err)
	cur.Delivered()

	// The old session's blocked write, of the map that still had ids[1],
	// lands last.
	old.Delivered()

	assert.NotContains(t, hub.lastPeers(ids[0]), ids[1], "a stale delivery must not roll the history back")
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

	// seen holds every user the client was ever shown as an owner, of
	// itself or a peer: the only users whose profiles it may hold.
	seen map[tailcfg.UserID]bool

	// deltaPeers is the peer set of a consumer that learns removals only
	// from PeersRemoved: a peer dropped without one stays here.
	deltaPeers map[tailcfg.NodeID]bool
}

func newModelClient(full *tailcfg.MapResponse) *modelClient {
	c := &modelClient{
		peers:    make(map[tailcfg.NodeID]*tailcfg.Node),
		profiles: make(map[tailcfg.UserID]tailcfg.UserProfile),
		seen:     make(map[tailcfg.UserID]bool),

		deltaPeers: make(map[tailcfg.NodeID]bool),
	}
	c.apply(full)

	return c
}

// unseenProfile returns a profile the client holds for a user it was
// never shown as an owner, or 0: a peer the policy hides must not leak
// its owner. Profiles of users seen once stay, as clients keep them.
func (c *modelClient) unseenProfile() tailcfg.UserID {
	for id := range c.profiles {
		if !c.seen[id] {
			return id
		}
	}

	return 0
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

	for _, p := range slices.Concat(r.Peers, r.PeersChanged) {
		c.deltaPeers[p.ID] = true
	}

	for _, id := range r.PeersRemoved {
		delete(c.deltaPeers, id)
	}

	// A full map's peer list, even an empty one, replaces the client's.
	if r.Peers != nil {
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

	defer func() {
		if c.self != nil {
			c.seen[c.self.User] = true
		}

		for _, p := range c.peers {
			c.seen[p.User] = true
		}
	}()

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

func TestStreamReusesRoutedPeerOnEndpointChange(t *testing.T) {
	for _, tt := range []struct {
		name   string
		route  string
		online bool
	}{
		{"subnet", "10.0.0.0/24", true},
		{"offline-exit", "0.0.0.0/0", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")
			route := netip.MustParsePrefix(tt.route)
			router := mustNode(t, s, ids[1]).AsStruct()
			router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			router.ApprovedRoutes = []netip.Prefix{route}
			s.PutNodeInStoreForTest(*router)

			if tt.online {
				s.Connect(router.ID)
			}

			st := NewStream(cfg, NewHub(), ids[0], capVer)
			_, err := st.Initial(s.Snapshot())
			require.NoError(t, err)

			before, ok := st.sent.peer(router.ID.NodeID())
			require.True(t, ok)
			require.Contains(t, before.AllowedIPs, route)

			rendered := st.r.rendered

			n := mustNode(t, s, ids[2]).AsStruct()
			n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}
			s.PutNodeInStoreForTest(*n)

			resps, err := st.Update(s.Snapshot())
			require.NoError(t, err)

			after, ok := st.sent.peer(router.ID.NodeID())
			require.True(t, ok)
			assert.Same(t, before, after, "an unrelated endpoint must keep the routed peer's render")
			assert.Equal(t, 1, st.r.rendered-rendered)
			assert.True(t, mentions(resps, ids[2]))
			assert.False(t, mentions(resps, router.ID))
		})
	}
}

func TestStreamRouteOverlaysTrackInputs(t *testing.T) {
	usersOnly := `{"acls":[{"action":"accept","src":["u1@","u2@"],"dst":["u1@:*","u2@:*"]}]}`
	cfg, s, ids := streamTestState(t, usersOnly)
	viewer, router, backup := ids[0], ids[1], ids[2]
	route := netip.MustParsePrefix("10.0.0.0/24")

	for _, id := range []types.NodeID{router, backup} {
		n := mustNode(t, s, id).AsStruct()
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
		s.PutNodeInStoreForTest(*n)
	}

	gen := s.Connect(router)
	s.Connect(backup)

	st := NewStream(cfg, NewHub(), viewer, capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])

	check := func(primary types.NodeID) {
		t.Helper()

		resps, err := st.Update(s.Snapshot())
		require.NoError(t, err)

		for _, resp := range resps {
			client.apply(resp)
		}

		for _, id := range []types.NodeID{router, backup} {
			p, ok := st.sent.peer(id.NodeID())
			require.True(t, ok)

			if id == primary {
				assert.Equal(t, []netip.Prefix{route}, p.PrimaryRoutes)
				assert.Contains(t, p.AllowedIPs, route)
			} else {
				assert.Empty(t, p.PrimaryRoutes)
				assert.NotContains(t, p.AllowedIPs, route)
			}
		}

		if primary == 0 {
			assert.Same(t, st.r.lastClass, st.sent.peers, "losing all route overlays restores the shared class map")
		}

		fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(s.Snapshot())
		require.NoError(t, err)
		require.Empty(t, client.sameAs(newModelClient(fresh[0])))
	}

	check(0)

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	check(router)
	require.NoError(t, s.Disconnect(router, gen))
	check(backup)

	_, err = s.SetPolicy([]byte(usersOnly))
	require.NoError(t, err)
	check(0)

	n := mustNode(t, s, viewer).AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	n.ApprovedRoutes = []netip.Prefix{route}
	s.PutNodeInStoreForTest(*n)
	check(backup)

	n.ApprovedRoutes = nil
	s.PutNodeInStoreForTest(*n)
	check(0)

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	check(backup)
	n = mustNode(t, s, backup).AsStruct()
	n.ApprovedRoutes = nil
	s.PutNodeInStoreForTest(*n)
	check(0)
}

func TestStreamRouteOverlaysFollowPeerVisibility(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	route := netip.MustParsePrefix("10.0.0.0/24")
	router := mustNode(t, s, ids[2]).AsStruct()
	router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	router.ApprovedRoutes = []netip.Prefix{route}
	s.PutNodeInStoreForTest(*router)
	s.Connect(router.ID)

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])

	for _, policy := range []string{ownUserOnly, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`} {
		_, err := s.SetPolicy([]byte(policy))
		require.NoError(t, err)
		resps, err := st.Update(s.Snapshot())
		require.NoError(t, err)

		for _, resp := range resps {
			client.apply(resp)
		}

		peer, visible := st.sent.peer(router.ID.NodeID())
		if policy == ownUserOnly {
			require.False(t, visible, "the old overlay must leave with the peer")
		} else {
			require.True(t, visible)
			require.Contains(t, peer.AllowedIPs, route)
		}

		fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
		require.NoError(t, err)
		require.Empty(t, client.sameAs(newModelClient(fresh[0])))
	}
}

// BenchmarkRoutedRender measures one endpoint update with unrelated routers,
// including invisible routers whose routes never belong to the viewer.
func BenchmarkRoutedRender(b *testing.B) {
	for _, visible := range []bool{false, true} {
		for _, routers := range []int{0, 100, 1000} {
			b.Run(fmt.Sprintf("visible=%t/routers=%d", visible, routers), func(b *testing.B) {
				cfg, s := benchState(b, routers+2)

				nodes := s.ListNodes()
				for j := 2; j < nodes.Len(); j++ {
					n := nodes.At(j).AsStruct()
					p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(j >> 8), byte(j), 0}), 24) //nolint:gosec // bounded by 1002 nodes
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{p}}
					n.ApprovedRoutes = []netip.Prefix{p}
					s.PutNodeInStoreForTest(*n)
				}

				if !visible {
					p := fmt.Sprintf(`{"acls":[{"action":"accept","src":["%s"],"dst":["%s:22"]}]}`, nodes.At(0).IPs()[0], nodes.At(1).IPs()[0])
					_, err := s.SetPolicy([]byte(p))
					require.NoError(b, err)
				}

				st := NewStream(cfg, NewHub(), nodes.At(0).ID(), capVer)
				_, err := st.Initial(s.Snapshot())
				require.NoError(b, err)

				port := uint16(1)

				b.ReportAllocs()

				for b.Loop() {
					b.StopTimer()

					n := nodes.At(1).AsStruct()
					n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
					port++

					s.PutNodeInStoreForTest(*n)
					snap := s.Snapshot()

					b.StartTimer()

					_, err := st.Update(snap)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
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
	for _, n := range []int{200, 1000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) { benchRetainedHeap(b, n) })
	}
}

func benchRetainedHeap(b *testing.B, n int) {
	b.Helper()

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
	// capVer is what the client speaks; sessions mix the newest and the
	// oldest supported.
	capVer tailcfg.CapabilityVersion
	// down is set while the client is disconnected after a failed write;
	// it reconnects at a later write.
	down bool
}

// TestStreamsConvergeUnderRandomWrites drives random writes of every kind
// against a session per node and checks after each write that every
// session's client equals a fresh session's. Only the sessions [Route]
// names are updated, so a session it skips must already be up to date.
func TestStreamsConvergeUnderRandomWrites(t *testing.T) {
	// Every recompile is checked against a compile from scratch too.
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := state.PolicyAuditFailures()

	var reach oracleReach

	for seed := range uint64(6) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			got := testStreamsConverge(t, rand.New(rand.NewPCG(seed, 6))) //nolint:gosec // deterministic test input
			reach.via += got.via
			reach.exit += got.exit
			reach.autoApproved += got.autoApproved
			reach.keysRotated += got.keysRotated
			reach.minCapVer += got.minCapVer
		})
	}

	require.Equal(t, failures, state.PolicyAuditFailures(), "incremental compiles must match compiles from scratch")

	// A shape the seeds never reach tests nothing.
	require.NotZero(t, reach.via, "a via route served at some step")
	require.NotZero(t, reach.exit, "an exit route served to a client at some step")
	require.NotZero(t, reach.autoApproved, "a route auto-approved at some step")
	require.NotZero(t, reach.keysRotated, "a node's keys rotated at some step")
	require.NotZero(t, reach.minCapVer, "a session at the oldest supported capability version")
}

// oracleReach counts how often the oracle reached the shapes its writes
// and policies are there for.
type oracleReach struct {
	via, exit, autoApproved, keysRotated, minCapVer int
}

// testStreamsConverge runs one seed and returns what it reached, so the
// caller can tell every shape was exercised.
func testStreamsConverge(t *testing.T, r *rand.Rand) oracleReach {
	t.Helper()

	cfg, s, _ := streamTestState(t, "")
	hub := NewHub()

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	u2, err := s.GetUserByName("u2")
	require.NoError(t, err)

	// addNode registers a node in the database and in memory, for u1 and
	// u2 in turn, so rules naming either keep members to resolve to.
	added := 0
	addNode := func(name string) types.NodeID {
		owner := []*types.User{u1, u2}[added%2]
		added++

		n := s.CreateRegisteredNodeForTest(owner, name)

		// Loaded as registration and boot do, as the user is now (it may
		// have been renamed); user aliases match by it.
		cur, err := s.GetUserByID(types.UserID(owner.ID))
		require.NoError(t, err)

		n.User = cur
		s.PutNodeInStoreForTest(*n)

		return n.ID
	}

	for i := range 3 {
		addNode(fmt.Sprintf("extra-%d", i))
	}

	route := netip.MustParsePrefix("10.0.0.0/24")

	// One tag:a router of the route from the start, so the via policy has
	// a router to steer to whenever it is picked; writes may untag it.
	router := s.CreateRegisteredNodeForTest(u1, "router")
	router.Tags = []string{"tag:a"}
	router.UserID, router.User = nil, nil
	router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	router.ApprovedRoutes = []netip.Prefix{route}
	s.PutNodeInStoreForTest(*router)

	policies := []string{
		"",
		ownUserOnly,
		`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		  "acls":[{"action":"accept","src":["tag:a"],"dst":["tag:b:*"]},
		          {"action":"accept","src":["u1@"],"dst":["u1@:*","10.0.0.0/24:*"]}],
		  "ssh":[{"action":"accept","src":["u1@"],"dst":["tag:b"],"users":["root"]}]}`,
		`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
		`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		  "acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],
		  "ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]},
		         {"action":"check","src":["tag:a"],"dst":["tag:b"],"users":["autogroup:nonroot"]}]}`,
		// SSH alone connects u1 to tag:b, so only SSH wakes reach them.
		`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		  "acls":[{"action":"accept","src":["tag:a"],"dst":["tag:a:*"]}],
		  "ssh":[{"action":"accept","src":["u1@"],"dst":["tag:b"],"users":["root"]},
		         {"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}]}`,
		`{"nodeAttrs":[{"target":["u1@"],"attr":["disable-ipv4"]}],
		  "acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
		// These two differ only in u2 reaching the route: a viewer that
		// already sees the router gains or loses it with no peer set or
		// own filter change, so only the routed wake reaches it.
		`{"acls":[{"action":"accept","src":["u1@","u2@"],"dst":["u1@:*","u2@:*"]}]}`,
		`{"acls":[{"action":"accept","src":["u1@","u2@"],"dst":["u1@:*","u2@:*"]},
		          {"action":"accept","src":["u2@"],"dst":["10.0.0.0/24:*"]}]}`,
		// u2 reaches the route only through a tag:a router.
		`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		  "grants":[{"src":["u2@"],"dst":["10.0.0.0/24"],"ip":["*"],"via":["tag:a"]},
		            {"src":["*"],"dst":["*"],"ip":["*"]}]}`,
		// Exit routes are reachable through autogroup:internet only.
		`{"acls":[{"action":"accept","src":["u2@"],"dst":["autogroup:internet:*"]},
		          {"action":"accept","src":["u1@","u2@"],"dst":["u1@:*","u2@:*"]}]}`,
		`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		  "autoApprovers":{"routes":{"10.0.0.0/24":["tag:a"]},"exitNode":["tag:b"]},
		  "acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
		`{"hosts":{"lan":"10.0.0.0/24","h1":"100.64.0.1/32"},
		  "acls":[{"action":"accept","src":["u2@"],"dst":["lan:*","h1:22"]},
		          {"action":"accept","src":["u1@"],"dst":["u1@:*"]}]}`,
	}

	exitRoutes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

	var reach oracleReach

	sessions := map[types.NodeID]*oracleSession{}
	open := func(id types.NodeID) {
		cv := []tailcfg.CapabilityVersion{capVer, capver.MinSupportedCapabilityVersion}[r.IntN(2)]
		if cv == capver.MinSupportedCapabilityVersion {
			reach.minCapVer++
		}

		st := NewStream(cfg, hub, id, cv)
		resps, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		for _, resp := range resps {
			requireSameEncoding(t, resp)
		}

		c := newModelClient(resps[0])
		for _, resp := range resps[1:] {
			c.apply(resp)
		}

		st.Delivered()

		sessions[id] = &oracleSession{st: st, client: c, capVer: cv}
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

	o := &oracleRun{
		t: t, r: r, s: s, gens: gens, policies: policies,
		route: route, exitRoutes: exitRoutes, router: router,
		u1: u1, u2: u2, open: open, addNode: addNode, reach: &reach,
	}

	for step := range 400 {
		nodes := s.ListNodes()
		nv := nodes.At(r.IntN(nodes.Len()))
		id := nv.ID()

		o.write(step, nodes, nv, id)

		snap := s.Snapshot()

		advanceOracleSessions(t, r, cfg, hub, snap, wake(snap), sessions)
		requireOracleConverged(t, step, cfg, snap, sessions)

		if servesVia(snap) {
			reach.via++
		}

		if servesExit(sessions) {
			reach.exit++
		}
	}

	return reach
}

// oracleRun holds what the oracle's writes act on.
type oracleRun struct {
	t          *testing.T
	r          *rand.Rand
	s          *state.State
	gens       map[types.NodeID]uint64
	policies   []string
	route      netip.Prefix
	exitRoutes []netip.Prefix
	router     *types.Node
	u1, u2     *types.User
	open       func(types.NodeID)
	addNode    func(string) types.NodeID
	reach      *oracleReach
}

// write applies one random write to nv, at step, of the kinds a real
// server sees.
func (o *oracleRun) write(step int, nodes views.Slice[types.NodeView], nv types.NodeView, id types.NodeID) {
	t, r, s, gens, policies := o.t, o.r, o.s, o.gens, o.policies
	route, exitRoutes, router, u1, u2 := o.route, o.exitRoutes, o.router, o.u1, o.u2
	open, addNode := o.open, o.addNode

	switch op := r.IntN(19); op {
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

		routes := []netip.Prefix{route}
		if r.IntN(3) == 0 {
			routes = exitRoutes
		}

		n.Hostinfo.RoutableIPs = routes
		s.PutNodeInStoreForTest(*n)
		_, _ = s.SetApprovedRoutes(id, routes)
	case 8:
		_, _ = s.SetApprovedRoutes(id, nil)
	case 9:
		_ = s.SetNodeHealth(id, r.IntN(2) == 0)
	case 10:
		pol := policies[r.IntN(len(policies))]

		// The via policy needs its router, route and source user;
		// other writes keep changing them once it is live.
		if strings.Contains(pol, `"via"`) {
			for _, u := range []*types.User{u1, u2} {
				_, _ = s.RenameUser(types.UserID(u.ID), u.Name)
			}

			rn := mustNode(t, s, router.ID).AsStruct()
			rn.Tags, rn.UserID, rn.User = []string{"tag:a"}, nil, nil
			rn.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			rn.ApprovedRoutes = []netip.Prefix{route}
			s.PutNodeInStoreForTest(*rn)
		}

		_, _ = s.SetPolicy([]byte(pol))
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

		// A rename and its undo in turn: the policies name u1 and u2,
		// so a rename for good would leave them naming nobody.
		u := users[r.IntN(len(users))]

		name := u.Name + "-renamed"
		if base, ok := strings.CutSuffix(u.Name, "-renamed"); ok {
			name = base
		}

		_, err = s.RenameUser(types.UserID(u.ID), name)
		require.NoError(t, err)
	case 17:
		// A key rotation: peers must learn the new keys.
		n := nv.AsStruct()
		n.NodeKey, n.DiscoKey = key.NewNode().Public(), key.NewDisco().Public()
		s.PutNodeInStoreForTest(*n)

		o.reach.keysRotated++
	case 18:
		// Routes announced, approved only by what the policy allows.
		n := nv.AsStruct()

		n.Hostinfo = n.Hostinfo.Clone()
		if n.Hostinfo == nil {
			n.Hostinfo = &tailcfg.Hostinfo{}
		}

		n.Hostinfo.RoutableIPs = append([]netip.Prefix{route}, exitRoutes...)
		require.NoError(t, s.AutoApproveRoutes(s.PutNodeInStoreForTest(*n)))

		if mustNode(t, s, id).ApprovedRoutes().Len() > nv.ApprovedRoutes().Len() {
			o.reach.autoApproved++
		}
	case 16:
		// A map request stamping LastSeen, online or not.
		n := nv.AsStruct()
		n.LastSeen = new(time.Unix(int64(1_700_000_000+step), 0))
		s.PutNodeInStoreForTest(*n)
	case 15:
		// Every user keeps a node of its own, so rules naming it
		// keep resolving to someone, and the router stays.
		own := nv.IsTagged() || s.Snapshot().ListNodesByUser(nv.TypedUserID()).Len() > 1
		if nodes.Len() > 3 && own && nv.ID() != router.ID {
			require.NoError(t, s.DeleteNode(nv))
			delete(gens, id)
		} else {
			open(addNode(fmt.Sprintf("new-%d", step)))
		}
	}
}

// servesExit reports whether any client holds a peer offering an exit
// route.
func servesExit(sessions map[types.NodeID]*oracleSession) bool {
	for _, sess := range sessions {
		for _, p := range sess.client.peers {
			if slices.ContainsFunc(p.AllowedIPs, tsaddr.IsExitRoute) {
				return true
			}
		}
	}

	return false
}

// servesVia reports whether any node gets a route through a via grant.
func servesVia(snap *state.Snapshot) bool {
	nodes := snap.ListNodes()
	for _, viewer := range nodes.All() {
		for _, peer := range nodes.All() {
			if len(snap.Policy().ViaRoutesForPeer(viewer, peer).Include) > 0 {
				return true
			}
		}
	}

	return false
}

// advanceOracleSessions brings the sessions to snap: the woken ones take
// an update, down ones reconnect now and then, and those of deleted nodes
// end.
func advanceOracleSessions(
	t *testing.T,
	r *rand.Rand,
	cfg *types.Config,
	hub *Hub,
	snap *state.Snapshot,
	wake []types.NodeID,
	sessions map[types.NodeID]*oracleSession,
) {
	t.Helper()

	woken := map[types.NodeID]bool{}
	for _, id := range wake {
		woken[id] = true
	}

	// In ID order, so a seed replays the same draws.
	for _, id := range slices.Sorted(maps.Keys(sessions)) {
		sess := sessions[id]
		if _, live := snap.GetNode(id); !live {
			delete(sessions, id)

			continue
		}

		switch {
		case sess.down && r.IntN(4) == 0:
			// The reconnect's initial map fails part way: the client got
			// a prefix of it, and stays down.
			st := NewStream(cfg, hub, id, sess.capVer)

			resps, err := st.Initial(snap)
			require.NoError(t, err)

			for _, resp := range resps[:r.IntN(len(resps)+1)] {
				sess.client.apply(resp)
			}
		case sess.down && r.IntN(2) == 0:
			sess.st = reconnectOracleSession(t, cfg, hub, snap, id, sess.capVer, sess.client)
			sess.down = false
		case !sess.down && woken[id]:
			deliverOracleUpdate(t, r, cfg, hub, snap, id, sess)
		}
	}
}

// deliverOracleUpdate updates sess at snap and applies it to the client.
// Now and then the write fails part way and the client goes down, to
// reconnect at a later write; now and then a second session of the node
// takes over while the first is blocked, and the old one's write lands
// after the new one's.
func deliverOracleUpdate(
	t *testing.T,
	r *rand.Rand,
	cfg *types.Config,
	hub *Hub,
	snap *state.Snapshot,
	id types.NodeID,
	sess *oracleSession,
) {
	t.Helper()

	resps, err := sess.st.Update(snap)
	require.NoError(t, err)

	for _, resp := range resps {
		requireSameEncoding(t, resp)
	}

	switch r.IntN(10) {
	case 0:
		// The write fails after a prefix: the client got those frames,
		// the session ends unconfirmed, and the client reconnects.
		for _, resp := range resps[:r.IntN(len(resps)+1)] {
			sess.client.apply(resp)
		}

		sess.down = true
	case 1:
		// A new session takes over while this one's write is blocked;
		// the blocked write finishes after the new session's.
		stale := sess.st
		sess.st = reconnectOracleSession(t, cfg, hub, snap, id, sess.capVer, sess.client)

		stale.Delivered()
	default:
		for _, resp := range resps {
			sess.client.apply(resp)
		}

		sess.st.Delivered()
	}
}

// reconnectOracleSession opens a new session for id at snap and applies
// its initial frames to client, as a reconnecting client receives them.
func reconnectOracleSession(
	t *testing.T,
	cfg *types.Config,
	hub *Hub,
	snap *state.Snapshot,
	id types.NodeID,
	cv tailcfg.CapabilityVersion,
	client *modelClient,
) *Stream {
	t.Helper()

	st := NewStream(cfg, hub, id, cv)

	resps, err := st.Initial(snap)
	require.NoError(t, err)

	for _, resp := range resps {
		requireSameEncoding(t, resp)
		client.apply(resp)
	}

	st.Delivered()

	return st
}

// requireOracleConverged checks every session's client equals a fresh
// render at snap and holds no profile of a user it was never shown.
func requireOracleConverged(t *testing.T, step int, cfg *types.Config, snap *state.Snapshot, sessions map[types.NodeID]*oracleSession) {
	t.Helper()

	for _, id := range slices.Sorted(maps.Keys(sessions)) {
		sess := sessions[id]
		if sess.down {
			continue
		}

		fresh, err := NewStream(cfg, NewHub(), id, sess.capVer).Initial(snap)
		require.NoError(t, err)

		if diff := sess.client.sameAs(newModelClient(fresh[0])); diff != "" {
			t.Fatalf("step %d: session %d differs from a fresh one: %s", step, id, diff)
		}

		if u := sess.client.unseenProfile(); u != 0 {
			t.Fatalf("step %d: session %d holds the profile of user %d, never visible to it", step, id, u)
		}

		for p := range sess.client.deltaPeers {
			if _, ok := sess.client.peers[p]; !ok {
				t.Fatalf("step %d: session %d was never told peer %d was removed", step, id, p)
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
	// hidden flips the health of a node without routes, which no client
	// is sent.
	"hidden": func(_ *testing.B, s *state.State, i int) {
		nodes := s.ListNodes()
		_ = s.SetNodeHealth(nodes.At(i%nodes.Len()).ID(), i%2 == 0)
	},
	"derp": func(_ *testing.B, s *state.State, i int) {
		s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			tailcfg.DERPRegionID(900 + i%2): {RegionID: tailcfg.DERPRegionID(900 + i%2)},
		}})
	},
}

// BenchmarkScalingWrites measures one write and the updates, encoded, of
// the sessions the hub routes it to, across write kinds, policy shapes and
// tailnet sizes. woken/op counts the sessions routed, updates/op those
// with something to send: the work a write needs. peer-renders/op counts
// the peers they rendered.
func BenchmarkScalingWrites(b *testing.B) {
	sizes := []int{100, 400, 1000}
	if testing.Short() {
		sizes = []int{100}
	}

	// HEADSCALE_SCALE_NODES runs one size instead, such as 10000.
	if v, ok := os.LookupEnv("HEADSCALE_SCALE_NODES"); ok {
		n, err := strconv.Atoi(v)
		require.NoError(b, err)

		sizes = []int{n}
	}

	for _, kind := range slices.Sorted(maps.Keys(scalingWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			for _, n := range sizes {
				b.Run(fmt.Sprintf("%s/%s/nodes=%d", kind, shape, n), func(b *testing.B) {
					s, streams := scalingTailnet(b, n, shape)
					write := scalingWrites[kind]

					var i, updates, rendered, woken int

					byNode := make(map[types.NodeID]*Stream, len(streams))
					for _, st := range streams {
						byNode[st.nodeID] = st
					}

					last := s.Snapshot()

					for b.Loop() {
						write(b, s, i)
						i++

						snap := s.Snapshot()
						all, wake := Route(last, snap, snap.Since(last))
						last = snap

						// Visit the woken sessions only, as the hub does.
						targets := streams
						if !all {
							targets = targets[:0:0]

							for id := range wake {
								if st, ok := byNode[id]; ok {
									targets = append(targets, st)
								}
							}
						}

						for _, st := range targets {
							woken++
							before := st.r.rendered

							out, err := st.Update(snap)
							if err != nil {
								b.Fatal(err)
							}

							if len(out) > 0 {
								updates++
							}

							for _, resp := range out {
								_, err := st.hub.Encode(resp, true, benchEncode)
								if err != nil {
									b.Fatal(err)
								}
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

	require.NotContains(t, s.Snapshot().ListPeerIDs(r1), r2, "the routers must not see each other")

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

// TestSharedFramesEncodeOnceAndIdentically has every session of an
// allow-all tailnet take one endpoint write, and checks the sessions send
// the same response, encoded once, to the bytes a direct encode gives.
func TestSharedFramesEncodeOnceAndIdentically(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()

	streams := map[types.NodeID]*Stream{}

	for _, id := range ids {
		st := NewStream(cfg, hub, id, capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		streams[id] = st
	}

	_ = s.Connect(ids[2])
	snap := s.Snapshot()

	var shared *tailcfg.MapResponse

	for _, id := range ids[:2] {
		resps, err := streams[id].Update(snap)
		require.NoError(t, err)
		require.Len(t, resps, 1)

		if shared == nil {
			shared = resps[0]
		}

		assert.Same(t, shared, resps[0], "viewers of one patch share the response")
	}

	encodes := 0
	encode := func(resp *tailcfg.MapResponse, compress bool) ([]byte, error) {
		encodes++

		return json.Marshal(resp)
	}

	first, err := hub.Encode(shared, false, encode)
	require.NoError(t, err)
	second, err := hub.Encode(shared, false, encode)
	require.NoError(t, err)

	want, err := json.Marshal(shared)
	require.NoError(t, err)

	assert.Equal(t, 1, encodes, "a shared response encodes once")
	assert.Equal(t, want, first)
	assert.Equal(t, want, second)
}

// benchEncode encodes a response as the poll loop sends it.
func benchEncode(resp *tailcfg.MapResponse, compress bool) ([]byte, error) {
	b, err := json.Marshal(resp)
	if err != nil || !compress {
		return b, err
	}

	return zstdframe.AppendEncode(nil, b, zstdframe.FastestCompression), nil
}

// TestStreamCatchesUpFromBeyondTheEditLog lets more writes go by than the
// edit log holds before a session updates, so it and its class's shared
// map rebuild from the view, and checks the client then equals a fresh
// session's.
func TestStreamCatchesUpFromBeyondTheEditLog(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	nodes := s.Snapshot().NodesVersion()

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])

	// More edits than an edit log ever keeps (twice its reach).
	for i := range 600 {
		n := mustNode(t, s, ids[1+i%2]).AsStruct()
		n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1))} //nolint:gosec // small
		s.PutNodeInStoreForTest(*n)
	}

	_, ok := s.Snapshot().NodesTouchedSince(nodes)
	require.False(t, ok, "the session must be beyond the edit log")

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	for _, r := range resps {
		client.apply(r)
	}

	fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, client.sameAs(newModelClient(fresh[0])))
}

// TestRouteWakesSSHDestinationOfChangedSource has SSH alone connect u1 to
// a tag:b node, and moves one of u1's nodes out of u1: the tag:b node is
// not a peer of the moved node, but its SSH principals changed, so the
// hub must wake it.
func TestRouteWakesSSHDestinationOfChangedSource(t *testing.T) {
	_, s, ids := streamTestState(t, `{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
		"acls":[{"action":"accept","src":["tag:a"],"dst":["tag:a:*"]}],
		"ssh":[{"action":"accept","src":["u1@"],"dst":["tag:b"],"users":["root"]}]}`)
	moved, dest := ids[0], ids[2]

	_, err := s.SetNodeTags(dest, []string{"tag:b"})
	require.NoError(t, err)

	before := s.Snapshot()
	destNode := mustNode(t, s, dest)

	// A session renders the destination's SSH policy first.
	was, err := before.Policy().SSHPolicy("https://headscale.test", destNode)
	require.NoError(t, err)

	_, err = s.SetNodeTags(moved, []string{"tag:a"})
	require.NoError(t, err)

	after := s.Snapshot()
	is, err := after.Policy().SSHPolicy("https://headscale.test", destNode)
	require.NoError(t, err)
	require.NotEqual(t, was, is, "the destination's SSH principals must change")
	require.NotContains(t, after.ListPeerIDs(moved), dest, "SSH alone connects them")

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all, "a node change under SSH rules must not wake everyone")
	assert.Contains(t, wake, dest)
}

// TestRouteWakesAllBeforeSSHIsPrepared changes a node before any session
// rendered SSH from the compile in effect: a session may still render
// from it, and nothing tells what its SSH was, so the hub wakes all.
func TestRouteWakesAllBeforeSSHIsPrepared(t *testing.T) {
	_, s, ids := streamTestState(t, `{"tagOwners":{"tag:a":["u1@"]},
		"acls":[{"action":"accept","src":["tag:a"],"dst":["tag:a:*"]}],
		"ssh":[{"action":"accept","src":["u1@"],"dst":["tag:a"],"users":["root"]}]}`)

	before := s.Snapshot()

	_, err := s.SetNodeTags(ids[0], []string{"tag:a"})
	require.NoError(t, err)

	after := s.Snapshot()
	all, _ := Route(before, after, after.Since(before))
	assert.True(t, all)
}

// requireSameEncoding checks [Marshal], which reuses each node render's
// encoding, gives the bytes [json.Marshal] does, twice: once encoding the
// renders and once from the cache.
func requireSameEncoding(t *testing.T, resp *tailcfg.MapResponse) {
	t.Helper()

	want, err := json.Marshal(resp)
	require.NoError(t, err)

	for range 2 {
		got, err := Marshal(resp)
		require.NoError(t, err)
		require.Equal(t, string(want), string(got))
	}
}

// TestRenderFirstBoundsConcurrentFirstMaps takes every first-map slot and
// checks the next caller waits until one is released, its context ends, its
// session stops or the hub closes.
func TestRenderFirstBoundsConcurrentFirstMaps(t *testing.T) {
	hub := NewHub()

	releases := make([]func(), 0, runtime.GOMAXPROCS(0))

	for range runtime.GOMAXPROCS(0) {
		release, ok := hub.RenderFirst(t.Context().Done(), nil)
		require.True(t, ok)

		releases = append(releases, release)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, ok := hub.RenderFirst(ctx.Done(), nil)
	require.False(t, ok, "every slot is taken")

	// leaves reports whether a wait with every slot taken gives up on
	// its own, without its context ending.
	leaves := func(stop <-chan struct{}) bool {
		left := make(chan bool, 1)

		go func() {
			_, ok := hub.RenderFirst(nil, stop)
			left <- !ok
		}()

		select {
		case l := <-left:
			return l
		case <-time.After(time.Second):
			return false
		}
	}

	stop := make(chan struct{})
	close(stop)
	require.True(t, leaves(stop), "a session stopped while queued renders nothing")

	releases[0]()

	release, ok := hub.RenderFirst(t.Context().Done(), nil)
	require.True(t, ok, "a released slot is free")

	defer release()

	hub.Close()
	require.True(t, leaves(nil), "a closed hub keeps no session queued")
}

// TestPingDropsWhenQueueFull fills a session's ping queue: a ping that does
// not fit is dropped, like one lost in flight, and reported unsent, and a
// drained queue takes pings again.
func TestPingDropsWhenQueueFull(t *testing.T) {
	hub := NewHub()
	pr := &tailcfg.PingRequest{URL: "https://headscale.example.com/machine/ping-response"}

	assert.False(t, hub.Ping(1, pr), "a node without a session took a ping")

	s := hub.Join(1, func() {})
	for range cap(s.pings) {
		require.True(t, hub.Ping(1, pr))
	}

	assert.False(t, hub.Ping(1, pr), "a full queue took a ping")

	<-s.Pings()
	assert.True(t, hub.Ping(1, pr), "a drained queue refused a ping")
}

// TestDERPFramesShared changes the DERP map and checks every session is
// sent the same response, so it is encoded once.
func TestDERPFramesShared(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()

	streams := make([]*Stream, 0, len(ids))
	for _, id := range ids {
		st := NewStream(cfg, hub, id, capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		streams = append(streams, st)
	}

	s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{901: {RegionID: 901}}})
	snap := s.Snapshot()

	var shared *tailcfg.MapResponse

	for _, st := range streams {
		resps, err := st.Update(snap)
		require.NoError(t, err)
		require.Len(t, resps, 1)

		if shared == nil {
			shared = resps[0]
		}

		assert.Same(t, shared, resps[0])
	}
}

// BenchmarkFirstMap renders and encodes a reconnecting node's first map
// in a full mesh: the read every node does at once after a restart, which
// walks every peer.
func BenchmarkFirstMap(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s, streams := scalingTailnet(b, n, "allow-all")
			st := streams[len(streams)/2]
			snap := s.Snapshot()

			b.ReportAllocs()

			for b.Loop() {
				first := NewStream(st.cfg, st.hub, st.nodeID, capVer)

				resps, err := first.Initial(snap)
				if err != nil {
					b.Fatal(err)
				}

				_, err = Marshal(resps[0])
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestRouteWakesViewersOfAnOfflineNodeThatExpires lets an offline node's
// key expire by the clock: the expiry tick must wake its viewers, since
// Expired is rendered from the time and no field of the node changes.
func TestRouteWakesViewersOfAnOfflineNodeThatExpires(t *testing.T) {
	_, s, ids := streamTestState(t, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)
	node, viewer := ids[0], ids[1]

	lastCheck := time.Now()
	expiry := lastCheck.Add(50 * time.Millisecond)

	_, err := s.SetNodeExpiry(node, &expiry)
	require.NoError(t, err)

	before := s.Snapshot()

	require.Eventually(t, func() bool { return mustNode(t, s, node).IsExpired() },
		time.Second, time.Millisecond)

	_, found := s.ExpireExpiredNodes(lastCheck)
	require.True(t, found, "test sanity: the tick finds the expired node")

	after := s.Snapshot()

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all)
	assert.Contains(t, wake, viewer, "a viewer must learn the node expired")
}

// TestStreamSelfDropsHTTPSWhenAnExtraRecordTakesItsName publishes an extra
// record at a node's name: the node must lose its HTTPS capability, since
// the name now belongs to a service, on the next update and not only on
// its next own change.
func TestStreamSelfDropsHTTPSWhenAnExtraRecordTakesItsName(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`, func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
		cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{}
	})

	node := mustNode(t, s, ids[0])
	domain, ok := node.CertDomain(s.Snapshot().DNS())
	require.True(t, ok, "test sanity: the node has a certificate name")

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	first, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Contains(t, first[0].Node.CapMap, nodecap.HTTPS)
	client := newModelClient(first[0])

	st.Delivered()

	before := s.Snapshot()
	for _, records := range [][]tailcfg.DNSRecord{
		{{Name: domain, Value: "100.64.0.99"}},
		nil,
		{{Name: domain, Value: "100.64.0.98"}},
		nil,
	} {
		s.SetExtraRecords(records)
		after := s.Snapshot()
		all, _ := Route(before, after, after.Since(before))
		require.True(t, all, "DNS changes must wake the session")

		resps, err := st.Update(after)
		require.NoError(t, err)
		require.NotEmpty(t, resps)

		for _, r := range resps {
			client.apply(r)
		}

		st.Delivered()
		assert.Equal(t, records, client.dns.ExtraRecords)
		_, https := client.self.CapMap[nodecap.HTTPS]
		assert.Equal(t, len(records) == 0, https)

		if len(records) == 0 {
			assert.Equal(t, []string{domain}, client.dns.CertDomains)
		} else {
			assert.Empty(t, client.dns.CertDomains)
		}

		before = after
	}
}

// A record taking a peer's name must not change that peer's rendered
// entry: peer renders read a records-free view by construction, and
// their CapMap comes from policy, not certificate eligibility.
func TestStreamPeerRendersIgnoreExtraRecords(t *testing.T) {
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
		cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{}
	})

	peerDomain, err := mustNode(t, s, ids[1]).GetFQDN(cfg.BaseDomain)
	require.NoError(t, err)

	peerDomain = strings.TrimSuffix(peerDomain, ".")

	renderPeers := func(snap *state.Snapshot) map[tailcfg.NodeID]*tailcfg.Node {
		t.Helper()

		r := newRenderer(cfg, NewHub(), ids[0], capVer)
		nm, err := r.render(snap)
		require.NoError(t, err)

		out := maps.Collect(nm.allPeers())
		require.NotEmpty(t, out, "test sanity: the node must see peers")

		return out
	}

	before := renderPeers(s.Snapshot())

	s.SetExtraRecords([]tailcfg.DNSRecord{{Name: peerDomain, Type: "A", Value: "100.64.0.99"}})

	after := renderPeers(s.Snapshot())

	for id, p := range before {
		assert.True(t, reflect.DeepEqual(p, after[id]), "peer %d must not depend on DNS records", id)

		_, https := p.CapMap[nodecap.HTTPS]
		assert.False(t, https, "peers never report certificate eligibility")
	}
}

// A retained snapshot must keep its records and certificate eligibility even
// when rendered for the first time after a reload, including a record removal.
func TestStreamDNSUsesSnapshot(t *testing.T) {
	initial := []tailcfg.DNSRecord{{Name: "service.headscale.test", Type: "A", Value: "100.64.0.99"}}
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
		cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{ExtraRecords: initial}
	})
	node := mustNode(t, s, ids[0])
	domain, err := node.GetFQDN(cfg.BaseDomain)
	require.NoError(t, err)

	domain = strings.TrimSuffix(domain, ".")

	before := s.Snapshot()
	records := []tailcfg.DNSRecord{{Name: strings.ToUpper(domain), Type: "A", Value: "100.64.0.99"}}
	s.SetExtraRecords(records)
	during := s.Snapshot()
	// The publisher retains ownership of its input, not of the stored records.
	records[0].Name = "unrelated.headscale.test"

	s.SetExtraRecords(nil)
	after := s.Snapshot()

	for _, tt := range []struct {
		name    string
		snap    *state.Snapshot
		records []tailcfg.DNSRecord
		cert    bool
	}{
		{"initial", before, initial, true},
		{"collision", during, []tailcfg.DNSRecord{{Name: domain, Type: "A", Value: "100.64.0.99"}}, false},
		{"removed", after, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := NewStream(cfg, NewHub(), ids[0], capVer)
			out, err := st.Initial(tt.snap)
			require.NoError(t, err)
			require.Len(t, out, 1)
			require.NotNil(t, out[0].DNSConfig)
			assert.Equal(t, tt.records, out[0].DNSConfig.ExtraRecords)
			_, https := out[0].Node.CapMap[nodecap.HTTPS]
			assert.Equal(t, tt.cert, https)

			if tt.cert {
				assert.Equal(t, []string{domain}, out[0].DNSConfig.CertDomains)
			} else {
				assert.Empty(t, out[0].DNSConfig.CertDomains)
			}
		})
	}
}

// dnsBenchTailnet builds a tailnet of n nodes under one user with DNS
// certificates enabled — the shape the DNS snapshot benchmark needs at
// sizes streamTestState does not reach.
func dnsBenchTailnet(tb testing.TB, n int, records []tailcfg.DNSRecord) (*types.Config, *state.State, types.NodeID) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/h.db"},
		},
		PrefixV4:         &p4,
		PrefixV6:         &p6,
		BaseDomain:       "headscale.test",
		ServerURL:        "https://headscale.test",
		DNSConfig:        types.DNSConfig{Certificates: types.CertificatesConfig{Enabled: true}},
		TailcfgDNSConfig: &tailcfg.DNSConfig{Proxied: true, ExtraRecords: records},
		Policy:           types.PolicyConfig{Mode: types.PolicyModeDB},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	u1 := database.CreateUserForTest("u1")

	first := database.CreateRegisteredNodeForTest(u1, "n1").ID
	for i := 1; i < n; i++ {
		database.CreateRegisteredNodeForTest(u1, fmt.Sprintf("n%d", i+1))
	}

	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = s.Close() })

	s.SetDERPMap(&tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
	})

	// The benchmark is meaningless if policy wiring ever regressed to
	// deny-by-default: the measured netmaps would be silently empty.
	out, err := NewStream(cfg, NewHub(), first, capVer).Initial(s.Snapshot())
	require.NoError(tb, err)
	require.NotEmpty(tb, out[0].Peers)

	return cfg, s, first
}

func BenchmarkDNSSnapshot(b *testing.B) {
	for _, nodes := range []int{3, 1000} {
		for _, records := range []int{1, 128} {
			for _, reload := range []bool{false, true} {
				b.Run(fmt.Sprintf("nodes=%d/records=%d/reload=%t", nodes, records, reload), func(b *testing.B) {
					recs := make([]tailcfg.DNSRecord, records)
					for i := range recs {
						recs[i] = tailcfg.DNSRecord{Name: fmt.Sprintf("service%d.headscale.test", i), Type: "A", Value: "100.64.0.99"}
					}

					cfg, s, id := dnsBenchTailnet(b, nodes, recs)
					snap := s.Snapshot()

					b.ReportAllocs()

					// shortcut: B/op detects record-copy regressions only; a
					// records scan in a peer render allocates nothing, so it
					// is invisible to both oracles —
					// TestStreamPeerRendersIgnoreExtraRecords covers
					// output-visible records dependencies only.
					for b.Loop() {
						if reload {
							if recs[0].Value == "100.64.0.99" {
								recs[0].Value = "100.64.0.98"
							} else {
								recs[0].Value = "100.64.0.99"
							}

							s.SetExtraRecords(recs)
							snap = s.Snapshot()
						}

						// A fresh hub per iteration rebuilds the class maps,
						// so every iteration pays the peer renders the
						// snapshot must keep independent of the records.
						st := NewStream(cfg, NewHub(), id, capVer)

						_, err := st.Initial(snap)
						if err != nil {
							b.Fatal(err)
						}

						st.Delivered()
					}
				})
			}
		}
	}
}

func TestStreamDNSOwnsStartupSettings(t *testing.T) {
	resolver := &dnstype.Resolver{Addr: "1.1.1.1", BootstrapResolution: []netip.Addr{netip.MustParseAddr("1.0.0.1")}}
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
		cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{
			Proxied:           true,
			Domains:           []string{"headscale.test"},
			Resolvers:         []*dnstype.Resolver{resolver},
			FallbackResolvers: []*dnstype.Resolver{resolver},
			Routes:            map[string][]*dnstype.Resolver{"split.test": {resolver}},
		}
	})
	before := s.Snapshot()
	cfg.BaseDomain = "changed.test"
	cfg.DNSConfig.Certificates.Enabled = false
	cfg.TailcfgDNSConfig.Domains[0] = "changed.test"
	resolver.Addr = "9.9.9.9"
	resolver.BootstrapResolution[0] = netip.MustParseAddr("9.9.9.10")

	s.SetExtraRecords([]tailcfg.DNSRecord{{Name: "service.headscale.test", Value: "100.64.0.99"}})

	for _, snap := range []*state.Snapshot{before, s.Snapshot()} {
		out, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(snap)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "n1.headscale.test.", out[0].Node.Name)
		assert.Contains(t, out[0].Node.CapMap, nodecap.HTTPS)
		assert.Equal(t, []string{"n1.headscale.test"}, out[0].DNSConfig.CertDomains)
		assert.Equal(t, []string{"headscale.test"}, out[0].DNSConfig.Domains)

		for _, resolvers := range [][]*dnstype.Resolver{out[0].DNSConfig.Resolvers, out[0].DNSConfig.FallbackResolvers, out[0].DNSConfig.Routes["split.test"]} {
			require.Len(t, resolvers, 1)
			assert.Equal(t, "1.1.1.1", resolvers[0].Addr)
			assert.Equal(t, []netip.Addr{netip.MustParseAddr("1.0.0.1")}, resolvers[0].BootstrapResolution)
		}

		for _, peer := range out[0].Peers {
			assert.True(t, strings.HasSuffix(peer.Name, ".headscale.test."))
		}
	}
}

func TestStreamDNSInitialReverseRoutes(t *testing.T) {
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{
			Proxied: true,
			Routes: map[string][]*dnstype.Resolver{
				"split.test":          {{Addr: "1.1.1.1"}},
				"64.100.in-addr.arpa": {{Addr: "9.9.9.9"}},
			},
		}
	})
	out, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)

	for _, zone := range []string{"64.100.in-addr.arpa", "127.100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"} {
		resolvers, ok := out[0].DNSConfig.Routes[zone]
		assert.True(t, ok, zone)
		assert.NotNil(t, resolvers, zone)
		assert.Empty(t, resolvers, zone)
	}

	assert.Equal(t, []*dnstype.Resolver{{Addr: "1.1.1.1"}}, out[0].DNSConfig.Routes["split.test"])
}

func TestStreamDNSConcurrentSnapshots(t *testing.T) {
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
		cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{}
	})
	domain, err := mustNode(t, s, ids[0]).GetFQDN(cfg.BaseDomain)
	require.NoError(t, err)

	domain = strings.TrimSuffix(domain, ".")
	before := s.Snapshot()
	records := []tailcfg.DNSRecord{{Name: domain, Type: "A", Value: "100.64.0.99"}}
	pristine := slices.Clone(records)
	s.SetExtraRecords(records)
	during := s.Snapshot()

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			records[0].Name = domain

			s.SetExtraRecords(nil)
			s.SetExtraRecords(records)
			// The publisher keeps ownership of its input: leave the slice
			// mutated while readers render, so an aliased view would show
			// (and -race would flag the shared write).
			records[0].Name = "mutated." + domain
		}
	})

	for range 4 {
		wg.Go(func() {
			r := newRenderer(cfg, NewHub(), ids[0], capVer)

			for range 100 {
				for _, snap := range []*state.Snapshot{before, during, s.Snapshot()} {
					nm, err := r.render(snap)
					if err != nil {
						t.Errorf("rendering snapshot: %v", err)

						return
					}

					_, https := nm.self.CapMap[nodecap.HTTPS]
					if !assert.Equal(t, len(nm.dns.ExtraRecords) == 0, https) {
						return
					}

					if https {
						if !assert.Equal(t, []string{domain}, nm.dns.CertDomains) {
							return
						}
					} else if !assert.Empty(t, nm.dns.CertDomains) {
						return
					}

					if snap == before && !assert.Empty(t, nm.dns.ExtraRecords) {
						return
					}

					if snap == during && !assert.Equal(t, pristine, nm.dns.ExtraRecords) {
						return
					}
				}
			}
		})
	}

	wg.Wait()
}

// TestRouteWakesViewerGainingARouteByPolicy grants a viewer that already
// sees a router its route by a policy edit: the viewer's peer set and own
// filter stay the same, so only the routed wake reaches it.
func TestRouteWakesViewerGainingARouteByPolicy(t *testing.T) {
	without := `{"acls":[{"action":"accept","src":["u1@","u2@"],"dst":["u1@:*","u2@:*"]}]}`
	with := `{"acls":[{"action":"accept","src":["u1@","u2@"],"dst":["u1@:*","u2@:*"]},
	          {"action":"accept","src":["u2@"],"dst":["10.0.0.0/24:*"]}]}`

	_, s, ids := streamTestState(t, without)
	router, viewer := ids[0], ids[2]

	route := netip.MustParsePrefix("10.0.0.0/24")
	n := mustNode(t, s, router).AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	s.PutNodeInStoreForTest(*n)

	_, err := s.SetApprovedRoutes(router, []netip.Prefix{route})
	require.NoError(t, err)

	s.Connect(router)
	require.Contains(t, s.Snapshot().ListPeerIDs(viewer), router, "test sanity: the viewer sees the router")

	before := s.Snapshot()

	_, err = s.SetPolicy([]byte(with))
	require.NoError(t, err)

	after := s.Snapshot()
	require.Equal(t, before.ListPeerIDs(viewer), after.ListPeerIDs(viewer), "test sanity: the peer set is the same")

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all, "test sanity: this edit narrows, so the routed wake is what reaches the viewer")

	assert.Contains(t, wake, viewer, "the viewer must learn the route")

	// A recompile that renders every peer the same sends nothing, so it
	// wakes no router's viewers.
	_, err = s.SetPolicy([]byte(with + "\n"))
	require.NoError(t, err)

	again := s.Snapshot()
	require.NotEqual(t, string(after.PolicySource()), string(again.PolicySource()), "test sanity: the edit recompiled")

	all, wake = Route(after, again, again.Since(after))
	assert.False(t, all)
	assert.Empty(t, wake, "an identical filter must wake nobody")
}

// TestRoutePolicyEditWakesOnlyWhatItReaches edits a rule only user1's nodes
// are in: user2's node, which no rule names, must not wake. A policy edit
// waking every session would quietly undo output-proportional cost.
func TestRoutePolicyEditWakesOnlyWhatItReaches(t *testing.T) {
	_, s, ids := streamTestState(t, `{"acls":[{"action":"accept","src":["u1@"],"dst":["u1@:22"]}]}`)
	outside := ids[2]

	before := s.Snapshot()

	_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["u1@"],"dst":["u1@:80"]}]}`))
	require.NoError(t, err)

	after := s.Snapshot()

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all, "a shared rule's edit must not wake every session")
	assert.Contains(t, wake, ids[0], "the rule's destinations must wake")
	assert.NotContains(t, wake, outside, "a node no rule names must not wake")
}

// TestRelayTargetOnlineFlipReachesPeers flips a relay target, no router,
// online and back: its own entry is all that carries the flip, and a peer
// must get it to drop a relay allocation through a node gone offline.
func TestRelayTargetOnlineFlipReachesPeers(t *testing.T) {
	relay := `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]},
	           {"src":["*"],"dst":["u2@"],"app":{"tailscale.com/cap/relay":[{}]}}]}`

	cfg, s, ids := streamTestState(t, relay)
	viewer, target := ids[0], ids[2]
	require.Contains(t, s.Snapshot().ListPeerIDs(viewer), target, "test sanity: the viewer sees the relay")

	st := NewStream(cfg, NewHub(), viewer, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	online := func(resps []*tailcfg.MapResponse) *bool {
		for _, r := range resps {
			for _, p := range r.PeersChangedPatch {
				if p.NodeID == target.NodeID() {
					return p.Online
				}
			}

			for _, p := range r.PeersChanged {
				if p.ID == target.NodeID() {
					return p.Online
				}
			}
		}

		return nil
	}

	var gen uint64

	for _, step := range []struct {
		name string
		do   func()
		want bool
	}{
		{"connect", func() { gen = s.Connect(target) }, true},
		{"disconnect", func() { require.NoError(t, s.Disconnect(target, gen)) }, false},
	} {
		before := s.Snapshot()

		step.do()

		after := s.Snapshot()

		all, wake := Route(before, after, after.Since(before))
		if !all {
			assert.Contains(t, wake, viewer, step.name)
		}

		resps, err := st.Update(after)
		require.NoError(t, err)
		st.Delivered()

		got := online(resps)
		require.NotNil(t, got, "%s must reach the peer", step.name)
		assert.Equal(t, step.want, *got, step.name)
	}
}

// TestStreamCapabilityCacheBound keeps supported versions shared while
// reconnects with arbitrary versions cannot leave renders in the hub.
func TestStreamCapabilityCacheBound(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	snap := s.Snapshot()

	var shared *peerMap

	for cv := capver.MinSupportedCapabilityVersion; cv <= capVer; cv++ {
		st := NewStream(cfg, hub, ids[0], cv)
		_, err := st.Initial(snap)
		require.NoError(t, err)

		shared = st.r.last.peers
	}

	versions := int(capVer-capver.MinSupportedCapabilityVersion) + 1
	require.Len(t, hub.classes.m, versions)

	for i := range 128 {
		for _, cv := range []tailcfg.CapabilityVersion{
			capVer + 1 + tailcfg.CapabilityVersion(i),
			capver.MinSupportedCapabilityVersion - 1 - tailcfg.CapabilityVersion(i),
		} {
			sess := hub.Join(ids[0], func() {})
			st := NewStream(cfg, hub, ids[0], cv)
			st.Attach(sess)
			resps, err := st.Initial(snap)
			require.NoError(t, err)
			require.Len(t, resps, 1)
			assert.Equal(t, cv, resps[0].Node.Cap)
			require.Len(t, resps[0].Peers, 2)

			for _, peer := range resps[0].Peers {
				assert.Equal(t, cv, peer.Cap)
			}

			st.Delivered()

			// A live unknown-version session still reuses its unchanged map.
			peers := st.r.last.peers
			updates, err := st.Update(snap)
			require.NoError(t, err)
			assert.Empty(t, updates)
			assert.Same(t, peers, st.r.last.peers)
			hub.Leave(sess)
		}
	}

	assert.Empty(t, hub.Connected())
	assert.Len(t, hub.classes.m, versions, "unknown versions leave no shared classes")
	hub.renders.m.Range(func(_, value any) bool {
		count := 0

		value.(*sync.Map).Range(func(_, _ any) bool { //nolint:forcetypeassert // peerRenders stores *sync.Map
			count++
			return true
		})
		assert.Equal(t, versions, count, "unknown versions leave no shared peer renders")

		return true
	})

	st := NewStream(cfg, hub, ids[1], capVer)
	_, err := st.Initial(snap)
	require.NoError(t, err)
	assert.Same(t, shared, st.r.last.peers, "unknown versions do not evict supported versions")
}

// TestPeerRendersForgetDropsEveryCapVer renders a node for two capability
// versions and forgets it: neither render may survive, or a deleted node's
// renders would pile up.
func TestPeerRendersForgetDropsEveryCapVer(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	node := mustNode(t, s, ids[0])

	var pr peerRenders

	for _, cv := range []tailcfg.CapabilityVersion{capVer, capVer - 1} {
		_, err := pr.render(cfg, s.Snapshot().DNS(), cv, s.Snapshot().Rev(), 1, node, nil)
		require.NoError(t, err)
	}

	pr.forget(node.ID())

	_, ok := pr.m.Load(node.ID())
	assert.False(t, ok, "a forgotten node keeps no render")
}

// TestClassMapsPruneVanishedClassWithoutNewOne deletes the only node of a
// class view: once the peer classes change, its map must go even though
// no new class appeared to trigger a prune.
func TestClassMapsPruneVanishedClassWithoutNewOne(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)

	var (
		cm      classMaps
		renders peerRenders
	)

	render := func(id types.NodeID) {
		snap := s.Snapshot()
		cm.get(cfg, &renders, snap, snap.PeerView(id), capVer, snap.PeerPolicyRev(), nil)
	}

	render(ids[0])
	render(ids[2])
	require.Len(t, cm.m, 2, "test sanity: one map per user's class")

	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))
	render(ids[0])

	assert.Len(t, cm.m, 1, "the deleted user's class map is gone")
}

// TestStaleRenderCacheAdmission lets deletion cleanup overtake a render
// holding an old snapshot. That render must stay valid without retaining
// a deleted peer or a vanished class in the shared caches.
func TestStaleRenderCacheAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		warm   bool
		forget bool
	}{
		{name: "cached", warm: true, forget: true},
		{name: "uncached", forget: true},
		{name: "resync-without-retained-node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")
			hub := NewHub()
			t.Cleanup(hub.Close)

			before := s.Snapshot()
			if tc.warm {
				_, err := NewStream(cfg, hub, ids[0], capVer).Initial(before)
				require.NoError(t, err)
			}

			require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))

			after := s.Snapshot()
			hub.renders.advance(after.Rev())

			if tc.forget {
				hub.forget(ids[2])
			}

			var wg sync.WaitGroup

			for range 32 {
				wg.Go(func() {
					stale, err := NewStream(cfg, hub, ids[0], capVer).Initial(before)
					if assert.NoError(t, err) {
						assert.Contains(t, peerSet(stale[0]), ids[2].NodeID(), "the old snapshot still renders correctly")
					}
				})
			}

			wg.Wait()

			_, retained := hub.renders.m.Load(ids[2])
			assert.False(t, retained, "stale renders must not admit a deleted node")

			current := NewStream(cfg, hub, ids[0], capVer)
			_, err := current.Initial(after)
			require.NoError(t, err)

			// Pruning the newest classes must also close late admission
			// by a renderer whose snapshot was captured before deletion.
			_, err = NewStream(cfg, hub, ids[0], capVer).Initial(before)
			require.NoError(t, err)
			assert.Len(t, hub.classes.m, 1, "stale renders must not admit a vanished class")
			_, retained = hub.renders.m.Load(ids[2])
			assert.False(t, retained)

			fresh := NewStream(cfg, hub, ids[1], capVer)
			resps, err := fresh.Initial(after)
			require.NoError(t, err)
			assert.NotContains(t, peerSet(resps[0]), ids[2].NodeID())
			assert.Same(t, current.r.last.peers, fresh.r.last.peers, "live classes remain shared")
		})
	}
}

// TestRenderCacheDeletionRace covers both admissions made before cleanup
// (whose detached maps may still be written) and misses after cleanup.
func TestRenderCacheDeletionRace(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	before := s.Snapshot()
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))

	after := s.Snapshot()

	for range 64 {
		hub := NewHub()

		var wg sync.WaitGroup

		wg.Go(func() {
			_, err := NewStream(cfg, hub, ids[0], capVer).Initial(before)
			assert.NoError(t, err)
		})
		wg.Go(func() {
			hub.renders.advance(after.Rev())
			hub.classes.advance(after)
			hub.forget(ids[2])

			_, err := NewStream(cfg, hub, ids[0], capVer).Initial(after)
			assert.NoError(t, err)
		})
		wg.Wait()

		_, retained := hub.renders.m.Load(ids[2])
		assert.False(t, retained, "a render racing cleanup leaves no deleted peer cached")
		assert.Len(t, hub.classes.m, 1)
		hub.Close()
	}
}

// TestClassMapsWatchCleanup lets an old map finish after the watcher has
// stopped its session. No current renderer remains to prune its class.
func TestClassMapsWatchCleanup(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("warm=%t/empty=%t", warm, empty), func(t *testing.T) {
				cfg, s, ids := streamTestState(t, "")
				hub := NewHub()
				t.Cleanup(hub.Close)

				stopped := false
				sess := hub.Join(ids[0], func() { stopped = true })
				st := NewStream(cfg, hub, ids[0], capVer)
				st.Attach(sess)

				before := s.Snapshot()
				if warm {
					_, err := st.Initial(before)
					require.NoError(t, err)
					st.Delivered()
				}

				require.NoError(t, s.DeleteNode(mustNode(t, s, ids[0])))

				if empty {
					_, err := s.SetPolicy([]byte(`{"acls":[]}`))
					require.NoError(t, err)

					for _, view := range s.Snapshot().PeerViews() {
						require.Empty(t, view)
					}
				}

				after := s.Snapshot()
				hub.renders.advance(after.Rev())
				hub.classes.advance(after)
				hub.forget(ids[0])
				hub.Leave(sess)
				require.True(t, stopped)
				require.Empty(t, hub.Connected())
				assert.Empty(t, hub.classes.m, "the watcher alone drops obsolete classes")

				_, err := st.Initial(before)
				require.NoError(t, err, "the in-flight snapshot still renders")
				st.Delivered()
				assert.Empty(t, hub.classes.m, "a stopped session cannot restore an obsolete class")

				_, retained := hub.renders.m.Load(ids[0])
				assert.False(t, retained)
			})
		}
	}
}

func TestClassMapsPruneOnEmptyView(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	before := s.Snapshot()
	_, err := NewStream(cfg, hub, ids[0], capVer).Initial(before)
	require.NoError(t, err)
	require.Len(t, hub.classes.m, 1)

	_, err = s.SetPolicy([]byte(`{"acls":[]}`))
	require.NoError(t, err)

	after := s.Snapshot()
	require.Empty(t, after.PeerView(ids[0]))
	_, err = NewStream(cfg, hub, ids[0], capVer).Initial(after)
	require.NoError(t, err)
	assert.Empty(t, hub.classes.m, "an empty view still prunes vanished classes")

	_, err = NewStream(cfg, hub, ids[0], capVer).Initial(before)
	require.NoError(t, err)
	assert.Empty(t, hub.classes.m, "the old class cannot return after pruning")
}

// TestHubSessionLifecycle walks the hub's session bookkeeping: joins count
// per node, a leave reports whether others remain, wakes reach only the
// named nodes and coalesce, forgetting a node stops its sessions and drops
// its history, and closing stops the rest, so a write of theirs still in
// flight records nothing, and refuses new sessions.
func TestHubSessionLifecycle(t *testing.T) {
	h := NewHub()

	stopped := map[string]int{}
	join := func(id types.NodeID, name string) *Session {
		s := h.Join(id, func() { stopped[name]++ })
		require.NotNil(t, s)

		return s
	}

	a1, a2, b := join(1, "a1"), join(1, "a2"), join(2, "b")

	assert.Equal(t, map[types.NodeID]int{1: 2, 2: 1}, h.Connected())

	assert.True(t, h.Leave(a2), "a1 still serves node 1")
	assert.True(t, h.IsConnected(1))

	// Two wakes for node 1 coalesce; node 2 is not woken.
	h.wake(false, map[types.NodeID]struct{}{1: {}})
	h.wake(false, map[types.NodeID]struct{}{1: {}})
	assert.Len(t, a1.Wakes(), 1)
	assert.Empty(t, b.Wakes())

	h.setLastPeers(nil, 2, sentView{ids: []types.NodeID{1}, rev: 1})
	h.forget(2)
	assert.Equal(t, 1, stopped["b"], "forgetting a node stops its sessions")
	assert.Empty(t, h.lastPeers(2), "and drops its history")

	// The stopped session leaves on its own, as poll does.
	assert.False(t, h.Leave(b))
	assert.False(t, h.IsConnected(2))

	h.Close()
	assert.Equal(t, 1, stopped["a1"], "closing stops the remaining sessions")

	h.setLastPeers(a1, 1, sentView{ids: []types.NodeID{2}, rev: 2})
	assert.Empty(t, h.lastPeers(1), "a write completing after the close records nothing")

	select {
	case <-h.Done():
	default:
		t.Fatal("Done must be closed once the hub is")
	}

	assert.Nil(t, h.Join(3, func() {}), "a closed hub takes no sessions")
}

// TestTwoRendersOfARevisionCarryTheSameView pins setLastPeers letting an
// equal revision through, and what that relies on: two sessions rendering
// one snapshot record the same peer view, so the second delivery must
// clear the attempt its write added.
func TestTwoRendersOfARevisionCarryTheSameView(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	snap := s.Snapshot()

	a, b := NewStream(cfg, hub, ids[0], capVer), NewStream(cfg, hub, ids[0], capVer)

	_, err := a.Initial(snap)
	require.NoError(t, err)
	a.Delivered()

	_, err = b.Initial(snap)
	require.NoError(t, err)

	require.NotNil(t, b.pending)
	assert.Equal(t, hub.lastPeers(ids[0]), b.pending.ids, "test sanity: both render the same view")

	b.Delivered()

	hub.mu.Lock()
	attempts := hub.sentPeers[ids[0]].attempts
	hub.mu.Unlock()
	assert.Empty(t, attempts, "a delivery at the same revision clears its attempt")
}

// TestHubFoldsUnconfirmedViews writes more unconfirmed views than the hub
// keeps apart: they fold into one, and a reconnect still announces every
// peer any of them carried.
func TestHubFoldsUnconfirmedViews(t *testing.T) {
	h := NewHub()

	want := make([]types.NodeID, 0, maxPeerAttempts+3)

	for i := range maxPeerAttempts + 3 {
		id := types.NodeID(100 + i) //nolint:gosec // small
		want = append(want, id)
		h.mayHavePeers(nil, 1, sentView{ids: []types.NodeID{id}, rev: uint64(i + 1)}) //nolint:gosec // small
	}

	assert.Equal(t, want, h.lastPeers(1), "every attempted peer stays announceable")

	h.mu.Lock()
	attempts := len(h.sentPeers[1].attempts)
	h.mu.Unlock()
	assert.LessOrEqual(t, attempts, maxPeerAttempts, "attempts fold instead of growing")
}

// TestStreamAnnouncesRemovalOfAPeerOnlyAFailedInitialCarried lets a peer
// join while a node is away, sends it in a reconnect's initial map whose
// write fails part way, and deletes it: the next reconnect must announce
// the removal, as the client may hold the peer from that partial map.
func TestStreamAnnouncesRemovalOfAPeerOnlyAFailedInitialCarried(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()

	first := NewStream(cfg, hub, ids[0], capVer)
	_, err := first.Initial(s.Snapshot())
	require.NoError(t, err)
	first.Delivered()

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	joined := s.CreateRegisteredNodeForTest(u1, "joined-while-away")
	s.PutNodeInStoreForTest(*joined)

	// This initial map carries the new peer; its write fails part way.
	partial, err := NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.True(t, mentions(partial, joined.ID), "test sanity: the failed initial carried the peer")

	require.NoError(t, s.DeleteNode(mustNode(t, s, joined.ID)))

	resps, err := NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)

	var removed []tailcfg.NodeID
	for _, r := range resps {
		removed = append(removed, r.PeersRemoved...)
	}

	assert.Contains(t, removed, joined.ID.NodeID(), "the client may hold the peer from the partial map")
}

// TestHubForgetIsNotUndoneByAWriteInFlight deletes a node while one of
// its sessions has a write in flight that then succeeds, with the session
// leaving the hub before or after, or rendering only after the deletion:
// in no order may the session record history for the deleted node, which
// no deletion would clear again. A stall leaves the hub before the write
// returns, so a session's own leaving counts too.
func TestHubForgetIsNotUndoneByAWriteInFlight(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	for name, order := range map[string][]string{
		"forget, deliver, leave": {"render", "forget", "deliver", "leave"},
		"forget, leave, deliver": {"render", "forget", "leave", "deliver"},
		"leave, forget, deliver": {"render", "leave", "forget", "deliver"},
		"leave, deliver":         {"render", "leave", "deliver"},
		"forget, render":         {"forget", "render", "deliver"},
	} {
		t.Run(name, func(t *testing.T) {
			hub := NewHub()

			sess := hub.Join(ids[0], func() {})
			require.NotNil(t, sess)

			st := NewStream(cfg, hub, ids[0], capVer)
			st.Attach(sess)

			for _, step := range order {
				switch step {
				case "render":
					_, err := st.Initial(s.Snapshot())
					require.NoError(t, err)
				case "forget":
					hub.forget(ids[0])
				case "leave":
					hub.Leave(sess)
				case "deliver":
					st.Delivered()
				}
			}

			hub.mu.Lock()
			v, kept := hub.sentPeers[ids[0]]
			hub.mu.Unlock()

			if slices.Contains(order, "forget") {
				assert.False(t, kept, "a deleted node keeps no history")
			} else {
				assert.Empty(t, v.ids, "a session that left records nothing it wrote")
			}
		})
	}
}

// TestStreamAnnouncesRemovalOfAPeerOnlyAFailedUpdateCarried is the update
// counterpart: a peer arrives in an update whose write fails part way and
// is then deleted, and the next session must announce its removal.
func TestStreamAnnouncesRemovalOfAPeerOnlyAFailedUpdateCarried(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()

	st := NewStream(cfg, hub, ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	joined := s.CreateRegisteredNodeForTest(u1, "joined-in-an-update")
	s.PutNodeInStoreForTest(*joined)

	// The update carrying the new peer fails to write; the session ends.
	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, resps, "test sanity: the update carries the new peer")

	require.NoError(t, s.DeleteNode(mustNode(t, s, joined.ID)))

	resps, err = NewStream(cfg, hub, ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)

	var removed []tailcfg.NodeID
	for _, r := range resps {
		removed = append(removed, r.PeersRemoved...)
	}

	assert.Contains(t, removed, joined.ID.NodeID(), "the client may hold the peer from the failed update")
}

func TestRouteWakesAfterLastUnpreparedSSHRuleIsRemoved(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"ssh":[{"action":"accept","src":["u1@"],"dst":["autogroup:self"],"users":["root"]}]}`)
	hub := NewHub()
	session := hub.Join(ids[0], func() {})
	st := NewStream(cfg, hub, ids[0], capVer)
	st.Attach(session)

	old := s.Snapshot()
	// The render has captured old, but has not reached lazy SSH preparation.
	_, err := s.SetPolicy([]byte(`{"ssh":[]}`))
	require.NoError(t, err)

	cur := s.Snapshot()
	initial, err := st.Initial(old)
	require.NoError(t, err)
	require.NotEmpty(t, initial[0].SSHPolicy.Rules)

	all, wake := Route(old, cur, cur.Since(old))
	_, target := wake[ids[0]]
	require.True(t, all || target, "revoked SSH target must be woken; got all=%v wake=%v", all, wake)
}

// A session may render a snapshot between the two snapshots a slow hub sees.
func TestHubCoalescedCommitsConverge(t *testing.T) {
	for _, mode := range []string{"policy_revert", "endpoint_revert", "transient_peer", "deleted_self", "history_overrun"} {
		t.Run(mode, func(t *testing.T) {
			const (
				allow = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
				deny  = `{"acls":[]}`
			)

			initialPolicy := allow
			if mode == "policy_revert" {
				initialPolicy = deny
			}

			cfg, s, ids := streamTestState(t, initialPolicy)
			hub := NewHub()
			t.Cleanup(hub.Close)

			sub := s.Subscribe()
			before := s.Snapshot()
			observer, transient := ids[0], types.NodeID(0)
			original := mustNode(t, s, ids[1]).AsStruct()

			switch mode {
			case "policy_revert":
				_, err := s.SetPolicy([]byte(allow))
				require.NoError(t, err)
			case "endpoint_revert":
				changed := original.Clone()
				changed.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.99:1234")}
				s.PutNodeInStoreForTest(*changed)
			default:
				user, err := s.GetUserByName("u1")
				require.NoError(t, err)

				n := s.CreateRegisteredNodeForTest(user, "transient")
				n.User = user
				s.PutNodeInStoreForTest(*n)

				transient = n.ID
				if mode == "deleted_self" {
					observer = transient
				}
			}

			stopped := make(chan struct{})

			var once sync.Once

			session := hub.Join(observer, func() { once.Do(func() { close(stopped) }) })
			st := NewStream(cfg, hub, observer, capVer)
			st.Attach(session)
			initial, err := st.Initial(s.Snapshot())
			require.NoError(t, err)
			st.Delivered()

			client := newModelClient(initial[0])

			switch mode {
			case "policy_revert":
				require.NotEmpty(t, client.filter)

				_, err = s.SetPolicy([]byte(deny))
				require.NoError(t, err)
			case "endpoint_revert":
				s.PutNodeInStoreForTest(*original)
			default:
				require.NoError(t, s.DeleteNode(mustNode(t, s, transient)))
			}

			if mode == "history_overrun" {
				for i := range 600 {
					n := original.Clone()
					n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1))}
					s.PutNodeInStoreForTest(*n)
				}
			}

			finished := make(chan struct{})
			go func() { defer close(finished); hub.watch(s, sub, before) }()

			t.Cleanup(func() { hub.Close(); <-finished })

			if mode == "deleted_self" {
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("deleted node's session was not stopped")
				}

				require.False(t, hub.HasPeerHistoryForTest(observer))

				return
			}

			select {
			case <-session.Wakes():
			case <-time.After(time.Second):
				t.Fatal("observer of intermediate state was not woken")
			}

			updates, err := st.Update(s.Snapshot())
			require.NoError(t, err)

			for _, response := range updates {
				data, err := Marshal(response)
				require.NoError(t, err)

				var wire tailcfg.MapResponse
				require.NoError(t, json.Unmarshal(data, &wire))
				client.apply(&wire)
			}

			switch mode {
			case "policy_revert":
				require.Empty(t, client.filter)
				require.Empty(t, client.peers)
			case "endpoint_revert":
				require.Empty(t, client.peers[ids[1].NodeID()].Endpoints)
			default:
				require.NotContains(t, client.peers, transient.NodeID())
				_, retained := hub.renders.m.Load(transient)
				require.False(t, retained, "the deleted peer's render must be reclaimed")
			}
		})
	}
}

func TestRouteCoalescedEndpointWritesStayScoped(t *testing.T) {
	_, s, ids := streamTestState(t, ownUserOnly)
	before := s.Snapshot()
	original := mustNode(t, s, ids[1]).AsStruct()
	changed := original.Clone()
	changed.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.99:1234")}
	s.PutNodeInStoreForTest(*changed)
	s.PutNodeInStoreForTest(*original)
	after := s.Snapshot()
	all, wake := Route(before, after, after.Since(before))
	require.False(t, all, "endpoint bursts must not wake the entire tailnet")
	require.Contains(t, wake, ids[0])
	require.Contains(t, wake, ids[1])
	require.NotContains(t, wake, ids[2])
}
