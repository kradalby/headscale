package mapper

import (
	"context"
	"encoding/json"
	"errors"
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
	"gorm.io/gorm"
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

// preNetmapRemovalsVer is one below the capability version of Tailscale v1.104,
// the first release whose clients also derived removals from a full netmap
// (tailscale/tailscale#15660): these clients still need explicit
// PeersRemoved frames. The hub emits them for every capability version.
const preNetmapRemovalsVer = capver.FullNetmapRemovalsCapVer - 1

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

		ServerURL: "https://headscale.test",
		Policy:    types.PolicyConfig{Mode: types.PolicyModeDB}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
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
		func() { _, _ = s.RenameNode(ids[0], "n1-renamed") },
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

		require.Empty(t, client.sameAs(newModelClient(fresh[0])), "step %d", i)
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

func mustNode(tb testing.TB, s *state.State, id types.NodeID) types.NodeView {
	tb.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(tb, ok)

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
		if len(r.Node.Tags) > 0 {
			c.seen[tailcfg.UserID(types.TaggedDevicesUserID)] = true
		}

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
			// Node.Clone canonicalizes empty cap payload slices just as full maps do.
			p.CapMap = p.Clone().CapMap
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
		have, err := json.Marshal(c.peers)
		if err != nil {
			return fmt.Sprintf("peers: encoding current client: %v", err)
		}

		want, err := json.Marshal(fresh.peers)
		if err != nil {
			return fmt.Sprintf("peers: encoding fresh client: %v", err)
		}

		return fmt.Sprintf("peers: have %s, want %s", have, want)
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
	check(router) // The offline approved router is the remaining fallback.

	n = mustNode(t, s, router).AsStruct()
	n.ApprovedRoutes = nil
	s.PutNodeInStoreForTest(*n)
	check(0) // With all approvals removed, the class map is shared again.
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
				cfg, s := benchState(b, routers+2, 1)

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
			cfg, s := benchState(b, n, 1)
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

// benchState returns a full mesh of n nodes owned by users users.
func benchState(tb testing.TB, n, users int) (*types.Config, *state.State) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/h.db"},
		},

		ServerURL: "https://headscale.test",
		Policy:    types.PolicyConfig{Mode: types.PolicyModeDB}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	for i, u := range database.CreateUsersForTest(users, "u") {
		database.CreateRegisteredNodesForTest(u, n/users+min(1, max(0, n%users-i)), u.Name)
	}

	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = s.Close() })

	return cfg, s
}

// BenchmarkStreamsUpdateEndpointChurn measures every session's update after
// a tenth of the nodes moved endpoints: the cost of one write burst across
// the tailnet.
func BenchmarkStreamsUpdateEndpointChurn(b *testing.B) {
	const n = 200

	cfg, s := benchState(b, n, 1)
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
// per pair, and nothing may accumulate across renders. A user per node
// makes the profiles every session holds as many as its peers.
func BenchmarkStreamsRetainedHeap(b *testing.B) {
	for _, n := range []int{200, 1000} {
		for _, users := range []int{1, n} {
			b.Run(fmt.Sprintf("nodes=%d/users=%d", n, users), func(b *testing.B) {
				cfg, s := benchState(b, n, users)

				var iter uint16

				for b.Loop() {
					b.ReportMetric(retainedPerPair(b, cfg, s, iter), "B/pair")
					iter++
				}
			})
		}
	}
}

// TestStreamsRetainedHeapPerPair bounds what a session keeps per peer with
// a user per node against one user: the profiles of peers' owners are
// shared by a class's sessions, so owners must not add per-pair state.
func TestStreamsRetainedHeapPerPair(t *testing.T) {
	cfg, s := benchState(t, 200, 200)
	perPair := retainedPerPair(t, cfg, s, 0)

	oneCfg, oneUser := benchState(t, 200, 1)
	shared := retainedPerPair(t, oneCfg, oneUser, 0)

	t.Logf("%.1f B per pair with a user per node, %.1f B with one user", perPair, shared)
	assert.Less(t, perPair, 2*shared, "sessions keep their peers' owners' profiles each")
}

// retainedPerPair opens a session per node, applies ten rounds of
// endpoint writes, and returns the heap the sessions keep per pair. iter
// picks endpoints the nodes do not hold yet, so every call updates.
func retainedPerPair(tb testing.TB, cfg *types.Config, s *state.State, iter uint16) float64 {
	tb.Helper()

	ids := s.ListNodes()
	hub := NewHub()

	runtime.GC()

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	streams := make([]*Stream, 0, ids.Len())
	for _, nv := range ids.All() {
		st := NewStream(cfg, hub, nv.ID(), capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(tb, err)

		streams = append(streams, st)
	}

	updated := 0

	// The port wraps harmlessly.
	for round := range uint16(10) {
		port := 1 + iter*10 + round
		for i := int(round); i < ids.Len(); i += 10 {
			n := ids.At(i).AsStruct()
			n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
			s.PutNodeInStoreForTest(*n)
		}

		for _, st := range streams {
			out, err := st.Update(s.Snapshot())
			require.NoError(tb, err)

			if len(out) > 0 {
				updated++
			}
		}
	}

	if updated == 0 {
		tb.Fatal("a call updated no session")
	}

	runtime.GC()

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	runtime.KeepAlive(streams)

	// Signed: the heap can shrink across the call.
	retained := float64(after.HeapAlloc) - float64(before.HeapAlloc)

	return retained / float64(ids.Len()*ids.Len())
}

// BenchmarkScalingOneEndpointWrite measures the total cost of one node
// moving its endpoint, every connected session included, across tailnet
// sizes: how the common write scales with N.
func BenchmarkScalingOneEndpointWrite(b *testing.B) {
	for _, n := range []int{100, 200, 400, 800} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			cfg, s := benchState(b, n, 1)
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
// For "via", every tenth node is an online tag:r router sharing an HA
// subnet with the next one, reached through a via grant, so every peer
// render resolves via routes.
var scalingPolicies = map[string]string{
	"allow-all": `{}`,
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
	// The plain grant reaches nodes, not subnets, so a member sees a
	// subnet only through the router its via grant elects.
	"via": `{"tagOwners":{"tag:r":["u0@"]},"grants":[
		{"src":["*"],"dst":["autogroup:member","autogroup:tagged"],"ip":["*"]},
		{"src":["autogroup:member"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:r"]}]}`,
}

// scalingRouters makes every tenth node an online router for the "via"
// shape: consecutive routers pair up on one subnet, so each subnet has a
// primary and a standby.
func scalingRouters(tb testing.TB, s *state.State) {
	tb.Helper()

	for i, nv := range s.ListNodes().All() {
		if i%10 != 0 {
			continue
		}

		pair := i / 20
		route := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", pair/256, pair%256))

		_, err := s.SetNodeTags(nv.ID(), []string{"tag:r"})
		require.NoError(tb, err)

		node := mustNode(tb, s, nv.ID()).AsStruct()
		node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		s.PutNodeInStoreForTest(*node)

		_, err = s.SetApprovedRoutes(nv.ID(), []netip.Prefix{route})
		require.NoError(tb, err)

		s.Connect(nv.ID())
	}

	// The shape must exercise via elections: a member sees the first
	// subnet through the router the grant elected, and not through its
	// standby.
	snap := s.Snapshot()
	viewer, router, standby := s.ListNodes().At(1), s.ListNodes().At(0), s.ListNodes().At(10)
	matchers, err := snap.Policy().MatchersForNode(viewer)
	require.NoError(tb, err)

	subnet := netip.MustParsePrefix("10.0.0.0/24")
	require.Contains(tb, snap.RoutesForPeer(viewer, mustNode(tb, s, router.ID()), matchers), subnet)
	require.NotContains(tb, snap.RoutesForPeer(viewer, mustNode(tb, s, standby.ID()), matchers), subnet)

	// And it is the via grant that serves it, not HA primaries under a
	// plain grant.
	via := snap.Policy().ViaRoutesForPeer(viewer, mustNode(tb, s, router.ID()))
	require.Contains(tb, via.Include, subnet, "the via grant steers the subnet")
	require.NotContains(tb, via.UsePrimary, subnet, "a plain grant covers the subnet")
}

// scalingTailnet returns a tailnet of n nodes spread over 10 users under
// the named policy shape, with a session for every node.
func scalingTailnet(tb testing.TB, n int, shape string) (*state.State, []*Stream) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/h.db"},
		},

		ServerURL: "https://headscale.test",
		Policy:    types.PolicyConfig{Mode: types.PolicyModeDB}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential}, DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	users := database.CreateUsersForTest(10, "u")
	for i, u := range users {
		database.CreateRegisteredNodesForTest(u, n/10+min(1, max(0, n%10-i)), u.Name)
	}

	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = s.Close() })

	// CreateUsersForTest names users "u-0"; the policies say "u0@".
	for i, u := range users {
		_, err := s.RenameUser(types.UserID(u.ID), fmt.Sprintf("u%d", i))
		require.NoError(tb, err)
	}

	if shape == "tags" {
		for i, nv := range s.ListNodes().All() {
			node := nv.AsStruct()
			node.Tags = []string{fmt.Sprintf("tag:t%d", i%20)}
			s.PutNodeInStoreForTest(*node)
		}
	}

	_, err = s.SetPolicy([]byte(scalingPolicies[shape]))
	require.NoError(tb, err)

	if shape == "via" {
		scalingRouters(tb, s)
	}

	hub := NewHub()
	streams := make([]*Stream, 0, n)

	for _, nv := range s.ListNodes().All() {
		st := NewStream(cfg, hub, nv.ID(), capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(tb, err)
		st.Delivered()

		streams = append(streams, st)
	}

	return s, streams
}

// scalingWrites are the operations the scaling benchmarks measure,
// given a node ID and the iteration number.
var scalingWrites = map[string]func(tb testing.TB, s *state.State, id types.NodeID, i int){
	"endpoint": scalingEndpoint,
	// endpoints writes 16 nodes, which the hub routes as one change, as it
	// does commits that coalesce under load.
	"endpoints-x16": func(tb testing.TB, s *state.State, _ types.NodeID, i int) {
		tb.Helper()

		nodes := s.ListNodes()
		for j := range 16 {
			scalingEndpoint(tb, s, nodes.At((i*16+j)%nodes.Len()).ID(), i)
		}
	},
	"online": func(tb testing.TB, s *state.State, id types.NodeID, _ int) {
		tb.Helper()

		nv := mustNode(tb, s, id)

		if nv.IsOnline().Valid() && nv.IsOnline().Get() {
			_ = s.Disconnect(nv.ID(), nv.SessionEpoch())
		} else {
			_ = s.Connect(nv.ID())
		}
	},
	// rejoin is two commits the hub routes as one, so it wakes every
	// session; see [state.Snapshot.Since].
	"rejoin": func(tb testing.TB, s *state.State, id types.NodeID, _ int) {
		tb.Helper()

		node := mustNode(tb, s, id).AsStruct()
		s.DeleteNodeFromStoreForTest(node.ID)
		s.PutNodeInStoreForTest(*node)
	},
	"rename": func(tb testing.TB, s *state.State, id types.NodeID, i int) {
		tb.Helper()

		_, err := s.RenameNode(id, fmt.Sprintf("renamed-%d", i))
		require.NoError(tb, err)
	},
	"policy": func(tb testing.TB, s *state.State, _ types.NodeID, i int) {
		tb.Helper()

		_, err := s.SetPolicy([]byte(fmt.Sprintf(`{"acls":[{"action":"accept","src":["*"],"dst":["*:%d"]}]}`, 1+i%2)))
		require.NoError(tb, err)
	},
	// Offline, unrouted nodes ignore unhealthy reports; healthy reports
	// already match their state. This measures requests, not health changes.
	"ignored-health": func(_ testing.TB, s *state.State, id types.NodeID, i int) {
		_ = s.SetNodeHealth(id, i%2 == 0)
	},
	"derp": func(_ testing.TB, s *state.State, _ types.NodeID, i int) {
		s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			tailcfg.DERPRegionID(900 + i%2): {RegionID: tailcfg.DERPRegionID(900 + i%2)},
		}})
	},
}

func TestScalingEndpointWrite(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	before := s.Snapshot()
	node := mustNode(t, s, ids[0])
	st := NewStream(cfg, NewHub(), ids[1], capVer)
	_, err := st.Initial(before)
	require.NoError(t, err)
	st.Delivered()

	scalingWrites["endpoint"](t, s, ids[0], 1234)

	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}
	after := s.Snapshot()
	updated := mustNode(t, s, ids[0])
	require.Equal(t, want, updated.Endpoints().AsSlice())
	require.Equal(t, node.NodeKey(), updated.NodeKey())
	require.Equal(t, node.DiscoKey(), updated.DiscoKey())
	require.Equal(t, node.GivenName(), updated.GivenName())
	require.Equal(t, before.PolicyRev(), after.PolicyRev())
	require.Equal(t, before.PeersRev(), after.PeersRev())

	row, err := s.DB().GetNodeByID(ids[0])
	require.NoError(t, err)
	require.Empty(t, row.Endpoints.List(), "the endpoint workload measures the control plane, not SQLite")

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all)
	require.Contains(t, wake, ids[1])
	require.NotContains(t, wake, ids[2])

	responses, err := st.Update(after)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	require.Len(t, responses[0].PeersChangedPatch, 1)
	require.Equal(t, ids[0].NodeID(), responses[0].PeersChangedPatch[0].NodeID)
	require.Equal(t, want, responses[0].PeersChangedPatch[0].Endpoints)
}

// BenchmarkScalingWrites measures one write and the updates, encoded, of
// the sessions the hub routes it to, across write kinds, policy shapes and
// tailnet sizes. woken/op counts the sessions routed, updates/op those
// with something to send: the work a write needs. peer-renders/op counts
// added or changed peer references per session, not shared TailNode calls.
// For policy writes, shape is the starting policy: setup opens visibility
// to every node, and the loop only alternates its port. Endpoint writes use
// the test store to update the immutable world without SQL. Every session
// encodes its response and confirms delivery. BenchmarkSTUNEndpointReports
// separately measures public MapRequests, including SQL persistence.
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
					sc := newScalingRun(s, streams)

					write := scalingWrites[kind]

					sc.warm(b, kind)
					sc.woken, sc.updates, sc.rendered, sc.quiet = 0, 0, 0, 0

					var i int

					for b.Loop() {
						sc.step(b, write, i)
						i++
					}

					sc.requireSettled(b, kind)

					b.ReportMetric(float64(sc.woken)/float64(i), "woken/op")
					b.ReportMetric(float64(sc.updates)/float64(i), "updates/op")
					b.ReportMetric(float64(sc.rendered)/float64(i), "peer-renders/op")
				})
			}
		}
	}
}

// scalingEndpoint moves node id to endpoint port i in the store: the
// benchmarks measure the control plane's work for the write, not SQLite.
func scalingEndpoint(tb testing.TB, s *state.State, id types.NodeID, i int) {
	tb.Helper()

	node := mustNode(tb, s, id).AsStruct()
	node.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i))} //nolint:gosec // benchmark cycles ports
	s.PutNodeInStoreForTest(*node)
}

// scalingRun routes writes to a tailnet's sessions as the hub does and
// counts the work: sessions woken, those with something to send, and the
// peers they rendered.
type scalingRun struct {
	s       *state.State
	streams []*Stream
	byNode  map[types.NodeID]*Stream
	last    *state.Snapshot

	woken, updates, rendered int

	// quiet counts writes that woke no session.
	quiet int
}

func newScalingRun(s *state.State, streams []*Stream) *scalingRun {
	sc := &scalingRun{s: s, streams: streams, byNode: make(map[types.NodeID]*Stream, len(streams)), last: s.Snapshot()}
	for _, st := range streams {
		sc.byNode[st.nodeID] = st
	}

	return sc
}

// warm performs the policy workload's first write, which expands
// visibility to every node, so the writes after it measure steady port
// alternation instead of one cold expansion amortized over b.N. It lands
// on port 2, so the first write after it, port 1, is a change too.
func (sc *scalingRun) warm(tb testing.TB, kind string) {
	tb.Helper()

	if kind == "policy" {
		sc.step(tb, scalingWrites[kind], 1)
	}
}

// step makes write i on the i-th session's node and updates, encodes for
// and confirms delivery to the sessions it wakes.
func (sc *scalingRun) step(tb testing.TB, write func(testing.TB, *state.State, types.NodeID, int), i int) {
	tb.Helper()

	write(tb, sc.s, sc.streams[i%len(sc.streams)].nodeID, i)

	snap := sc.s.Snapshot()
	all, wake := Route(sc.last, snap, snap.Since(sc.last))
	sc.last = snap

	// Visit the woken sessions only, as the hub does.
	targets := sc.streams
	if !all {
		targets = targets[:0:0]

		for id := range wake {
			if st, ok := sc.byNode[id]; ok {
				targets = append(targets, st)
			}
		}
	}

	if len(targets) == 0 {
		sc.quiet++
	}

	for _, st := range targets {
		sc.woken++
		before := st.r.rendered

		out, err := st.Update(snap)
		if err != nil {
			tb.Fatal(err)
		}

		if len(out) > 0 {
			sc.updates++
		}

		for _, resp := range out {
			_, err := st.hub.Encode(resp, true, benchEncode)
			if err != nil {
				tb.Fatal(err)
			}
		}

		st.Delivered()

		sc.rendered += st.r.rendered - before
	}
}

// requireSettled checks, outside any timed loop, what the steps must
// leave behind: every delivery confirmed, and for the policy workload a
// session woken by every write. A reflection-based assert per step would
// be timed work.
func (sc *scalingRun) requireSettled(tb testing.TB, kind string) {
	tb.Helper()

	for _, st := range sc.streams {
		require.Nil(tb, st.pending, "successful writes confirm delivery even when attempts would fold")
		require.Empty(tb, st.hub.sentPeers[st.nodeID].attempts, "successful writes leave no failed-write history")
	}

	// A policy write that repeats the previous port rewrites the identical
	// document and wakes nothing, whatever the benchtime.
	if kind == "policy" {
		require.Zero(tb, sc.quiet, "every policy write wakes work")
	}
}

// TestScalingWriteWork pins the work each write kind costs at one size,
// what [BenchmarkScalingWrites] reports but no CI lane runs. The counts are
// exact, so a change doing more fails and one doing less must lower them.
// Rows above what the write needs say so, with the item that would lower
// them.
func TestScalingWriteWork(t *testing.T) {
	const n, writes = 100, 4

	// Sessions woken, sessions sent an update and peers rendered, over the
	// writes. A session sees its own class of ten nodes under the self and
	// users shapes, and the two tags its tag reaches under tags.
	//
	// Policy rows add the setup write that expands visibility, which every
	// session renders, to the writes that only alternate its port.
	//
	// Rejoin is two commits the hub routes as one, which wakes every
	// session (Snapshot.Since escalation, N2): above need.
	//
	// The via shape sees what allow-all does, plus routes that differ per
	// viewer: a write that moves the policy or a via election, as policy
	// and rejoin writes and a router going offline do, re-renders every
	// routed peer in every session (renderPeers), five primary routers
	// here, where only the routers the election steers to or from need it:
	// above need, as the renderer cannot tell which those are. The first
	// online write also changes the router's own PrimaryRoutes. Rejoin
	// restores its original SessionStart, so final wire state is unchanged.
	ceilings := map[string][3]int{
		"derp/allow-all":           {400, 400, 0},
		"derp/self":                {400, 400, 0},
		"derp/tags":                {400, 400, 0},
		"derp/users":               {400, 400, 0},
		"derp/via":                 {400, 400, 0},
		"endpoint/allow-all":       {400, 400, 396},
		"endpoint/self":            {40, 40, 36},
		"endpoint/tags":            {44, 44, 40},
		"endpoint/users":           {40, 40, 36},
		"endpoint/via":             {400, 400, 396},
		"endpoints-x16/allow-all":  {400, 400, 6336},
		"endpoints-x16/self":       {100, 100, 576},
		"endpoints-x16/tags":       {360, 360, 640},
		"endpoints-x16/users":      {100, 100, 576},
		"endpoints-x16/via":        {400, 400, 6336},
		"ignored-health/allow-all": {0, 0, 0},
		"ignored-health/self":      {0, 0, 0},
		"ignored-health/tags":      {0, 0, 0},
		"ignored-health/users":     {0, 0, 0},
		"ignored-health/via":       {0, 0, 0},
		"online/allow-all":         {400, 396, 396},
		"online/self":              {40, 36, 36},
		"online/tags":              {44, 40, 40},
		"online/users":             {40, 36, 36},
		"online/via":               {400, 397, 891},
		"policy/allow-all":         {500, 500, 0},
		"policy/self":              {500, 500, 9000},
		"policy/tags":              {500, 500, 8900},
		"policy/users":             {500, 500, 9000},
		"policy/via":               {500, 500, 2475},
		"rejoin/allow-all":         {400, 0, 396},
		"rejoin/self":              {400, 0, 36},
		"rejoin/tags":              {400, 0, 40},
		"rejoin/users":             {400, 0, 36},
		"rejoin/via":               {400, 0, 2277},
		"rename/allow-all":         {400, 400, 396},
		"rename/self":              {40, 40, 36},
		"rename/tags":              {44, 44, 40},
		"rename/users":             {40, 40, 36},
		"rename/via":               {400, 400, 396},
	}

	for _, kind := range slices.Sorted(maps.Keys(scalingWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			t.Run(kind+"/"+shape, func(t *testing.T) {
				s, streams := scalingTailnet(t, n, shape)
				sc := newScalingRun(s, streams)
				sc.warm(t, kind)

				for i := range writes {
					sc.step(t, scalingWrites[kind], i)
				}

				sc.requireSettled(t, kind)

				limit, ok := ceilings[kind+"/"+shape]
				require.True(t, ok, "no ceiling for %s/%s", kind, shape)

				got := [3]int{sc.woken, sc.updates, sc.rendered}
				assert.Equal(t, limit, got, "sessions woken, updated, peers rendered")
			})
		}
	}
}

// BenchmarkRouteCoalescedWrites measures Route alone over k endpoint
// writes, which the hub routes as one change when commits coalesce: its
// cost should follow the sessions it wakes, not k.
func BenchmarkRouteCoalescedWrites(b *testing.B) {
	for _, shape := range []string{"allow-all", "users"} {
		for _, k := range []int{1, 16, 200} {
			b.Run(fmt.Sprintf("%s/nodes=1000/changed=%d", shape, k), func(b *testing.B) {
				s, _ := scalingTailnet(b, 1000, shape)
				old := s.Snapshot()
				nodes := s.ListNodes()

				for i := range k {
					node := nodes.At(i).AsStruct()
					node.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
					s.PutNodeInStoreForTest(*node)
				}

				cur := s.Snapshot()
				c := cur.Since(old)
				require.False(b, c.Global, "test sanity: endpoint writes are scoped")

				for b.Loop() {
					Route(old, cur, c)
				}
			})
		}
	}
}

// TestRouteWalksEachViewOnce changes many nodes of one class: Route must
// walk the class's shared view once, not once per changed node. The work
// tests count woken sessions and renders, which a repeated walk of the
// same view does not change.
func TestRouteWalksEachViewOnce(t *testing.T) {
	s, _ := scalingTailnet(t, 100, "allow-all")
	old := s.Snapshot()
	nodes := s.ListNodes()

	changed := make([]types.NodeID, 0, 20)

	for i := range 20 {
		node := nodes.At(i).AsStruct()
		node.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
		s.PutNodeInStoreForTest(*node)
		changed = append(changed, node.ID)
	}

	cur := s.Snapshot()
	assert.Len(t, reachedViews(old, cur, changed), 1, "allow-all has one class")

	all, wake := Route(old, cur, cur.Since(old))
	assert.False(t, all)
	assert.Len(t, wake, nodes.Len(), "every node sees the changed ones")
}

// TestRouteWakesNewPrimary fails over a route between two routers that
// cannot see each other: the one taking the route did not change, and no
// node it sees changed, yet its own map now carries the route.
func TestRouteWakesNewPrimary(t *testing.T) {
	_, s, ids := streamTestState(t, `{"tagOwners":{"tag:r":["u1@"]},"acls":[{"action":"accept","src":["u2@"],"dst":["tag:r:*","10.0.0.0/24:*"]}]}`)
	r1, r2 := ids[0], ids[1]

	route := netip.MustParsePrefix("10.0.0.0/24")
	gens := map[types.NodeID]uint64{}

	for _, id := range []types.NodeID{r1, r2} {
		_, err := s.SetNodeTags(id, []string{"tag:r"})
		require.NoError(t, err)
		n := mustNode(t, s, id).AsStruct()
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		s.PutNodeInStoreForTest(*n)

		_, err = s.SetApprovedRoutes(id, []netip.Prefix{route})
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

func TestStreamViaMixedInternetAndSubnetRoutes(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{
		"tagOwners":{"tag:via":["u1@"]},
		"grants":[{"src":["u2@"],"dst":["10.0.0.0/24","2001:db8::/64","autogroup:internet"],"ip":["*"],"via":["tag:via"]}]
	}`)
	routes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("2001:db8::/64"),
		tsaddr.AllIPv4(),
		tsaddr.AllIPv6(),
	}
	_, err := s.SetNodeTags(ids[0], []string{"tag:via"})
	require.NoError(t, err)

	for _, id := range []types.NodeID{ids[1], ids[0]} {
		n := mustNode(t, s, id).AsStruct()
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
		s.PutNodeInStoreForTest(*n)
		_, err := s.SetApprovedRoutes(id, routes)
		require.NoError(t, err)
		s.Connect(id)
	}

	st := NewStream(cfg, NewHub(), ids[2], capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])
	peer := client.peers[ids[0].NodeID()]
	require.NotNil(t, peer)

	for _, route := range routes {
		assert.Contains(t, peer.AllowedIPs, route)

		if other := client.peers[ids[1].NodeID()]; other != nil {
			assert.NotContains(t, other.AllowedIPs, route)
		}
	}
}

func TestStreamViaInternetSurvivesRegularGrant(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%t", reverse), func(t *testing.T) {
			grants := []string{
				`{"src":["u2@"],"dst":["autogroup:internet"],"ip":["*"],"via":["tag:a"]}`,
				`{"src":["u2@"],"dst":["autogroup:internet"],"ip":["*"],"via":["tag:b"]}`,
				`{"src":["u2@"],"dst":["tag:a"],"ip":["*"]}`,
			}
			if reverse {
				slices.Reverse(grants)
			}

			cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},"grants":[`+strings.Join(grants, ",")+`]}`)
			routes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}
			_, err := s.SetNodeTags(ids[0], []string{"tag:a"})
			require.NoError(t, err)

			n := mustNode(t, s, ids[0]).AsStruct()
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
			s.PutNodeInStoreForTest(*n)
			_, err = s.SetApprovedRoutes(ids[0], routes)
			require.NoError(t, err)
			s.Connect(ids[0])

			st := NewStream(cfg, NewHub(), ids[2], capVer)
			initial, err := st.Initial(s.Snapshot())
			require.NoError(t, err)

			peer := newModelClient(initial[0]).peers[ids[0].NodeID()]
			require.NotNil(t, peer)

			for _, route := range routes {
				assert.Contains(t, peer.AllowedIPs, route)
				assert.NotContains(t, peer.PrimaryRoutes, route)
			}
		})
	}
}

func TestStreamViaIndependentGrants(t *testing.T) {
	for _, tt := range []struct {
		name     string
		tags     [2][]string
		offlineB bool
		want     [2]bool
	}{
		{name: "empty", tags: [2][]string{{"tag:a"}, nil}, want: [2]bool{true, false}},
		{name: "offline", tags: [2][]string{{"tag:a"}, {"tag:b"}}, offlineB: true, want: [2]bool{true, true}},
		{name: "disjoint", tags: [2][]string{{"tag:a"}, {"tag:b"}}, want: [2]bool{true, true}},
		{name: "overlap", tags: [2][]string{{"tag:a", "tag:b"}, {"tag:b"}}, want: [2]bool{true, false}},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", tt.name, reverse), func(t *testing.T) {
				grants := []string{
					`{"src":["u2@"],"dst":["10.0.0.0/24"],"ip":["*"],"via":["tag:a"]}`,
					`{"src":["u2@"],"dst":["10.0.0.0/24"],"ip":["*"],"via":["tag:b"]}`,
				}
				if reverse {
					slices.Reverse(grants)
				}

				cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},"grants":[`+strings.Join(grants, ",")+`]}`)
				route := netip.MustParsePrefix("10.0.0.0/24")

				for i, id := range ids[:2] {
					if len(tt.tags[i]) > 0 {
						_, err := s.SetNodeTags(id, tt.tags[i])
						require.NoError(t, err)
					}

					n := mustNode(t, s, id).AsStruct()
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
					s.PutNodeInStoreForTest(*n)
					_, err := s.SetApprovedRoutes(id, []netip.Prefix{route})
					require.NoError(t, err)

					if i != 1 || !tt.offlineB {
						s.Connect(id)
					}
				}

				st := NewStream(cfg, NewHub(), ids[2], capVer)
				initial, err := st.Initial(s.Snapshot())
				require.NoError(t, err)

				client := newModelClient(initial[0])
				for i, id := range ids[:2] {
					peer := client.peers[id.NodeID()]
					if tt.want[i] {
						require.NotNil(t, peer)
						assert.Contains(t, peer.AllowedIPs, route)
						assert.Contains(t, peer.PrimaryRoutes, route)
					} else if peer != nil {
						assert.NotContains(t, peer.AllowedIPs, route)
						assert.NotContains(t, peer.PrimaryRoutes, route)
					}
				}
			})
		}
	}
}

// viaSourceCheck asserts the viewer client's via view of the two routers:
// the wanted router carries the route, the other does not, and want 0
// asserts the viewer outside the source is told no via peer at all and
// steers nothing through the routers it cannot see.
func viaSourceCheck(
	t *testing.T,
	s *state.State,
	ids [3]types.NodeID,
	route netip.Prefix,
	client *modelClient,
	want types.NodeID,
) {
	t.Helper()

	for _, id := range ids[:2] {
		peer := client.peers[id.NodeID()]
		switch {
		case id == want:
			require.NotNil(t, peer)
			assert.Contains(t, peer.AllowedIPs, route)
		case want == 0:
			// A viewer outside the source is told no via peer at all,
			// and the via result steers nothing through the routers
			// it cannot see.
			assert.NotContains(t, client.peers, id.NodeID(), "a viewer outside the source sees no via peer")

			live := s.Snapshot()
			v, _ := live.GetNode(ids[2])

			routerView, ok := live.GetNode(id)
			if assert.True(t, ok) {
				via := live.Policy().ViaRoutesForPeer(v, routerView)
				assert.Empty(t, via.Include, "a viewer outside the source steers no route to the router")
				assert.Empty(t, via.Exclude, "a viewer outside the source steers nothing away from the router either")
			}
		case peer != nil:
			assert.NotContains(t, peer.AllowedIPs, route)
		}
	}
}

func TestStreamViaSourceSubnets(t *testing.T) {
	for _, family := range []struct {
		name, source, advertised, destination, route, unrelated, exit string
	}{
		{"ipv4", "10.44.0.128/25", "10.44.0.0/24", "10.45.0.128/25", "10.45.0.0/24", "10.46.0.0/24", "0.0.0.0/0"},
		{"ipv6", "2001:db8:44::/65", "2001:db8:44::/64", "2001:db8:45::/65", "2001:db8:45::/64", "2001:db8:46::/64", "::/0"},
	} {
		for _, mode := range []string{"approved", "unapproved", "withdrawn", "unrelated", "exit-only", "regular-overlap", "tag-source", "tag-source-unrelated"} {
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				grant := fmt.Sprintf(`{"src":[%q],"dst":[%q],"ip":["tcp:443"],"via":["tag:via"]}`, family.source, family.destination)
				tagOwners := `"tag:via":["u1@"]`

				if mode == "regular-overlap" {
					grant = fmt.Sprintf(`{"src":["u2@"],"dst":[%q],"ip":["tcp:443"],"via":["tag:via"]},
						{"src":[%q],"dst":[%q],"ip":["tcp:443"]}`, family.destination, family.source, family.destination)
				}

				if strings.HasPrefix(mode, "tag-source") {
					// The source is a tag: only a viewer advertising an
					// approved subnet covering a member's address matches,
					// because its own addresses are not the member's.
					grant = fmt.Sprintf(`{"src":["tag:viewer"],"dst":[%q],"ip":["tcp:443"],"via":["tag:via"]}`, family.destination)
					tagOwners = `"tag:via":["u1@"],"tag:viewer":["u1@"]`
				}

				cfg, s, ids := streamTestState(t, `{"tagOwners":{`+tagOwners+`},"grants":[`+grant+`]}`)
				route := netip.MustParsePrefix(family.route)

				for _, id := range []types.NodeID{ids[1], ids[0]} {
					if mode != "regular-overlap" || id == ids[0] {
						_, err := s.SetNodeTags(id, []string{"tag:via"})
						require.NoError(t, err)
					}

					n := mustNode(t, s, id).AsStruct()
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
					s.PutNodeInStoreForTest(*n)
					_, err := s.SetApprovedRoutes(id, []netip.Prefix{route})
					require.NoError(t, err)
					s.Connect(id)
				}

				if strings.HasPrefix(mode, "tag-source") {
					// The via router ids[0] doubles as the source member; the
					// viewer stays untagged so only its advertised subnet can
					// match the tag-resolved source.
					_, err := s.SetNodeTags(ids[0], []string{"tag:via", "tag:viewer"})
					require.NoError(t, err)
				}

				source := netip.MustParsePrefix(family.advertised)

				switch mode {
				case "unrelated":
					source = netip.MustParsePrefix(family.unrelated)
				case "exit-only":
					source = netip.MustParsePrefix(family.exit)
				case "tag-source", "tag-source-unrelated":
					// Covers the member's tailnet address (or nothing, for
					// the unrelated sibling); the viewer's own address is
					// another host's, so only the advertised subnet can
					// match the tag-resolved source.
					covering, unrelatedSrc := "100.64.0.0/24", "10.99.0.0/24"
					if family.name == "ipv6" {
						covering, unrelatedSrc = "fd7a:115c:a1e0::/64", "2001:db8:99::/64"
					}

					if mode == "tag-source" {
						source = netip.MustParsePrefix(covering)
					} else {
						source = netip.MustParsePrefix(unrelatedSrc)
					}
				}

				viewer := mustNode(t, s, ids[2]).AsStruct()
				viewer.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{source}}
				s.PutNodeInStoreForTest(*viewer)

				if mode != "unapproved" {
					_, err := s.SetApprovedRoutes(ids[2], []netip.Prefix{source})
					require.NoError(t, err)
				}

				if mode == "withdrawn" {
					viewer = mustNode(t, s, ids[2]).AsStruct()
					viewer.Hostinfo.RoutableIPs = nil
					s.PutNodeInStoreForTest(*viewer)
				}

				snap := s.Snapshot()
				hub := NewHub()
				t.Cleanup(hub.Close)
				st := NewStream(cfg, hub, ids[2], capVer)
				initial, err := st.Initial(snap)
				require.NoError(t, err)
				st.Delivered()

				client := newModelClient(initial[0])

				want := types.NodeID(0)
				if mode == "approved" || mode == "regular-overlap" || mode == "tag-source" {
					want = ids[1]
				}

				viaSourceCheck(t, s, ids, route, client, want)

				// Routing uses the advertised prefix, not broader packet authorization.
				routerMap, err := NewStream(cfg, hub, ids[0], capVer).Initial(snap)
				require.NoError(t, err)

				authorized := false

				for _, rule := range newModelClient(routerMap[0]).filter {
					for _, dst := range rule.DstPorts {
						assert.NotEqual(t, family.route, dst.IP)

						if dst.IP == family.destination && dst.Ports.First == 443 && dst.Ports.Last == 443 {
							authorized = true
						}
					}
				}

				if want != 0 {
					assert.True(t, authorized, "the narrower destination and permitted port remain in the packet filter")
				}

				if mode == "approved" {
					_ = s.SetNodeHealth(ids[1], false)
					responses, err := st.Update(s.Snapshot())
					require.NoError(t, err)

					for _, response := range responses {
						client.apply(response)
					}

					st.Delivered()
					viaSourceCheck(t, s, ids, route, client, ids[0])

					_, err = s.SetApprovedRoutes(ids[2], nil)
					require.NoError(t, err)
					responses, err = st.Update(s.Snapshot())
					require.NoError(t, err)

					for _, response := range responses {
						client.apply(response)
					}

					st.Delivered()
					viaSourceCheck(t, s, ids, route, client, 0)

					old, err := NewStream(cfg, hub, ids[2], capVer).r.render(snap)
					require.NoError(t, err)

					client = newModelClient(fullResponse(cfg, old))

					viaSourceCheck(t, s, ids, route, client, ids[1])
				}
			})
		}
	}
}

func TestStreamViaRouteFailover(t *testing.T) {
	for _, failure := range []string{"offline", "unhealthy", "coalesced"} {
		t.Run(failure, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, `{
				"tagOwners":{"tag:via":["u1@"]},
				"grants":[{"src":["u2@"],"dst":["10.0.0.0/24"],"ip":["*"],"via":["tag:via"]}]
			}`)
			route := netip.MustParsePrefix("10.0.0.0/24")
			outside := s.DB().CreateRegisteredNodeForTest(s.DB().CreateUserForTest("outside"), "outside")
			s.PutNodeInStoreForTest(*outside)

			epochs := map[types.NodeID]uint64{}

			for _, id := range []types.NodeID{outside.ID, ids[0], ids[1]} {
				if id != outside.ID {
					_, err := s.SetNodeTags(id, []string{"tag:via"})
					require.NoError(t, err)
				}

				n := mustNode(t, s, id).AsStruct()
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
				s.PutNodeInStoreForTest(*n)
				_, err := s.SetApprovedRoutes(id, []netip.Prefix{route})
				require.NoError(t, err)

				epochs[id] = s.Connect(id)
			}

			before := s.Snapshot()
			primary, ok := before.PrimaryRouteFor(route)
			require.True(t, ok)
			require.Equal(t, outside.ID, primary, "global election must not choose either via router")

			st := NewStream(cfg, NewHub(), ids[2], capVer)
			initial, err := st.Initial(before)
			require.NoError(t, err)

			client := newModelClient(initial[0])

			st.Delivered()

			check := func(want types.NodeID) {
				t.Helper()

				for _, id := range []types.NodeID{outside.ID, ids[0], ids[1]} {
					peer := client.peers[id.NodeID()]
					if id == want {
						require.NotNil(t, peer)
						require.Contains(t, peer.AllowedIPs, route)
						require.Contains(t, peer.PrimaryRoutes, route)
					} else if peer != nil {
						require.NotContains(t, peer.AllowedIPs, route)
						require.NotContains(t, peer.PrimaryRoutes, route)
					}
				}
			}
			check(ids[0])

			if failure == "unhealthy" {
				_ = s.SetNodeHealth(ids[0], false)
			} else {
				require.NoError(t, s.Disconnect(ids[0], epochs[ids[0]]))

				if failure == "coalesced" {
					epochs[ids[0]] = s.Connect(ids[0])
				}
			}

			after := s.Snapshot()
			require.Equal(t, before.PolicyRev(), after.PolicyRev())
			require.Equal(t, before.PeersRev(), after.PeersRev())
			require.Equal(t, before.PrimaryRoutes(), after.PrimaryRoutes())
			all, wake := Route(before, after, after.Since(before))
			require.True(t, all || slices.Contains(slices.Collect(maps.Keys(wake)), ids[2]), "via failover must wake its viewer")

			update := func() {
				responses, err := st.Update(s.Snapshot())
				require.NoError(t, err)

				for _, response := range responses {
					client.apply(response)
				}

				st.Delivered()

				fresh, err := NewStream(cfg, NewHub(), ids[2], capVer).Initial(s.Snapshot())
				require.NoError(t, err)
				require.Empty(t, client.sameAs(newModelClient(fresh[0])))
			}
			update()
			check(ids[1])

			switch failure {
			case "unhealthy":
				_ = s.SetNodeHealth(ids[0], true)
			case "offline":
				epochs[ids[0]] = s.Connect(ids[0])
			}

			update()

			if failure == "unhealthy" {
				check(ids[0]) // Main 4342883bd: a retained older session takes its route back.
			} else {
				check(ids[1]) // A reconnected router has a newer session and stays standby.
			}

			require.NoError(t, s.Disconnect(ids[0], epochs[ids[0]]))
			require.NoError(t, s.Disconnect(ids[1], epochs[ids[1]]))
			update()
			check(ids[0]) // Main pure VIA fallback uses the lowest approved candidate, independently of global incumbent fallback.

			for _, id := range ids[:2] {
				_, err := s.SetApprovedRoutes(id, nil)
				require.NoError(t, err)
			}

			update()
			check(0) // Removing approvals still removes routes from every viewer.

			old, err := NewStream(cfg, NewHub(), ids[2], capVer).Initial(before)
			require.NoError(t, err)

			client = newModelClient(old[0])

			check(ids[0])
		})
	}
}

// TestPrimaryMoveRendersOnlyTheMovedRouters fails over one HA subnet in a
// tailnet with other routers: a viewer must render the routes of the two
// routers whose primaries moved, not of every router, and still converge
// on a fresh session's map.
func TestPrimaryMoveRendersOnlyTheMovedRouters(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	r1, r2, viewer := ids[0], ids[1], ids[2]

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	gens := map[types.NodeID]uint64{}
	route := func(id types.NodeID, prefix netip.Prefix) {
		n := mustNode(t, s, id).AsStruct()
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{prefix}}
		s.PutNodeInStoreForTest(*n)

		_, err := s.SetApprovedRoutes(id, []netip.Prefix{prefix})
		require.NoError(t, err)

		gens[id] = s.Connect(id)
	}

	ha := netip.MustParsePrefix("10.0.0.0/24")
	route(r1, ha)
	route(r2, ha)

	for i := range 3 {
		n := s.CreateRegisteredNodeForTest(u1, fmt.Sprintf("router-%d", i))
		n.User = u1
		s.PutNodeInStoreForTest(*n)
		route(n.ID, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24))
	}

	st := NewStream(cfg, NewHub(), viewer, capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])
	for _, resp := range initial[1:] {
		client.apply(resp)
	}

	primary, _ := s.Snapshot().PrimaryRouteFor(ha)
	require.Equal(t, r1, primary, "test sanity")

	before := st.r.rendered

	require.NoError(t, s.Disconnect(r1, gens[r1]))

	primary, _ = s.Snapshot().PrimaryRouteFor(ha)
	require.Equal(t, r2, primary, "test sanity: the route failed over")

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	assert.Equal(t, 2, st.r.rendered-before, "the routers whose primaries stayed are rendered again")

	for _, resp := range resps {
		client.apply(resp)
	}

	fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	assert.Empty(t, client.sameAs(newModelClient(fresh[0])), "the session converges on a fresh map")
}

// TestRendererForgetsRoutersItNoLongerRenders keeps one session through
// router churn: routers that are deleted, or stop serving routes, must not
// stay in the renderer's record of routed peers, which would otherwise
// grow with every router the session ever saw.
func TestRendererForgetsRoutersItNoLongerRenders(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	st := NewStream(cfg, NewHub(), ids[2], capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)

	routed := func() int { return len(st.r.routedPrimaries) }

	for i := range 12 {
		n := s.CreateRegisteredNodeForTest(u1, fmt.Sprintf("churn-%d", i))
		n.User = u1
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 2, byte(i), 0}), 24)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{prefix}}
		s.PutNodeInStoreForTest(*n)

		_, err := s.SetApprovedRoutes(n.ID, []netip.Prefix{prefix})
		require.NoError(t, err)
		s.Connect(n.ID)

		_, err = st.Update(s.Snapshot())
		require.NoError(t, err)
		require.Equal(t, 1, routed(), "test sanity: router %d is rendered with its routes", i)

		if i%2 == 0 {
			require.NoError(t, s.DeleteNode(mustNode(t, s, n.ID)))
		} else {
			_, err = s.SetApprovedRoutes(n.ID, nil)
			require.NoError(t, err)
		}

		_, err = st.Update(s.Snapshot())
		require.NoError(t, err)
		assert.Zero(t, routed(), "after router %d went: deleted and route-less routers stay recorded", i)
	}
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
	b, err := Marshal(resp)
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

// TestFramePatchesKeepOnlyTheLatestCommit churns one peer's endpoints: the
// shared patches must hold only the latest commit's, not one per write,
// each pinning two superseded renders.
func TestFramePatchesKeepOnlyTheLatestCommit(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	streams := make([]*Stream, 0, 2)

	for _, id := range ids[:2] {
		st := NewStream(cfg, hub, id, capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		streams = append(streams, st)
	}

	moving := mustNode(t, s, ids[2]).AsStruct()

	for i := range uint16(50) {
		moving.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), i+1)}
		s.PutNodeInStoreForTest(*moving)

		var shared *tailcfg.MapResponse

		for _, st := range streams {
			resps, err := st.Update(s.Snapshot())
			require.NoError(t, err)
			require.Len(t, resps, 1)
			require.Len(t, resps[0].PeersChangedPatch, 1, "test sanity: an endpoint write is a patch")

			if shared == nil {
				shared = resps[0]
			}

			require.Same(t, shared, resps[0], "viewers of one commit share its patch")
		}

		hub.frames.mu.Lock()
		held := len(hub.frames.patches)
		hub.frames.mu.Unlock()
		require.LessOrEqual(t, held, 1, "write %d: patches of superseded commits are kept", i)
	}
}

// TestFramesReleasedByCommitsWithoutPatches sends a shared patch, then
// moves the hub past it with a commit that only removes a node: no session
// shares anything for that commit, so nothing else would start the frame
// cache over, and the patch's two renders and response stayed rooted.
func TestFramesReleasedByCommitsWithoutPatches(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	streams := make([]*Stream, 0, 2)

	for _, id := range ids[:2] {
		st := NewStream(cfg, hub, id, capVer)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		streams = append(streams, st)
	}

	moving := mustNode(t, s, ids[2]).AsStruct()
	moving.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}
	s.PutNodeInStoreForTest(*moving)

	for _, st := range streams {
		resps, err := st.Update(s.Snapshot())
		require.NoError(t, err)
		require.Len(t, resps, 1)
		require.Len(t, resps[0].PeersChangedPatch, 1, "test sanity: an endpoint write is a patch")
	}

	frames := func() int {
		hub.frames.mu.Lock()
		defer hub.frames.mu.Unlock()

		return len(hub.frames.patches) + len(hub.frames.frames) + len(hub.frames.byResp)
	}
	require.NotZero(t, frames(), "test sanity: the patch is shared")

	s.DeleteNodeFromStoreForTest(ids[2])
	hub.advance(s.Snapshot())

	assert.Zero(t, frames(), "a later commit releases the frames of an earlier one")
}

// TestFirstMapDeliveryAfterFoldedAttempts checks a reconnect after folded
// attempts: a peer that joined after the last delivery, was folded into the
// node's history by failed attempts, then left, is announced as removed —
// a failed attempt may have shown it.
func TestFirstMapDeliveryAfterFoldedAttempts(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	// The delivered view holds neither the joining peer nor the node itself.
	joined := mustNode(t, s, ids[1]).AsStruct()
	s.DeleteNodeFromStoreForTest(ids[1])

	delivered := s.Snapshot()
	setup := NewStream(cfg, hub, ids[0], capVer)
	_, err := setup.Initial(delivered)
	require.NoError(t, err)
	setup.Delivered()

	// The peer joins: reconnect attempts at the newer snapshot fold its
	// view into the node's history.
	s.PutNodeInStoreForTest(*joined)
	seen := s.Snapshot()

	var last *Stream

	for range maxPeerAttempts + 1 {
		last = NewStream(cfg, hub, ids[0], capVer)
		_, err = last.Initial(seen)
		require.NoError(t, err)
	}

	require.Empty(t, hub.sentPeers[ids[0]].attempts, "folding does not mean a reconnect was delivered")
	require.Nil(t, setup.pending, "the setup stream cannot report reconnect delivery")
	require.NotNil(t, last.pending)

	// The peer leaves: the reconnect must announce its removal, because a
	// folded attempt may have shown it.
	s.DeleteNodeFromStoreForTest(ids[1])
	folded := s.Snapshot()

	reconnect := NewStream(cfg, hub, ids[0], capVer)
	resps, err := reconnect.Initial(folded)
	require.NoError(t, err)

	require.Len(t, resps, 2, "the reconnect announces the removed peer")
	require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, resps[1].PeersRemoved, "the folded history is what a reconnect removes")

	reconnect.Delivered()
	require.Nil(t, reconnect.pending)

	// The delivered reconnect records the peers the snapshot says it sees:
	// the hub's delivery record against the truth, not against itself.
	require.Equal(t, folded.PeerView(ids[0]), hub.lastPeers(ids[0]), "the delivered reconnect records the snapshot's peers")

	// The response decodes into the same model a fresh stream of the same
	// snapshot would build.
	fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(folded)
	require.NoError(t, err)
	require.Empty(t, newModelClient(resps[0]).sameAs(newModelClient(fresh[0])))
}

// BenchmarkFirstMap separates a reconnect on a warm hub from the first
// render on a cold hub and from reopening state (including Close). The last
// includes DB load, policy compile and peer construction, but not process
// startup, HTTP/Noise, or a concurrent reconnect storm.
func BenchmarkFirstMap(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s, streams := scalingTailnet(b, n, "allow-all")
			st := streams[len(streams)/2]
			snap := s.Snapshot()

			for _, cache := range []string{"warm-hub", "cold-hub", "new-state"} {
				for _, encoding := range []string{"json", "zstd"} {
					b.Run(cache+"/"+encoding, func(b *testing.B) {
						if cache == "warm-hub" {
							first := NewStream(st.cfg, st.hub, st.nodeID, capVer)
							resps, err := first.Initial(snap)
							require.NoError(b, err)
							_, err = st.hub.Encode(resps[0], encoding == "zstd", benchEncode)
							require.NoError(b, err)
							first.Delivered()
						}

						b.ReportAllocs()

						var (
							first *Stream
							size  int
						)

						for b.Loop() {
							hub, current := st.hub, snap
							if cache != "warm-hub" {
								hub = NewHub()
							}

							var reopened *state.State

							if cache == "new-state" {
								var err error

								reopened, err = state.NewState(st.cfg)
								require.NoError(b, err)

								current = reopened.Snapshot()
							}

							first = NewStream(st.cfg, hub, st.nodeID, capVer)
							resps, err := first.Initial(current)
							require.NoError(b, err)
							data, err := hub.Encode(resps[0], encoding == "zstd", benchEncode)
							require.NoError(b, err)
							first.Delivered()

							size = len(data)

							if reopened != nil {
								require.NoError(b, reopened.Close())
							}
						}

						require.NotNil(b, first)
						require.Nil(b, first.pending, "successful reconnects confirm delivery even when attempts would fold")

						if cache == "warm-hub" {
							require.Empty(b, st.hub.sentPeers[st.nodeID].attempts, "successful reconnects leave no failed-write history")
						}

						b.ReportMetric(float64(size), "encoded-bytes/op")
					})
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
	})

	peerDomain, err := mustNode(t, s, ids[1]).GetFQDN(cfg.DNSConfig.BaseDomain)
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
		cfg.DNSConfig.ExtraRecords = initial
	})
	node := mustNode(t, s, ids[0])
	domain, err := node.GetFQDN(cfg.DNSConfig.BaseDomain)
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

		ServerURL: "https://headscale.test",
		DNSConfig: types.DNSConfig{Certificates: types.CertificatesConfig{Enabled: true}, BaseDomain: "headscale.test", ExtraRecords: records},

		Policy: types.PolicyConfig{Mode: types.PolicyModeDB}, Prefixes: types.PrefixesConfig{V4: &p4, V6: &p6},
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
	nameservers := []string{"1.1.1.1"}
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
		cfg.DNSConfig.MagicDNS = true
		cfg.DNSConfig.OverrideLocalDNS = true
		cfg.DNSConfig.Nameservers = types.Nameservers{Global: nameservers, Split: map[string][]string{"split.test": nameservers}}
	})
	before := s.Snapshot()
	cfg.DNSConfig.BaseDomain = "changed.test"
	cfg.DNSConfig.Certificates.Enabled = false
	nameservers[0] = "9.9.9.9"
	cfg.DNSConfig.Nameservers.Split["split.test"][0] = "9.9.9.10"

	s.SetExtraRecords([]tailcfg.DNSRecord{{Name: "service.headscale.test", Value: "100.64.0.99"}})

	for _, snap := range []*state.Snapshot{before, s.Snapshot()} {
		out, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(snap)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "n1.headscale.test.", out[0].Node.Name)
		assert.Contains(t, out[0].Node.CapMap, nodecap.HTTPS)
		assert.Equal(t, []string{"n1.headscale.test"}, out[0].DNSConfig.CertDomains)
		assert.Equal(t, []string{"headscale.test"}, out[0].DNSConfig.Domains)

		for _, resolvers := range [][]*dnstype.Resolver{out[0].DNSConfig.Resolvers, out[0].DNSConfig.Routes["split.test"]} {
			require.Len(t, resolvers, 1)
			assert.Equal(t, "1.1.1.1", resolvers[0].Addr)
		}

		for _, peer := range out[0].Peers {
			assert.True(t, strings.HasSuffix(peer.Name, ".headscale.test."))
		}
	}
}

func TestStreamDNSInitialReverseRoutes(t *testing.T) {
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.MagicDNS = true
		cfg.DNSConfig.Nameservers.Split = map[string][]string{"split.test": {"1.1.1.1"}, "64.100.in-addr.arpa": {"9.9.9.9"}}
	})
	out, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)

	assert.Equal(t, []*dnstype.Resolver{{Addr: "9.9.9.9"}}, out[0].DNSConfig.Routes["64.100.in-addr.arpa"], "operator routes inside client-handled ranges remain explicit")
	assert.NotContains(t, out[0].DNSConfig.Routes, "127.100.in-addr.arpa")
	assert.NotContains(t, out[0].DNSConfig.Routes, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa")

	custom4 := netip.MustParsePrefix("10.44.0.0/24")
	custom6 := netip.MustParsePrefix("fd00:abcd::/64")
	cfg.Prefixes.V4, cfg.Prefixes.V6 = &custom4, &custom6

	view := cfg.DNSView().AsStruct()
	for _, zone := range []string{"0.44.10.in-addr.arpa", "0.0.0.0.0.0.0.0.d.c.b.a.0.0.d.f.ip6.arpa"} {
		resolvers, ok := view.Routes[zone]
		assert.True(t, ok, zone)
		assert.NotNil(t, resolvers, zone)
		assert.Empty(t, resolvers, zone)
	}

	assert.Equal(t, []*dnstype.Resolver{{Addr: "1.1.1.1"}}, out[0].DNSConfig.Routes["split.test"])
}

func TestStreamDNSConcurrentSnapshots(t *testing.T) {
	cfg, s, ids := streamTestState(t, "", func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
	})
	domain, err := mustNode(t, s, ids[0]).GetFQDN(cfg.DNSConfig.BaseDomain)
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

// TestRouteWakesNodeWhoseCapsAloneChanged grants a node attribute to
// u2's node and nothing else: no filter changes, so only the caps delta
// can wake the node, whose own entry and DNS carry its caps.
func TestRouteWakesNodeWhoseCapsAloneChanged(t *testing.T) {
	const rules = `"acls":[{"action":"accept","src":["u1@"],"dst":["u1@:*"]}]`

	cfg, s, ids := streamTestState(t, `{`+rules+`}`)
	target := ids[2]

	st := NewStream(cfg, NewHub(), target, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	before := s.Snapshot()

	_, err = s.SetPolicy([]byte(`{` + rules + `,"nodeAttrs":[{"target":["u2@"],"attr":["custom:probe"]}]}`))
	require.NoError(t, err)

	after := s.Snapshot()
	c := after.Since(before)
	assert.Contains(t, c.Caps, target, "the caps delta names the node")

	all, wake := Route(before, after, c)
	require.False(t, all, "test sanity: a node attribute is a scoped change")
	assert.Contains(t, wake, target)

	resps, err := st.Update(after)
	require.NoError(t, err)
	require.NotEmpty(t, resps, "test sanity: the node is sent its new caps")
	assert.Contains(t, resps[0].Node.CapMap, nodecap.Cap("custom:probe"))
}

// TestPeerRenderSurvivesEqualCapsRecompile widens the policy so the
// viewer's class gets a new view, rebuilt from scratch under the new
// compile, while every node keeps the caps it had: the peer it saw before
// must keep its render, so it is not sent again.
func TestPeerRenderSurvivesEqualCapsRecompile(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	before := s.Snapshot()
	peer, _ := st.r.last.peer(ids[1].NodeID())
	require.NotNil(t, peer)

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	require.NotEqual(t, before.PeerPolicyRev(), s.Snapshot().PeerPolicyRev(), "test sanity: the recompile renders peers anew")

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, resps, "test sanity: the viewer gains a peer")

	for _, resp := range resps {
		assert.False(t, mentions([]*tailcfg.MapResponse{resp}, ids[1]), "the unchanged peer is sent again")
	}

	again, _ := st.r.last.peer(ids[1].NodeID())
	assert.Same(t, peer, again, "the peer's render is kept")
}

// TestProfileOnlyUpdateIsCounted renames a peer's owner, which changes
// nothing but the profile sent: the generated-responses metric must name
// it rather than count it as unknown.
func decodeMapForTest(tb testing.TB, response *tailcfg.MapResponse) *tailcfg.MapResponse {
	tb.Helper()

	wire, err := Marshal(response)
	require.NoError(tb, err)

	var decoded tailcfg.MapResponse
	require.NoError(tb, json.Unmarshal(wire, &decoded))

	return &decoded
}

var errInjectedTagNodeUpdate = errors.New("injected tag node SQL update failure")

func TestFailedTagPersistAndIgnoredReportStillDeliverRevocation(t *testing.T) {
	const policy = `{
		"tagOwners":{"tag:ci":["u1@"],"tag:viewer":["u0@"]},
		"acls":[{"action":"accept","src":["u1@"],"dst":["tag:viewer:*"]}],
		"ssh":[{"action":"accept","src":["u1@"],"dst":["tag:viewer"],"users":["root"]}]
	}`

	s, setup := scalingTailnet(t, 3, "allow-all")
	t.Cleanup(setup[0].hub.Close)
	cfg := setup[0].cfg
	viewer, tagged, hidden := setup[0].nodeID, setup[1].nodeID, setup[2].nodeID
	_, err := s.SetPolicy([]byte(policy))
	require.NoError(t, err)
	_, err = s.SetNodeTags(viewer, []string{"tag:viewer"})
	require.NoError(t, err)

	h := NewHub()
	defer h.Close()

	h.Watch(s)
	viewerSession := h.Join(viewer, func() {})
	st := NewStream(cfg, h, viewer, capVer)
	st.Attach(viewerSession)

	before := s.Snapshot()
	initial, err := st.Initial(before)
	require.NoError(t, err)
	client := newModelClient(decodeMapForTest(t, initial[0]))
	require.Contains(t, client.peers, tagged.NodeID())
	require.NotContains(t, client.peers, hidden.NodeID())
	require.NotEmpty(t, client.ssh.Rules, "the tag transition must actually revoke an existing SSH permission")
	st.Delivered()

	hiddenStream := NewStream(cfg, h, hidden, capVer)
	hiddenStream.Attach(h.Join(hidden, func() {}))
	_, err = hiddenStream.Initial(before)
	require.NoError(t, err)
	hiddenStream.Delivered()

	const callback = "mapper_fail_tag_node_update"

	updates := s.DB().DB.Callback().Update()
	require.NoError(t, updates.Before("gorm:update").Register(callback, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			_ = tx.AddError(errInjectedTagNodeUpdate)
		}
	}))

	removeFault := sync.OnceFunc(func() { require.NoError(t, updates.Remove(callback)) })
	t.Cleanup(removeFault)

	_, err = s.SetNodeTags(tagged, []string{"tag:ci"})
	require.ErrorIs(t, err, errInjectedTagNodeUpdate)

	failed := s.Snapshot()
	require.NotEqual(t, before.PolicyRev(), failed.PolicyRev())
	require.True(t, mustNode(t, s, tagged).IsTagged(), "the committed graph policy must keep the revocation despite SQL failure")
	row, err := s.DB().GetNodeByID(tagged)
	require.NoError(t, err)
	require.Empty(t, row.Tags, "the injected SQL failure must be real")
	removeFault()

	node := mustNode(t, s, tagged)
	// No observer consumes the intermediate report. There is no returned
	// Change to dispatch: delivery must come from the Hub subscription.
	require.NoError(t, s.UpdateNodeFromMapRequest(tagged, tailcfg.MapRequest{
		NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Endpoints: node.Endpoints().AsSlice(), Hostinfo: node.Hostinfo().AsStruct(),
	}))
	_, err = s.SetNodeTags(tagged, []string{"tag:ci"})
	require.NoError(t, err)
	row, err = s.DB().GetNodeByID(tagged)
	require.NoError(t, err)
	require.Equal(t, []string{"tag:ci"}, row.Tags.List(), "retry repairs the durable tag")
	waitWake(t, viewerSession)

	final := s.Snapshot()
	out, err := st.Update(final)
	require.NoError(t, err)
	require.NotEmpty(t, out)

	removed, clearedSSH := false, false

	for _, response := range out {
		decoded := decodeMapForTest(t, response)

		removed = removed || slices.Contains(decoded.PeersRemoved, tagged.NodeID())
		if decoded.SSHPolicy != nil {
			require.Empty(t, decoded.SSHPolicy.Rules)

			clearedSSH = true
		}

		require.False(t, mentions([]*tailcfg.MapResponse{decoded}, hidden), "a policy revocation cannot leak another user's hidden node")
		client.apply(decoded)
	}

	require.True(t, removed, "the already initialized observer must receive the lost peer removal")
	require.True(t, clearedSSH, "the already initialized observer must receive SSH revocation")
	require.NotContains(t, client.peers, tagged.NodeID())
	require.Empty(t, client.ssh.Rules)
	st.Delivered()

	fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(final)
	require.NoError(t, err)
	require.Empty(t, client.sameAs(newModelClient(decodeMapForTest(t, fresh[0]))))

	hiddenOut, err := hiddenStream.Update(final)
	require.NoError(t, err)
	require.Empty(t, hiddenOut, "hidden viewers receive neither tagged identity nor new profile data")
}

func TestMapRequestLastSeenVisibility(t *testing.T) {
	for _, online := range []bool{true, false} {
		for _, jitter := range []bool{false, true} {
			t.Run(fmt.Sprintf("online=%t/jitter=%t", online, jitter), func(t *testing.T) {
				cfg, s, ids := streamTestState(t, ownUserOnly)
				reporter, viewer := ids[1], ids[0]
				epoch := s.Connect(reporter)
				node := mustNode(t, s, reporter)
				req := tailcfg.MapRequest{
					NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(),
					Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname(), OS: "linux", NetInfo: &tailcfg.NetInfo{PreferredDERP: 1, DERPLatency: map[string]float64{"1-v4": 0.010}}},
				}
				require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))

				if !online {
					require.NoError(t, s.Disconnect(reporter, epoch))
				}

				before := s.Snapshot()
				was, ok := before.GetNode(reporter)
				require.True(t, ok)

				seen := was.LastSeen().Get()
				st := NewStream(cfg, NewHub(), viewer, capVer)
				initial, err := st.Initial(before)
				require.NoError(t, err)
				client := newModelClient(decodeMapForTest(t, initial[0]))

				st.Delivered()

				if jitter {
					req.Hostinfo.NetInfo.DERPLatency["1-v4"] = 0.025
				}

				require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))
				after := s.Snapshot()
				is, ok := after.GetNode(reporter)
				require.True(t, ok)
				require.True(t, is.LastSeen().Get().After(seen))
				require.Equal(t, seen, was.LastSeen().Get(), "old snapshot timestamp is immutable")
				require.True(t, was.Hostinfo().Equal(is.Hostinfo()), "identical/jitter reports change no retained Hostinfo field")
				require.Equal(t, before.PolicyRev(), after.PolicyRev())
				require.Equal(t, before.PeersRev(), after.PeersRev())
				require.Equal(t, before.PrimariesRev(), after.PrimariesRev())
				all, wake := Route(before, after, after.Since(before))
				require.False(t, all)

				out, err := st.Update(after)
				require.NoError(t, err)

				if online {
					require.Empty(t, wake)
					require.Empty(t, out, "online LastSeen is not rendered")
				} else {
					require.ElementsMatch(t, []types.NodeID{viewer, reporter}, slices.Collect(maps.Keys(wake)))
					require.Len(t, out, 1)
					require.True(t, patchOnly(out[0]), "offline LastSeen is the only changed wire field")
					decoded := decodeMapForTest(t, out[0])
					require.Len(t, decoded.PeersChangedPatch, 1)
					patch := decoded.PeersChangedPatch[0]
					require.Equal(t, &tailcfg.PeerChange{NodeID: reporter.NodeID(), LastSeen: patch.LastSeen}, patch)
					require.NotNil(t, patch.LastSeen)
					require.True(t, patch.LastSeen.Equal(is.LastSeen().Get()))
					client.apply(decoded)
				}

				fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(after)
				require.NoError(t, err)
				require.Empty(t, client.sameAs(newModelClient(decodeMapForTest(t, fresh[0]))))
			})
		}
	}
}

func TestDeletionRoutesOnlyToPreviousVisiblePeers(t *testing.T) {
	for _, tt := range []struct {
		deleted types.NodeID
		peers   []types.NodeID
	}{
		{3, []types.NodeID{1, 5}},
		{2, []types.NodeID{4}},
		{42, nil},
	} {
		t.Run(fmt.Sprint(tt.deleted), func(t *testing.T) {
			s, setup := scalingTailnet(t, 5, "self")

			owners := [2]*types.User{mustNode(t, s, 1).User().AsStruct(), mustNode(t, s, 2).User().AsStruct()}
			for id := types.NodeID(1); id <= 5; id++ {
				node := mustNode(t, s, id).AsStruct()
				owner := owners[(id+1)%2]
				node.UserID, node.User = new(owner.ID), owner
				s.PutNodeInStoreForTest(*node)
			}

			h := NewHub()
			defer h.Close()

			sessions := make(map[types.NodeID]*Session)

			var stopped []types.NodeID

			for id := types.NodeID(1); id <= 5; id++ {
				sessions[id] = h.Join(id, func() { stopped = append(stopped, id) })
			}

			before := s.Snapshot()
			if tt.deleted <= 5 {
				require.Equal(t, tt.peers, before.ListPeerIDs(tt.deleted), "real policy groups match the old odd/even visibility fixture")
			}

			victim, ok := before.GetNode(tt.deleted)
			if !ok {
				victim = (&types.Node{ID: tt.deleted}).View()
			}

			require.NoError(t, s.DeleteNode(victim))
			after := s.Snapshot()
			all, wake := Route(before, after, after.Since(before))
			require.False(t, all)
			// Self teardown is independent of the peer recipient list.
			h.forget(tt.deleted)

			if tt.deleted <= 5 {
				require.Equal(t, []types.NodeID{tt.deleted}, stopped)
				require.False(t, h.IsConnected(tt.deleted))
			} else {
				require.Empty(t, stopped)
				require.Equal(t, before.Rev(), after.Rev())
			}

			h.wake(all, wake)

			var recipients []types.NodeID

			for id, sess := range sessions {
				if len(sess.wakes) != 0 {
					recipients = append(recipients, id)
				}
			}

			require.ElementsMatch(t, tt.peers, recipients, "only previous visible peers receive deletion work")

			for _, st := range setup {
				st.hub.Close()
			}
		})
	}
}

// Legacy broadcast outcomes are recorded separately: raw graph endpoints
// deliberately deliver rows main's eager STUN/shrink heuristic suppressed.
func TestEndpointReportsConvergeFromPublicState(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.1.5:41641")
	local2 := netip.MustParseAddrPort("192.168.1.6:41641")
	stun := netip.MustParseAddrPort("203.0.113.7:41641")
	stun2 := netip.MustParseAddrPort("203.0.113.8:41641")

	portmap := netip.MustParseAddrPort("198.51.100.9:41641")
	for _, tt := range []struct {
		name                 string
		stored, reported     []netip.AddrPort
		types                []tailcfg.EndpointType
		legacyEager, changed bool
	}{
		{"adds only a STUN endpoint - legacy suppress", []netip.AddrPort{local}, []netip.AddrPort{local, stun}, []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN}, false, true},
		{"adds only STUN4LocalPort - legacy suppress", []netip.AddrPort{local}, []netip.AddrPort{local, stun}, []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN4LocalPort}, false, true},
		{"adds a useful local endpoint", []netip.AddrPort{stun}, []netip.AddrPort{stun, local}, []tailcfg.EndpointType{tailcfg.EndpointSTUN, tailcfg.EndpointLocal}, true, true},
		{"adds a useful portmapped endpoint", []netip.AddrPort{local}, []netip.AddrPort{local, portmap}, []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointPortmapped}, true, true},
		{"pure shrink - legacy suppress", []netip.AddrPort{local, local2}, []netip.AddrPort{local}, []tailcfg.EndpointType{tailcfg.EndpointLocal}, false, true},
		{"nil types older client adds endpoint", []netip.AddrPort{local}, []netip.AddrPort{local, local2}, nil, true, true},
		{"only STUN endpoints churn - legacy suppress", []netip.AddrPort{local, stun}, []netip.AddrPort{local, stun2}, []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN}, false, true},
		{"mixed STUN and useful addition", []netip.AddrPort{local}, []netip.AddrPort{local, stun, local2}, []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN, tailcfg.EndpointLocal}, true, true},
		{"first endpoints ever STUN only", nil, []netip.AddrPort{stun}, []tailcfg.EndpointType{tailcfg.EndpointSTUN}, true, true},
		{"no stored and none announced", nil, nil, nil, false, false},
		{"identical report", []netip.AddrPort{local, stun}, []netip.AddrPort{local, stun}, nil, false, false},
		{"reordered equal set", []netip.AddrPort{local, stun}, []netip.AddrPort{stun, local}, nil, false, false},
		{"nil report retains stored set", []netip.AddrPort{local}, nil, nil, false, false},
		{"typed API explicit empty clears", []netip.AddrPort{local}, []netip.AddrPort{}, nil, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("legacy eager broadcast=%v; graph endpoint change=%v", tt.legacyEager, tt.changed)
			cfg, s, ids := streamTestState(t, ownUserOnly)
			viewer, reporter, hidden := ids[0], ids[1], ids[2]
			s.Connect(reporter)
			node := mustNode(t, s, reporter)
			req := tailcfg.MapRequest{
				NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Endpoints: tt.stored,
				Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname(), NetInfo: &tailcfg.NetInfo{PreferredDERP: 1}},
			}
			require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))
			before := s.Snapshot()
			st := NewStream(cfg, NewHub(), viewer, capVer)
			initial, err := st.Initial(before)
			require.NoError(t, err)
			client := newModelClient(decodeMapForTest(t, initial[0]))

			st.Delivered()

			hiddenStream := NewStream(cfg, NewHub(), hidden, capVer)
			_, err = hiddenStream.Initial(before)
			require.NoError(t, err)

			req.Endpoints, req.EndpointTypes = tt.reported, tt.types
			require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))
			after := s.Snapshot()

			want := tt.stored
			if tt.changed {
				want = tt.reported
			}

			require.ElementsMatch(t, want, mustNode(t, s, reporter).Endpoints().AsSlice())
			row, err := s.DB().GetNodeByID(reporter)
			require.NoError(t, err)
			require.ElementsMatch(t, want, row.Endpoints.List(), "accepted endpoint set is durable")

			oldNode, ok := before.GetNode(reporter)
			require.True(t, ok)
			require.ElementsMatch(t, tt.stored, oldNode.Endpoints().AsSlice(), "old snapshot is immutable")

			old, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(before)
			require.NoError(t, err)
			oldClient := newModelClient(decodeMapForTest(t, old[0]))
			require.ElementsMatch(t, tt.stored, oldClient.peers[reporter.NodeID()].Endpoints)

			all, wake := Route(before, after, after.Since(before))
			require.False(t, all)
			require.NotContains(t, wake, hidden)

			if tt.changed {
				require.ElementsMatch(t, []types.NodeID{viewer, reporter}, slices.Collect(maps.Keys(wake)))
			} else {
				require.Empty(t, wake)
			}

			out, err := st.Update(after)
			require.NoError(t, err)
			require.Equal(t, tt.changed, len(out) > 0)

			for _, response := range out {
				client.apply(decodeMapForTest(t, response))
			}

			st.Delivered()
			require.ElementsMatch(t, want, client.peers[reporter.NodeID()].Endpoints)

			fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(after)
			require.NoError(t, err)
			require.Empty(t, client.sameAs(newModelClient(decodeMapForTest(t, fresh[0]))))

			hiddenOut, err := hiddenStream.Update(after)
			require.NoError(t, err)
			require.Empty(t, hiddenOut, "hidden viewer receives no reporter identity or endpoints")
		})
	}
}

func TestMapRequestEmptyEndpointsWireContract(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	reporter := ids[1]
	s.Connect(reporter)
	node := mustNode(t, s, reporter)
	local := netip.MustParseAddrPort("192.0.2.1:41641")
	req := tailcfg.MapRequest{NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Endpoints: []netip.AddrPort{local}}
	require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))
	req.Endpoints = []netip.AddrPort{}
	wire, err := json.Marshal(req)
	require.NoError(t, err)
	require.NotContains(t, string(wire), `"Endpoints"`, "pinned MapRequest omitempty cannot transmit explicit empty")

	var decoded tailcfg.MapRequest
	require.NoError(t, json.Unmarshal(wire, &decoded))
	require.Nil(t, decoded.Endpoints)
	require.NoError(t, s.UpdateNodeFromMapRequest(reporter, decoded))
	require.Equal(t, []netip.AddrPort{local}, mustNode(t, s, reporter).Endpoints().AsSlice(), "nil request behavior is unchanged from main")

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	first, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	client := newModelClient(decodeMapForTest(t, first[0]))
	require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))
	require.Empty(t, mustNode(t, s, reporter).Endpoints().AsSlice(), "typed public API can distinguish the nonnil empty slice")
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, out)

	for _, response := range out {
		client.apply(decodeMapForTest(t, response))
	}

	require.Empty(t, client.peers[reporter.NodeID()].Endpoints, "server response whole-peer encoding clears old endpoints")
}

func TestSTUNReportsCoalesceWhileInitialWriteIsBlocked(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	viewer, reporter, hidden := ids[0], ids[1], ids[2]
	s.Connect(reporter)
	node := mustNode(t, s, reporter)
	local := netip.MustParseAddrPort("192.0.2.1:41641")
	req := tailcfg.MapRequest{NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Endpoints: []netip.AddrPort{local}}
	require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))

	h := NewHub()
	defer h.Close()

	h.Watch(s)
	sess := h.Join(viewer, func() {})
	hiddenSession := h.Join(hidden, func() {})
	st := NewStream(cfg, h, viewer, capVer)
	st.Attach(sess)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	written := make(chan []*tailcfg.MapResponse)
	finished := make(chan struct{})

	go func() { written <- initial; st.Delivered(); close(finished) }()

	for i := range 32 {
		req.Endpoints = []netip.AddrPort{local, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), uint16(10000+i))}
		req.EndpointTypes = []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN}
		require.NoError(t, s.UpdateNodeFromMapRequest(reporter, req))
	}

	require.Eventually(t, func() bool { return len(sess.wakes) == 1 }, time.Second, time.Millisecond)
	require.Empty(t, hiddenSession.wakes)
	h.mu.Lock()
	retained, attempts := h.retained, len(h.sentPeers[viewer].attempts)
	h.mu.Unlock()
	require.LessOrEqual(t, retained, h.maxHistoryIDs)
	require.LessOrEqual(t, attempts, maxPeerAttempts)

	old := <-written

	<-finished

	client := newModelClient(decodeMapForTest(t, old[0]))
	require.Equal(t, []netip.AddrPort{local}, client.peers[reporter.NodeID()].Endpoints)
	waitWake(t, sess)

	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, out, 1, "32 pending reports coalesce to one latest endpoint frame")

	for _, response := range out {
		client.apply(decodeMapForTest(t, response))
	}

	require.Equal(t, req.Endpoints, client.peers[reporter.NodeID()].Endpoints)
	// The catch-up write fails before confirmation. A replacement stream
	// must still obtain the complete latest raw endpoint set.
	retry := NewStream(cfg, h, viewer, capVer)
	retry.Attach(h.Join(viewer, func() {}))
	reconnected, err := retry.Initial(s.Snapshot())
	require.NoError(t, err)

	for _, response := range reconnected {
		client.apply(decodeMapForTest(t, response))
	}

	retry.Delivered()

	fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, client.sameAs(newModelClient(decodeMapForTest(t, fresh[0]))))
	h.frames.mu.Lock()
	patches := len(h.frames.patches)
	h.frames.mu.Unlock()
	require.LessOrEqual(t, patches, 1)
}

func TestHostinfoOnlyMetadataUpdateWakesNobody(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	viewer, target := ids[0], ids[1]
	s.Connect(target)
	node := mustNode(t, s, target)
	req := tailcfg.MapRequest{
		NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Endpoints: node.Endpoints().AsSlice(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname(), OS: "linux", DeviceModel: "a", NetInfo: &tailcfg.NetInfo{PreferredDERP: 1}},
	}
	require.NoError(t, s.UpdateNodeFromMapRequest(target, req))

	streams := []*Stream{NewStream(cfg, NewHub(), viewer, capVer), NewStream(cfg, NewHub(), target, capVer)}
	for _, st := range streams {
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		st.Delivered()
	}

	before := s.Snapshot()
	req.Hostinfo.DeviceModel = "b"
	require.NoError(t, s.UpdateNodeFromMapRequest(target, req))
	after := s.Snapshot()
	require.Equal(t, "b", mustNode(t, s, target).Hostinfo().DeviceModel())
	row, err := s.DB().GetNodeByID(target)
	require.NoError(t, err)
	require.Equal(t, "b", row.Hostinfo.DeviceModel, "metadata remains durable")

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all)
	require.Empty(t, wake, "metadata absent from both wire Hostinfo shapes schedules nobody")

	for _, st := range streams {
		out, err := st.Update(after)
		require.NoError(t, err)
		require.Empty(t, out)
	}

	req.Hostinfo.OS = "windows"
	require.NoError(t, s.UpdateNodeFromMapRequest(target, req))
	visible := s.Snapshot()
	all, wake = Route(after, visible, visible.Since(after))
	require.False(t, all)
	require.Contains(t, wake, viewer, "OS is read from the peer and NextDNS metadata")

	out, err := streams[0].Update(visible)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Len(t, out[0].PeersChanged, 1)
	require.Equal(t, target.NodeID(), out[0].PeersChanged[0].ID)
	require.Equal(t, "windows", out[0].PeersChanged[0].Hostinfo.OS())
}

func TestProfileOnlyUpdateIsCounted(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	u2 := mustNode(t, s, ids[2]).Owner()
	_, err = s.RenameUser(types.UserID(u2.Model().ID), "u2-renamed")
	require.NoError(t, err)

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, resps, 1)
	require.NotEmpty(t, resps[0].UserProfiles, "test sanity: the rename sends the profile")
	assert.Equal(t, "profiles", responseType(resps[0]))

	_, err = s.RenameUser(types.UserID(u2.Model().ID), "u2-renamed")
	require.NoError(t, err)
	resps, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, resps, "idempotent user rename emits no frame")

	beforeProvider := s.Snapshot()
	_, err = s.UpdateUser(types.UserID(u2.Model().ID), func(u *types.User) error { u.Provider = "provider-only"; return nil })
	require.NoError(t, err)
	resps, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, resps, "provider metadata has no wire-visible profile effect")

	afterProvider := s.Snapshot()
	all, wake := Route(beforeProvider, afterProvider, afterProvider.Since(beforeProvider))
	require.False(t, all, "provider-only metadata must not schedule every session")
	require.Empty(t, wake, "provider-only metadata must schedule no recipients")
	require.Equal(t, "provider-only", mustNode(t, s, ids[2]).User().Provider(), "admin reads still receive the updated metadata")
}

// TestClassProfilesDropAnOwnerWithItsLastNode hands the only node of a
// peer's owner to another user. Under allow-all the class's view is the
// same before and after, so its shared profile map is edited rather than
// rebuilt, and it must forget the old owner as a session built from
// scratch never holds one. A kept profile is invisible on the wire, which
// is why only the maps themselves tell.
func TestClassProfilesDropAnOwnerWithItsLastNode(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	viewer, moved := ids[0], ids[2]

	st := NewStream(cfg, NewHub(), viewer, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	nv := mustNode(t, s, moved)
	was := nv.Owner().TailscaleUserProfile().ID
	require.Contains(t, profileIDs(st.r.last.profiles), was, "test sanity: the viewer holds the peer's owner")

	to, err := s.GetUserByID(types.UserID(mustNode(t, s, viewer).Owner().Model().ID))
	require.NoError(t, err)

	n := nv.AsStruct()
	n.UserID, n.User = &to.ID, to
	s.PutNodeInStoreForTest(*n)

	_, err = st.Update(s.Snapshot())
	require.NoError(t, err)

	fresh := NewStream(cfg, NewHub(), viewer, capVer)
	_, err = fresh.Initial(s.Snapshot())
	require.NoError(t, err)

	assert.NotContains(t, profileIDs(st.r.last.profiles), was, "the session keeps the profile of an owner with no node left")
	assert.Equal(t, profileIDs(fresh.r.last.profiles), profileIDs(st.r.last.profiles), "a session built from scratch holds other profiles")

	require.Len(t, st.r.classes.m, 1, "test sanity: one class holds the session's peers")

	for _, entry := range st.r.classes.m {
		owners := entry.cur.owners

		_, counted := owners.nodes.Get(was)
		assert.False(t, counted, "the class counts nodes for an owner with none")
		assert.Equal(t, profileIDs(fresh.r.last.profiles), profileIDs(owners.profiles), "the class's profiles differ from a fresh build")
	}
}

// profileIDs returns the users m holds a profile for, sorted.
func profileIDs(m *profileMap) []tailcfg.UserID {
	return slices.Sorted(maps.Keys(maps.Collect(m.All())))
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

// TestStreamCapabilityCacheBound keeps live versions shared while
// reconnects with arbitrary versions share theirs and leave no renders in
// the hub.
func TestStreamCapabilityCacheBound(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	snap := s.Snapshot()

	var live []*Stream

	// Every other supported version stays connected; the rest connect and
	// are dropped, so a cache that outlives its sessions shows up below.
	for cv := capver.MinSupportedCapabilityVersion; cv <= capVer; cv++ {
		st := NewStream(cfg, hub, ids[0], cv)
		_, err := st.Initial(snap)
		require.NoError(t, err)

		if (cv-capver.MinSupportedCapabilityVersion)%2 == 0 || cv == capVer {
			live = append(live, st)
		}
	}

	shared := live[len(live)-1].r.last.peers
	versions := len(live)

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
			assert.Zero(t, resps[0].Node.Cap, "self never carries capability version")
			require.Len(t, resps[0].Peers, 2)

			for _, peer := range resps[0].Peers {
				assert.Equal(t, peerCapVer(cv), peer.Cap)
			}

			// It renders peers as the nearest supported version does.
			nearest := live[0].r.last.peers
			if cv > capVer {
				nearest = shared
			}

			assert.Same(t, nearest, st.r.last.peers)

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

	runtime.GC()
	assert.Len(t, hub.caches(), versions, "closed versions leave no shared renders")
	assert.Eventually(t, func() bool {
		runtime.GC()
		hub.mu.Lock()
		defer hub.mu.Unlock()

		return len(hub.versions) == versions
	}, 10*time.Second, 10*time.Millisecond, "closed versions leave no index entries")

	st := NewStream(cfg, hub, ids[1], capVer)
	_, err := st.Initial(snap)
	require.NoError(t, err)
	assert.Same(t, shared, st.r.last.peers, "other versions do not evict live ones")
	runtime.KeepAlive(live)
}

// TestStreamNewerClientSharesCurrentRenders connects a client newer than
// the server beside a current one: auto-updated fleets pass the server's
// version within weeks of a release, and must not need a second set of
// peer renders, or retention doubles with every newer client.
func TestStreamNewerClientSharesCurrentRenders(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	snap := s.Snapshot()

	cur := NewStream(cfg, hub, ids[0], capVer)
	_, err := cur.Initial(snap)
	require.NoError(t, err)

	for _, cv := range []tailcfg.CapabilityVersion{capVer + 1, capVer + 100} {
		newer := NewStream(cfg, hub, ids[1], cv)
		resps, err := newer.Initial(snap)
		require.NoError(t, err)
		assert.Zero(t, resps[0].Node.Cap, "self never carries capability version")

		want, _ := cur.r.last.peers.Get(ids[2].NodeID())
		got, _ := newer.r.last.peers.Get(ids[2].NodeID())

		require.NotNil(t, want)
		assert.Same(t, want, got, "version %d renders peers apart from the current version", cv)
		assert.Len(t, hub.caches(), 1, "version %d keeps its own render cache", cv)
	}

	runtime.KeepAlive(cur)
}

// TestStreamNewerClientsRetainNoSecondRenderSet bounds what clients newer
// than the server retain beside a current fleet: no more than as many
// current clients, whose renders are shared. A few sessions against many
// peers make a second render set stand out.
func TestStreamNewerClientsRetainNoSecondRenderSet(t *testing.T) {
	s, streams := scalingTailnet(t, 200, "allow-all")
	cfg, hub := streams[0].cfg, streams[0].hub
	snap := s.Snapshot()

	heap := func() float64 {
		runtime.GC()
		runtime.GC()

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		return float64(m.HeapAlloc)
	}

	fleet := func(cv tailcfg.CapabilityVersion) ([]*Stream, float64) {
		before := heap()
		out := make([]*Stream, 0, 20)

		for _, st := range streams[:20] {
			st := NewStream(cfg, hub, st.nodeID, cv)
			_, err := st.Initial(snap)
			require.NoError(t, err)

			out = append(out, st)
		}

		return out, heap() - before
	}

	current, atCurrent := fleet(capVer)
	newer, atNewer := fleet(capVer + 1)
	t.Logf("20 more sessions at the current version: %.0f B; at a newer one: %.0f B", atCurrent, atNewer)
	assert.Less(t, atNewer, atCurrent*3/2, "newer clients keep a render set of their own")
	runtime.KeepAlive(current)
	runtime.KeepAlive(newer)
	runtime.KeepAlive(streams)
}

// TestHubKeepsRendersOnlyOfLiveVersions opens and closes one short session
// per capability version beside sessions that stay: once the short ones
// are gone, the hub must keep what the live sessions render, not one set
// of renders for every version a client ever spoke.
func TestHubKeepsRendersOnlyOfLiveVersions(t *testing.T) {
	s, streams := scalingTailnet(t, 200, "allow-all")
	cfg, hub, id := streams[0].cfg, streams[0].hub, streams[0].nodeID
	snap := s.Snapshot()

	heap := func() float64 {
		runtime.GC()
		runtime.GC()

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		return float64(m.HeapAlloc)
	}

	// session opens a session at cv, as poll does, and returns its stream
	// and its end; poll drops the stream once the session ends.
	session := func(cv tailcfg.CapabilityVersion) (*Stream, func()) {
		sess := hub.Join(id, func() {})
		st := NewStream(cfg, hub, id, cv)
		st.Attach(sess)
		_, err := st.Initial(snap)
		require.NoError(t, err)
		st.Delivered()

		return st, func() { hub.Leave(sess) }
	}

	before := heap()
	st, leave := session(capVer - 1)
	perVersion := heap() - before

	leave()
	runtime.KeepAlive(st)

	base := heap()

	for cv := capver.MinSupportedCapabilityVersion; cv < capVer; cv++ {
		_, leave := session(cv)
		leave()
	}

	retained := heap() - base
	t.Logf("one live version: %.0f B; after %d closed versions: %.0f B retained",
		perVersion, capVer-capver.MinSupportedCapabilityVersion, retained)
	assert.Less(t, retained, perVersion/2, "closed sessions' versions keep their renders")
	runtime.KeepAlive(streams)
}

// TestStreamReconnectAtReleasedVersion lets a version's cache go with its
// last session, changes the tailnet, and reconnects at that version: the
// session renders into an empty cache and must converge on what a fresh
// hub sends, and keep converging.
func TestStreamReconnectAtReleasedVersion(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	cv := capVer - 1

	other := NewStream(cfg, hub, ids[1], capVer)
	_, err := other.Initial(s.Snapshot())
	require.NoError(t, err)

	open := func() (*Stream, *Session, *modelClient) {
		sess := hub.Join(ids[0], func() {})
		st := NewStream(cfg, hub, ids[0], cv)
		st.Attach(sess)
		resps, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		c := newModelClient(resps[0])
		for _, resp := range resps[1:] {
			c.apply(resp)
		}

		st.Delivered()

		return st, sess, c
	}

	requireFresh := func(c *modelClient) {
		t.Helper()

		fresh, err := NewStream(cfg, NewHub(), ids[0], cv).Initial(s.Snapshot())
		require.NoError(t, err)
		require.Empty(t, c.sameAs(newModelClient(fresh[0])))
	}

	live := func(v tailcfg.CapabilityVersion) bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()

		return hub.versions[v].Value() != nil
	}

	_, sess, _ := open()
	hub.Leave(sess)
	runtime.GC()
	require.False(t, live(cv), "the version's cache goes with its last session")
	require.True(t, live(capVer), "a live version keeps its cache")

	moved := mustNode(t, s, ids[1]).AsStruct()
	moved.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	s.PutNodeInStoreForTest(*moved)
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))

	// As the watcher does after the deletion.
	hub.advance(s.Snapshot())
	hub.forget(ids[2])

	st, sess, c := open()
	requireFresh(c)
	assert.NotContains(t, c.peers, ids[2].NodeID(), "the reconnect is told of the removal")

	moved.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:41641")}
	s.PutNodeInStoreForTest(*moved)

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, resps)

	for _, resp := range resps {
		c.apply(resp)
	}

	st.Delivered()
	requireFresh(c)
	hub.Leave(sess)
	runtime.KeepAlive(other)
}

// TestPeerRendersForgetDropsEveryCapVer renders a node for two capability
// versions and forgets it: neither render may survive, or a deleted node's
// renders would pile up.
func TestPeerRendersForgetDropsEveryCapVer(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)

	live := make([]*Stream, 0, 2)

	for _, cv := range []tailcfg.CapabilityVersion{capVer, capVer - 1} {
		st := NewStream(cfg, hub, ids[0], cv)
		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)

		live = append(live, st)
	}

	for _, st := range live {
		_, ok := st.r.renders.m.Load(ids[1])
		require.True(t, ok, "test sanity: version %d renders the peer", st.r.capVer)
	}

	hub.forget(ids[1])

	for _, st := range live {
		_, ok := st.r.renders.m.Load(ids[1])
		assert.False(t, ok, "version %d keeps a forgotten node's render", st.r.capVer)
	}
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

			// current holds the version's cache for every render below.
			current := NewStream(cfg, hub, ids[0], capVer)

			before := s.Snapshot()
			if tc.warm {
				_, err := NewStream(cfg, hub, ids[0], capVer).r.render(before)
				require.NoError(t, err)
			}

			require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))

			after := s.Snapshot()
			hub.advance(after)

			if tc.forget {
				hub.forget(ids[2])
			}

			var wg sync.WaitGroup

			for range 32 {
				wg.Go(func() {
					stale, err := NewStream(cfg, hub, ids[0], capVer).r.render(before)
					if assert.NoError(t, err) {
						_, present := stale.peer(ids[2].NodeID())
						assert.True(t, present, "the old snapshot still renders correctly")
					}
				})
			}

			wg.Wait()

			_, retained := current.r.renders.m.Load(ids[2])
			assert.False(t, retained, "stale renders must not admit a deleted node")

			_, err := current.Initial(after)
			require.NoError(t, err)

			// Pruning the newest classes must also close late admission
			// by a renderer whose snapshot was captured before deletion.
			_, err = NewStream(cfg, hub, ids[0], capVer).r.render(before)
			require.NoError(t, err)
			assert.Len(t, current.r.classes.m, 1, "stale renders must not admit a vanished class")
			_, retained = current.r.renders.m.Load(ids[2])
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
		old, cur := NewStream(cfg, hub, ids[0], capVer), NewStream(cfg, hub, ids[0], capVer)

		var wg sync.WaitGroup

		wg.Go(func() {
			_, err := old.Initial(before)
			assert.NoError(t, err)
		})
		wg.Go(func() {
			hub.advance(after)
			hub.forget(ids[2])

			_, err := cur.Initial(after)
			assert.NoError(t, err)
		})
		wg.Wait()

		_, retained := cur.r.renders.m.Load(ids[2])
		assert.False(t, retained, "a render racing cleanup leaves no deleted peer cached")
		assert.Len(t, cur.r.classes.m, 1)
		runtime.KeepAlive(old)
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

					for _, id := range ids[1:] {
						n := mustNode(t, s, id).AsStruct()
						n.Tags = []string{"tag:isolated"}
						s.PutNodeInStoreForTest(*n)
					}

					for _, view := range s.Snapshot().PeerViews() {
						require.Empty(t, view)
					}
				}

				after := s.Snapshot()
				hub.advance(after)
				hub.forget(ids[0])
				hub.Leave(sess)
				require.True(t, stopped)
				require.Empty(t, hub.Connected())
				assert.Empty(t, st.r.classes.m, "the watcher alone drops obsolete classes")

				_, err := st.r.render(before)
				require.NoError(t, err, "the in-flight snapshot still renders")
				st.Delivered()
				assert.Empty(t, st.r.classes.m, "a stopped session cannot restore an obsolete class")

				_, retained := st.r.renders.m.Load(ids[0])
				assert.False(t, retained)
			})
		}
	}
}

func TestClassMapsPruneOnEmptyView(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	for _, id := range ids {
		n := mustNode(t, s, id).AsStruct()
		n.Tags = []string{"tag:isolated"}
		s.PutNodeInStoreForTest(*n)
	}

	hub := NewHub()
	t.Cleanup(hub.Close)

	before := s.Snapshot()
	first := NewStream(cfg, hub, ids[0], capVer)
	_, err := first.Initial(before)
	require.NoError(t, err)

	classes := first.r.classes
	require.Len(t, classes.m, 1)

	_, err = s.SetPolicy([]byte(`{"acls":[]}`))
	require.NoError(t, err)

	after := s.Snapshot()
	require.Empty(t, after.PeerView(ids[0]))
	_, err = NewStream(cfg, hub, ids[0], capVer).Initial(after)
	require.NoError(t, err)
	assert.Empty(t, classes.m, "an empty view still prunes vanished classes")

	_, err = NewStream(cfg, hub, ids[0], capVer).r.render(before)
	require.NoError(t, err)
	assert.Empty(t, classes.m, "the old class cannot return after pruning")
	runtime.KeepAlive(first)
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
				require.NotContains(t, client.peers, ids[2].NodeID(), "cross-user peer is hidden after policy reverts")
				require.Contains(t, client.peers, ids[1].NodeID(), "own devices remain peers under every policy")
			case "endpoint_revert":
				require.Empty(t, client.peers[ids[1].NodeID()].Endpoints)
			default:
				require.NotContains(t, client.peers, transient.NodeID())
				_, retained := st.r.renders.m.Load(transient)
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

// TestStreamAppOnlyViaFollowsPolicy edits an app-only via grant (one with
// no ip, so it compiles to no filter rule) and retags its viewer while the
// router stays visible through a node ACL, and checks after each write that
// every session the hub routes it to converges on a fresh session's map.
// The via steering is the only thing these writes change in the viewer's
// render, so they test that what invalidates retained peer renders covers
// every policy input the via route reads.
func TestStreamAppOnlyViaFollowsPolicy(t *testing.T) {
	route := netip.MustParsePrefix("10.0.0.0/24")

	viaPolicy := func(src, dst string) string {
		return `{"tagOwners":{"tag:router":["u1@"],"tag:client":["u1@"]},
		  "grants":[
		    {"src":["u1@","u2@","tag:client"],"dst":["tag:router"],"ip":["*"]},
		    {"src":["` + src + `"],"dst":["` + dst + `"],"via":["tag:router"],
		     "app":{"example.com/cap/probe":[{}]}}]}`
	}

	for _, tc := range []struct {
		name  string
		write func(t *testing.T, s *state.State, viewer types.NodeID)
		// served is whether the viewer is sent the route after write.
		served bool
	}{
		{
			name: "src",
			write: func(t *testing.T, s *state.State, _ types.NodeID) {
				t.Helper()

				_, err := s.SetPolicy([]byte(viaPolicy("u2@", "10.0.0.0/24")))
				require.NoError(t, err)
			},
		},
		{
			name: "dst",
			write: func(t *testing.T, s *state.State, _ types.NodeID) {
				t.Helper()

				_, err := s.SetPolicy([]byte(viaPolicy("u1@", "10.0.1.0/24")))
				require.NoError(t, err)
			},
		},
		{
			name: "retag",
			write: func(t *testing.T, s *state.State, viewer types.NodeID) {
				t.Helper()

				_, err := s.SetNodeTags(viewer, []string{"tag:client"})
				require.NoError(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, viaPolicy("u1@", "10.0.0.0/24"))
			viewer, router := ids[0], ids[2]

			n := mustNode(t, s, router).AsStruct()
			n.Tags = []string{"tag:router"}
			n.UserID, n.User = nil, nil
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			n.ApprovedRoutes = []netip.Prefix{route}
			s.PutNodeInStoreForTest(*n)
			s.Connect(router)

			hub := NewHub()
			streams := map[types.NodeID]*Stream{}
			clients := map[types.NodeID]*modelClient{}

			for _, id := range ids {
				st := NewStream(cfg, hub, id, capVer)
				resps, err := st.Initial(s.Snapshot())
				require.NoError(t, err)

				clients[id] = newModelClient(resps[0])
				for _, resp := range resps[1:] {
					clients[id].apply(resp)
				}

				st.Delivered()
				streams[id] = st
			}

			sent := func() bool {
				p, ok := clients[viewer].peers[router.NodeID()]
				require.True(t, ok, "the node ACL keeps the router visible")

				return slices.Contains(p.AllowedIPs, route)
			}
			require.True(t, sent(), "the app-only via grant steers the route to the viewer")

			last := s.Snapshot()
			step := func(what string) {
				t.Helper()

				snap := s.Snapshot()
				all, wake := Route(last, snap, snap.Since(last))
				last = snap

				for _, id := range ids {
					if _, ok := wake[id]; !all && !ok {
						continue
					}

					resps, err := streams[id].Update(snap)
					require.NoError(t, err)

					for _, resp := range resps {
						clients[id].apply(resp)
					}

					streams[id].Delivered()
				}

				for _, id := range ids {
					fresh, err := NewStream(cfg, NewHub(), id, capVer).Initial(snap)
					require.NoError(t, err)
					require.Empty(t, clients[id].sameAs(newModelClient(fresh[0])), "%s: node %d", what, id)
				}
			}

			tc.write(t, s, viewer)
			step(tc.name)
			require.Equal(t, tc.served, sent())

			// An endpoint update after the edit stays a patch: it does not
			// recompile, so it must not make the viewer re-render routes.
			rendered := streams[viewer].r.rendered
			ep := mustNode(t, s, router).AsStruct()
			ep.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
			s.PutNodeInStoreForTest(*ep)
			step("endpoint")
			assert.Equal(t, rendered+1, streams[viewer].r.rendered, "an endpoint update renders only the changed peer")
		})
	}
}

// TestOfflinePeerHistorySurvivesPartialReconnect keeps clients at different
// generations of one peer class, then loses the removal frame on a reconnect:
// the next reconnect replays the removal. Removals a client holds only from a
// failed write are pinned by TestHubFoldsUnconfirmedViews and
// TestStreamAnnouncesRemovalOfAPeerOnlyAFailedInitialCarried; policy-driven
// removal of a still-live peer is pinned by the random-writes oracle test.
func TestOfflinePeerHistorySurvivesPartialReconnect(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	clients := make(map[types.NodeID]*modelClient)

	for i := range 12 {
		n := s.CreateRegisteredNodeForTest(u1, fmt.Sprintf("offline-%d", i))
		n.User = u1
		s.PutNodeInStoreForTest(*n)
		sess := hub.Join(n.ID, func() {})
		st := NewStream(cfg, hub, n.ID, preNetmapRemovalsVer)
		st.Attach(sess)
		resps, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		require.Len(t, resps, 1)
		clients[n.ID] = newModelClient(resps[0])

		st.Delivered()
		require.False(t, hub.Leave(sess))
	}

	// Every client pinned the generation it left: distinct revisions, one
	// current class.
	hub.mu.Lock()

	generations := make([]uint64, 0, len(clients))
	for id := range clients {
		generations = append(generations, hub.sentPeers[id].rev)
	}
	hub.mu.Unlock()

	distinct := make(map[uint64]bool, len(generations))
	for _, rev := range generations {
		distinct[rev] = true
	}

	require.Len(t, distinct, len(clients), "every client pinned its own generation")

	require.Len(t, s.Snapshot().PeerViews(), 1, "one current class can leave many historical views")
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	for id, client := range clients {
		sess := hub.Join(id, func() {})
		st := NewStream(cfg, hub, id, preNetmapRemovalsVer)
		st.Attach(sess)
		resps, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		require.Len(t, resps, 2)

		// The full frame arrives without the removed peer, but the
		// removal frame that would clear the delta consumer fails.
		require.NotContains(t, peerSet(resps[0]), ids[1].NodeID())
		client.apply(resps[0])
		require.Contains(t, client.deltaPeers, ids[1].NodeID())
		require.False(t, hub.Leave(sess))

		sess = hub.Join(id, func() {})
		st = NewStream(cfg, hub, id, preNetmapRemovalsVer)
		st.Attach(sess)
		resps, err = st.Initial(s.Snapshot())
		require.NoError(t, err)
		require.Len(t, resps, 2)
		require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, resps[1].PeersRemoved)

		for _, resp := range resps {
			client.apply(resp)
		}

		st.Delivered()
		require.False(t, hub.Leave(sess))

		resps, err = NewStream(cfg, hub, id, preNetmapRemovalsVer).Initial(s.Snapshot())
		require.NoError(t, err)
		require.Len(t, resps, 1, "a delivered removal needs no replay")

		// The delta consumer now holds exactly a fresh map's peer set.
		assert.Equal(t, peerSet(resps[0]), client.deltaPeers)
		assert.NotContains(t, client.deltaPeers, ids[1].NodeID())
	}
}

// leaveAfterInitial connects id, delivers its initial map and disconnects
// it, returning the client that map built.
func leaveAfterInitial(
	t *testing.T,
	cfg *types.Config,
	s *state.State,
	hub *Hub,
	id types.NodeID,
	cv tailcfg.CapabilityVersion,
) *modelClient {
	t.Helper()

	sess := hub.Join(id, func() {})
	st := NewStream(cfg, hub, id, cv)
	st.Attach(sess)

	resps, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(resps[0])
	for _, resp := range resps[1:] {
		client.apply(resp)
	}

	st.Delivered()
	require.False(t, hub.Leave(sess))

	return client
}

// historyCost is what hub's histories of offline nodes cost by its own
// measure, counted independently: each entry, and each distinct backing
// array its views pin, whole.
func historyCost(hub *Hub) int {
	cost := 0
	for _, view := range historyArrays(hub) {
		cost += cap(view)
	}

	hub.mu.Lock()
	defer hub.mu.Unlock()

	return cost + len(hub.offlineAt)
}

// historyArrays returns the distinct views hub's histories retain, by
// backing array.
func historyArrays(hub *Hub) map[*types.NodeID][]types.NodeID {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	arrays := make(map[*types.NodeID][]types.NodeID, len(hub.sentPeers))

	for _, history := range hub.sentPeers {
		for _, view := range append([][]types.NodeID{history.ids}, history.attempts...) {
			if len(view) > 0 {
				arrays[&view[0]] = view
			}
		}
	}

	return arrays
}

// TestHubDropsOfflinePeerHistoryAfterTTL lets two nodes leave a minute
// apart: each history outlives its node's last session by the TTL, and a
// node back within it is still told what was removed while away. A live
// node's history never expires.
func TestHubDropsOfflinePeerHistoryAfterTTL(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	now := time.Unix(1, 0)
	hub.now = func() time.Time { return now }

	leaveAfterInitial(t, cfg, s, hub, ids[0], capVer)

	now = now.Add(time.Minute)

	leaveAfterInitial(t, cfg, s, hub, ids[2], capVer)
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	now = now.Add(peerHistoryTTL - time.Minute - time.Nanosecond)

	hub.expireHistory()
	require.True(t, hub.HasPeerHistoryForTest(ids[0]), "history lives for the TTL")

	now = now.Add(time.Nanosecond)

	hub.expireHistory()
	require.False(t, hub.HasPeerHistoryForTest(ids[0]), "history is dropped once the TTL passed")
	require.True(t, hub.HasPeerHistoryForTest(ids[2]), "a later leave expires later")

	sess := hub.Join(ids[2], func() {})
	st := NewStream(cfg, hub, ids[2], capVer)
	st.Attach(sess)
	resps, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, resps, 2, "within the TTL a reconnect is told about removals")
	require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, resps[1].PeersRemoved)
	st.Delivered()

	now = now.Add(2 * peerHistoryTTL)

	hub.expireHistory()
	require.True(t, hub.HasPeerHistoryForTest(ids[2]), "a connected node keeps its history")
}

// TestHubCapsOfflinePeerHistory disconnects one new node per membership
// generation, so every offline node pins its own array, under a cap a few
// of them fill: the retained IDs stay under it, and the nodes that left
// first lose their history first.
func TestHubCapsOfflinePeerHistory(t *testing.T) {
	cfg, s, _ := streamTestState(t, "")
	hub := NewHub()
	hub.maxHistoryIDs = 40

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	const leaves = 24

	left := make([]types.NodeID, 0, leaves)

	for i := range leaves {
		n := s.CreateRegisteredNodeForTest(u1, fmt.Sprintf("offline-%d", i))
		n.User = u1
		s.PutNodeInStoreForTest(*n)
		leaveAfterInitial(t, cfg, s, hub, n.ID, capVer)
		left = append(left, n.ID)

		retained := historyCost(hub)
		require.LessOrEqual(t, retained, hub.maxHistoryIDs, "after %d leaves", i+1)

		hub.mu.Lock()
		counted := hub.retained
		hub.mu.Unlock()
		require.Equal(t, retained, counted, "the hub counts what its histories hold")
	}

	kept := slices.DeleteFunc(slices.Clone(left), func(id types.NodeID) bool { return !hub.HasPeerHistoryForTest(id) })
	require.NotEmpty(t, kept, "the cap keeps the latest histories")
	require.Less(t, len(kept), len(left), "the cap dropped histories")
	require.Equal(t, left[len(left)-len(kept):], kept, "the oldest offline histories go first")
}

// leaveWithHistory gives id the history v, then connects and disconnects it.
func leaveWithHistory(t *testing.T, hub *Hub, id types.NodeID, v sentView) {
	t.Helper()

	hub.mu.Lock()
	hub.sentPeers[id] = v
	hub.mu.Unlock()

	require.False(t, hub.Leave(hub.Join(id, func() {})))
}

func retainedOf(hub *Hub) int {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	return hub.retained
}

// TestHubCapsEmptyOfflineHistories disconnects more isolated nodes, whose
// histories hold no IDs, than the cap: the entries themselves are bounded,
// oldest first.
func TestHubCapsEmptyOfflineHistories(t *testing.T) {
	hub := NewHub()
	hub.maxHistoryIDs = 4

	for i := range 12 {
		leaveWithHistory(t, hub, types.NodeID(100+i), sentView{rev: uint64(i + 1)})

		hub.mu.Lock()
		entries := len(hub.offlineAt)
		hub.mu.Unlock()

		require.LessOrEqual(t, entries, hub.maxHistoryIDs, "after %d leaves", i+1)
		require.Equal(t, historyCost(hub), retainedOf(hub), "the hub counts what its histories hold")
	}

	require.False(t, hub.HasPeerHistoryForTest(100), "the oldest history goes first")
	require.True(t, hub.HasPeerHistoryForTest(111), "the latest history stays")
}

// TestHubCapsFailedAttemptsOfOfflineNodes disconnects nodes whose history
// is only views written but never confirmed: they count against the cap
// like delivered ones.
func TestHubCapsFailedAttemptsOfOfflineNodes(t *testing.T) {
	hub := NewHub()
	hub.maxHistoryIDs = 20

	for i := range 10 {
		id := types.NodeID(100 + i)
		attempt := []types.NodeID{id + 1, id + 2, id + 3, id + 4}
		leaveWithHistory(t, hub, id, sentView{rev: uint64(i + 1), attempts: [][]types.NodeID{attempt}})

		require.LessOrEqual(t, historyCost(hub), hub.maxHistoryIDs, "after %d leaves", i+1)
		require.Equal(t, historyCost(hub), retainedOf(hub))
	}

	require.False(t, hub.HasPeerHistoryForTest(100), "failed attempts are evicted like deliveries")
}

// TestHubCountsASharedViewOnce lets two nodes that were sent the same
// snapshot view go offline: the view pins one array, counted once.
func TestHubCountsASharedViewOnce(t *testing.T) {
	hub := NewHub()
	view := []types.NodeID{1, 2, 3, 4, 5}

	leaveWithHistory(t, hub, 10, sentView{ids: view, rev: 1})
	leaveWithHistory(t, hub, 11, sentView{ids: view, rev: 1})

	require.Equal(t, cap(view)+2, retainedOf(hub), "one array and two entries")
	require.Equal(t, historyCost(hub), retainedOf(hub))
}

// TestHubTTLRestartsOnRejoin brings a node back within the TTL and lets it
// leave again: its history then lives a TTL from the second leave.
func TestHubTTLRestartsOnRejoin(t *testing.T) {
	hub := NewHub()
	now := time.Unix(1, 0)
	hub.now = func() time.Time { return now }

	leaveWithHistory(t, hub, 10, sentView{ids: []types.NodeID{1}, rev: 1})

	now = now.Add(peerHistoryTTL - time.Minute)

	require.False(t, hub.Leave(hub.Join(10, func() {})))

	now = now.Add(peerHistoryTTL - time.Nanosecond)

	hub.expireHistory()
	require.True(t, hub.HasPeerHistoryForTest(10), "the TTL counts from the last leave")

	now = now.Add(time.Nanosecond)

	hub.expireHistory()
	require.False(t, hub.HasPeerHistoryForTest(10))
	require.Zero(t, retainedOf(hub))
}

// TestHubBoundsFailedHistoryOfAConnectedNode keeps a node connected through
// overlapping sessions while its writes fail, each attempt carrying a peer
// that then goes away: the folded union of its attempts must stay under
// the cap though the node never leaves. Confirmed deliveries keep it to the
// last view.
func TestHubBoundsFailedHistoryOfAConnectedNode(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(fmt.Sprintf("delivered=%v", delivered), func(t *testing.T) {
			hub := NewHub()
			hub.maxHistoryIDs = 8

			const id = types.NodeID(1)

			sessions := []*Session{hub.Join(id, func() {}), hub.Join(id, func() {})}

			for i := range 48 {
				v := sentView{ids: []types.NodeID{types.NodeID(1000 + i)}, rev: uint64(i + 1)}
				by := sessions[i%2]

				hub.mayHavePeers(by, id, v)

				if delivered {
					hub.setLastPeers(by, id, v)
				}

				require.LessOrEqual(t, retainedOf(hub), hub.maxHistoryIDs, "after %d attempts", i+1)
				require.LessOrEqual(t, len(hub.lastPeers(id)), hub.maxHistoryIDs+maxPeerAttempts,
					"after %d attempts: peers of failed writes accumulate", i+1)
			}

			if delivered {
				require.Equal(t, []types.NodeID{1047}, hub.lastPeers(id), "deliveries keep the last view")
			}

			require.True(t, hub.Leave(sessions[0]))
			require.False(t, hub.Leave(sessions[1]))
			require.Equal(t, historyCost(hub), retainedOf(hub))
		})
	}
}

// TestFoldedHistoryIsRightSized folds attempts that repeat the same peers:
// the union kept must not pin the concatenation it was built from, and is
// counted by what it pins.
func TestFoldedHistoryIsRightSized(t *testing.T) {
	hub := NewHub()

	const id = types.NodeID(1)

	sess := hub.Join(id, func() {})

	for i := range maxPeerAttempts + 1 {
		hub.mayHavePeers(sess, id, sentView{ids: []types.NodeID{2, 3, 4, 5, 6}, rev: uint64(i + 1)})
	}

	hub.mu.Lock()
	cur := hub.sentPeers[id]
	hub.mu.Unlock()

	require.True(t, cur.folded, "test sanity: the attempts folded")
	require.Equal(t, []types.NodeID{2, 3, 4, 5, 6}, cur.ids)
	require.Equal(t, len(cur.ids), cap(cur.ids), "the union pins the concatenation it was built from")
	require.Equal(t, cap(cur.ids), retainedOf(hub), "a connected node's folded union is counted")
}

// TestStreamReturningAfterHistoryExpiryConvergesOnAFreshMap brings a node
// back after its history expired, with no sweep in between: the reconnect
// itself must not replay the expired history, and the client converges on
// exactly what a fresh session gets. A consumer that learns removals only
// from PeersRemoved keeps a peer deleted while it was away: the price of
// bounding history, as upstream paid after its 15 minutes.
func TestStreamReturningAfterHistoryExpiryConvergesOnAFreshMap(t *testing.T) {
	for _, cv := range []tailcfg.CapabilityVersion{preNetmapRemovalsVer, capVer} {
		t.Run(fmt.Sprintf("cap=%d", cv), func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")
			hub := NewHub()
			now := time.Unix(1, 0)
			hub.now = func() time.Time { return now }

			client := leaveAfterInitial(t, cfg, s, hub, ids[0], cv)
			require.Contains(t, client.peers, ids[1].NodeID())

			require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

			u2, err := s.GetUserByName("u2")
			require.NoError(t, err)

			joined := s.CreateRegisteredNodeForTest(u2, "joined-while-away")
			joined.User = u2
			s.PutNodeInStoreForTest(*joined)

			now = now.Add(peerHistoryTTL)

			sess := hub.Join(ids[0], func() {})
			st := NewStream(cfg, hub, ids[0], cv)
			st.Attach(sess)
			resps, err := st.Initial(s.Snapshot())
			require.NoError(t, err)
			require.Len(t, resps, 1, "expired history announces no removals")

			client.apply(resps[0])
			st.Delivered()

			fresh, err := NewStream(cfg, NewHub(), ids[0], cv).Initial(s.Snapshot())
			require.NoError(t, err)
			require.Empty(t, client.sameAs(newModelClient(fresh[0])))
			require.Contains(t, client.peers, joined.ID.NodeID())
			require.Contains(t, client.deltaPeers, ids[1].NodeID(), "a delta-only consumer misses the removal")
		})
	}
}

// BenchmarkOfflinePeerHistory measures retained peer-ID storage after all
// sessions leave. Growing views differ by one join per disconnect; shared
// views all come from one snapshot; growing-sparse keeps the growing counts
// while spacing the IDs apart, a control for the ID-compressed designs the
// docs weigh, where raw slices still retain by array, not by ID value. Every
// simulated delivery succeeds, so the counts cover confirmed views: a write
// that fails part way keeps the same arrays as unconfirmed attempts. Counts
// deduplicate backing arrays but exclude maps, render caches and heap slack.
// No clock advances, so only [maxPeerHistoryIDs] drops history.
func BenchmarkOfflinePeerHistory(b *testing.B) {
	for _, n := range []int{64, 256, 1024} {
		for _, shape := range []string{"shared", "growing", "growing-sparse"} {
			for _, version := range []tailcfg.CapabilityVersion{preNetmapRemovalsVer, capver.FullNetmapRemovalsCapVer} {
				b.Run(fmt.Sprintf("%s/cap=%d/offline=%d", shape, version, n), func(b *testing.B) {
					initial := 3
					if shape == "shared" {
						initial += n
					}

					cfg, s := benchState(b, initial, 1)
					base := s.ListNodes()
					nodes := make(types.Nodes, n)
					ip4, ip6 := base.At(2).IPv4().Get().Next(), base.At(2).IPv6().Get().Next()

					for i := range nodes {
						if shape == "shared" {
							nodes[i] = base.At(i + 3).AsStruct()

							continue
						}

						node := base.At(0).AsStruct()

						node.ID = types.NodeID(i + 4) //nolint:gosec // bounded benchmark size
						if shape == "growing-sparse" {
							node.ID <<= 20
						}

						node.Hostname = fmt.Sprintf("offline-%d", i)
						node.GivenName = node.Hostname
						node.NodeKey = key.NewNode().Public()
						v4, v6 := ip4, ip6
						node.IPv4, node.IPv6 = &v4, &v6
						nodes[i] = node
						ip4, ip6 = ip4.Next(), ip6.Next()
					}

					for b.Loop() {
						hub := NewHub()

						for _, node := range nodes {
							if shape != "shared" {
								// Membership writes are not what is
								// measured; keep shapes comparable.
								b.StopTimer()
								s.PutNodeInStoreForTest(*node)
								b.StartTimer()
							}

							sess := hub.Join(node.ID, func() {})
							st := NewStream(cfg, hub, node.ID, version)
							st.Attach(sess)

							_, err := st.Initial(s.Snapshot())
							if err != nil {
								b.Fatal(err)
							}

							st.Delivered()

							if hub.Leave(sess) {
								b.Fatal("unexpected second session")
							}
						}

						b.StopTimer()

						hub.mu.Lock()
						histories := len(hub.sentPeers)
						hub.mu.Unlock()

						arrays := historyArrays(hub)

						var retained, capacity int
						for _, view := range arrays {
							retained += len(view)
							capacity += cap(view)
						}

						// The table in docs/ref/debug.md restates these counts;
						// they are asserted whenever the benchmark runs, and no
						// CI lane runs benchmarks. Only the counts are asserted:
						// bytes report allocator-dependent capacity, which the
						// doc anchors to its toolchain.
						switch {
						case shape == "shared":
							require.Equal(b, n, histories, "one history per offline node")
							require.Len(b, arrays, 1, "one class pins one array")
							require.Equal(b, n+3, retained)
						case n*(n+7)/2 <= maxPeerHistoryIDs:
							require.Equal(b, n, histories, "one history per offline node")
							require.Len(b, arrays, n, "one array per generation")
							require.Equal(b, n*(n+7)/2, retained)
						default:
							require.Less(b, histories, n, "the cap dropped the oldest histories")
							require.Len(b, arrays, histories, "one array per generation")
							require.LessOrEqual(b, retained, maxPeerHistoryIDs)
						}

						views := s.Snapshot().PeerViews()
						b.ReportMetric(float64(len(views)), "current-classes")

						// The published view count: the one class holds
						// every offline node and itself.
						require.Len(b, views, 1, "one current class")
						require.Len(b, views[0], n+3)
						b.ReportMetric(float64(len(views[0])), "view-IDs")

						b.ReportMetric(float64(histories), "histories")
						b.ReportMetric(float64(len(arrays)), "history-arrays")
						b.ReportMetric(float64(retained), "retained-IDs")
						b.ReportMetric(float64(capacity*8), "history-ID-bytes")
						runtime.KeepAlive(hub)

						if shape != "shared" {
							for _, node := range nodes {
								s.DeleteNodeFromStoreForTest(node.ID)
							}
						}

						b.StartTimer()
					}
				})
			}
		}
	}
}
