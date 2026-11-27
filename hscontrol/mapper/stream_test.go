package mapper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
	"weak"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/graph"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	"tailscale.com/version"
)

const capVer = tailcfg.CurrentCapabilityVersion

// preNetmapRemovalsVer is one below the capability version of Tailscale v1.104,
// the first release whose clients also derived removals from a full netmap
// (tailscale/tailscale#15660): these clients still need explicit
// PeersRemoved frames. The hub emits them for every capability version.
const preNetmapRemovalsVer = capver.FullNetmapRemovalsCapVer - 1

// streamTestState returns a State with users u1, u2 and nodes n1, n1b
// (u1) and n2 (u2), under policy (allow-all when empty).
func streamTestState(tb pbtT, policy string, configure ...func(*types.Config)) (*types.Config, *state.State, [3]types.NodeID) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: streamTestDir(tb) + "/h.db"},
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

func streamTestDir(tb pbtT) string {
	tb.Helper()

	if t, ok := tb.(testing.TB); ok {
		return t.TempDir()
	}

	// Rapid cleans up each generated case, including a replay during shrinking.
	dir, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), "headscale-mapper-")
	require.NoError(tb, err)
	tb.Cleanup(func() {
		err := os.RemoveAll(dir) //nolint:gosec // MkdirTemp created this directory.
		require.NoError(tb, err)
	})

	return dir
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

func TestStreamMembershipDeltaCandidates(t *testing.T) {
	// Pinned to address form: a membership edit moves the stamps of the nodes it moves, whose viewers render them again.
	t.Setenv(state.TestCapabilitySourcesEnv, "false")

	for _, kind := range []string{"join", "leave", "replace", "coalesced", "coalesced-outside", "caps", "visibility", "invalid", "repair"} {
		t.Run(kind, func(t *testing.T) {
			policy := ""
			if kind == "coalesced-outside" {
				policy = ownUserOnly
			}

			cfg, s, ids := streamTestState(t, policy)
			hub := NewHub()
			t.Cleanup(hub.Close)
			st := NewStream(cfg, hub, ids[0], capVer)

			if kind == "repair" {
				n := mustNode(t, s, ids[1]).AsStruct()
				n.Expiry = new(time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC))
				s.PutNodeInStoreForTest(*n)
			}

			before := s.Snapshot()
			initial, err := st.Initial(before)
			require.NoError(t, err)
			st.Delivered()

			client := newModelClient(initial[0])
			oldPeerMap := st.r.lastClass
			oldClass := maps.Collect(oldPeerMap.All())

			joined := mustNode(t, s, ids[2]).AsStruct()
			joined.ID = types.NodeID(1 << 40)
			joined.Hostname, joined.GivenName = "joined", "joined"
			joined.IPv4, joined.IPv6 = new(netip.MustParseAddr("100.100.100.100")), nil

			limit := 1

			switch kind {
			case "leave":
				s.DeleteNodeFromStoreForTest(ids[2])
			case "replace":
				s.DeleteNodeFromStoreForTest(ids[2])
				s.PutNodeInStoreForTest(*joined)

				limit = 2
			case "coalesced":
				for i := range 32 {
					scalingEndpoint(t, s, ids[1], i+1)
				}

				s.PutNodeInStoreForTest(*joined)
				s.DeleteNodeFromStoreForTest(joined.ID)
				joined.ID++
				s.PutNodeInStoreForTest(*joined)

				limit = 2
			case "coalesced-outside":
				for i := range 32 {
					scalingEndpoint(t, s, ids[2], i+1)
				}

				owner := mustNode(t, s, ids[1]).AsStruct()
				joined.UserID, joined.User = owner.UserID, owner.User
				s.PutNodeInStoreForTest(*joined)
			case "caps":
				s.PutNodeInStoreForTest(*joined)
				_, err = s.SetPolicy([]byte(fmt.Sprintf(`{"nodeAttrs":[{"target":[%q],"attr":["custom:probe"]}]}`, mustNode(t, s, ids[1]).IPs()[0].String())))
				require.NoError(t, err)

				limit = 2
			case "visibility":
				_, err = s.SetPolicy([]byte(ownUserOnly))
				require.NoError(t, err)
			case "invalid", "repair":
				n := mustNode(t, s, ids[1]).AsStruct()

				n.Expiry = nil
				if kind == "invalid" {
					n.Expiry = new(time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC))
				}

				s.PutNodeInStoreForTest(*n)
				s.PutNodeInStoreForTest(*joined)

				limit = 2
			default:
				s.PutNodeInStoreForTest(*joined)
			}

			after := s.Snapshot()
			view := after.PeerView(ids[0])
			require.False(t, len(view) == len(st.r.lastPeerIDs) && len(view) > 0 && &view[0] == &st.r.lastPeerIDs[0], "fixture must replace view identity")
			class, _, _ := st.r.classes.get(cfg, st.r.renders, after, view, capVer, after.CapsRev(), after.NodeCaps)
			misses := graph.MapLogMisses()
			candidates := st.r.peerCandidates(after, class, view)

			if kind == "coalesced" || kind == "coalesced-outside" {
				misses++ // The coalesced edit log is larger than these tiny views.
			}

			require.Equal(t, misses, graph.MapLogMisses(), "use the smaller candidate source")
			slices.Sort(candidates)
			candidates = slices.Compact(candidates)
			require.Subset(t, candidates, graph.Changes(st.r.lastClass, class), "candidates must cover every changed render")
			require.LessOrEqual(t, len(candidates), limit, "membership edits must not name every peer")

			check := func(snap *state.Snapshot) {
				t.Helper()

				updates, err := st.Update(snap)
				require.NoError(t, err)

				for _, response := range updates {
					client.apply(response)
				}

				st.Delivered()

				freshHub := NewHub()
				t.Cleanup(freshHub.Close)
				fresh, err := NewStream(cfg, freshHub, ids[0], capVer).Initial(snap)
				require.NoError(t, err)
				require.Empty(t, client.sameAs(newModelClient(fresh[0])))
			}
			check(after)
			check(before) // An older snapshot cannot use the forward node edit log.
			check(after)
			require.Equal(t, oldClass, maps.Collect(oldPeerMap.All()), "old class must stay immutable")
		})
	}
}

func TestStreamSharesClassNodeCursor(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	t.Cleanup(hub.Close)
	streams := []*Stream{NewStream(cfg, hub, ids[0], capVer), NewStream(cfg, hub, ids[1], capVer)}

	check := func(snap *state.Snapshot) {
		t.Helper()

		for _, st := range streams {
			var err error
			if st.sent == nil {
				_, err = st.Initial(snap)
			} else {
				_, err = st.Update(snap)
			}

			require.NoError(t, err)
			st.Delivered()
		}

		_, _, cursor := streams[0].r.classes.get(cfg, streams[0].r.renders, snap, snap.PeerView(ids[0]), capVer, snap.CapsRev(), snap.NodeCaps)
		for _, st := range streams {
			if cursor != st.r.lastNodes {
				t.Fatal("sessions must share their class's existing cursor")
			}
		}
	}

	before := s.Snapshot()
	check(before)
	scalingEndpoint(t, s, ids[2], 1)
	after := s.Snapshot()
	check(after)

	for _, st := range streams {
		_, err := st.Update(before)
		require.NoError(t, err)
		st.Delivered()
		touched, ok := after.NodesTouchedSince(st.r.lastNodes)
		require.True(t, ok)
		require.Equal(t, []types.NodeID{ids[2]}, touched, "stale renders must use their own snapshot's cursor")
	}

	check(after)
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

func mustNode(tb pbtT, s *state.State, id types.NodeID) types.NodeView {
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
	chunks   policyv2.FilterChunks
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

// served is the client's own entry and its peers', by ID, as views for
// the stored judge ([statemodel.Served]).
func (c *modelClient) served() (tailcfg.NodeView, []tailcfg.NodeView) {
	var self tailcfg.NodeView
	if c.self != nil {
		self = c.self.View()
	}

	peers := make([]tailcfg.NodeView, 0, len(c.peers))
	for _, id := range slices.Sorted(maps.Keys(c.peers)) {
		if p := c.peers[id]; p != nil {
			peers = append(peers, p.View())
		}
	}

	return self, peers
}

// capHolders returns the addresses of the nodes the client holds, itself
// and its peers, whose CapMap has capability.
func (c *modelClient) capHolders(capability nodecap.Cap) []netip.Addr {
	var out []netip.Addr

	for _, n := range append([]*tailcfg.Node{c.self}, slices.Collect(maps.Values(c.peers))...) {
		if n == nil {
			continue
		}

		if _, ok := n.CapMap[capability]; !ok {
			continue
		}

		for _, p := range n.Addresses {
			if p.IsSingleIP() {
				out = append(out, p.Addr())
			}
		}
	}

	return out
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

	// The filter is what the client assembles from the chunks it holds,
	// whichever way they came: "base" in address mode, named chunks in
	// capability mode.
	if r.PacketFilter != nil || r.PacketFilters != nil {
		c.chunks = c.chunks.ApplyResponse(r)
		c.filter = c.chunks.Rules()
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
	case !fresh.chunks.Equal(c.chunks):
		return fmt.Sprintf("filter chunks: have %v, want %v", c.chunks.Names(), fresh.chunks.Names())
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
			routes := []netip.Prefix{route}
			// An exit route is offered only with the other family's.
			if tsaddr.IsExitRoute(route) {
				routes = append(routes, tsaddr.AllIPv6())
			}

			router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
			router.ApprovedRoutes = routes
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

// TestStreamRouteOverlaySurvivesRerenderedPeer pins a viewer's route overlay
// while its class map holds an unchanged peer under another pointer than the
// viewer's map: a session behind the viewer renders the peer's previous
// version into the shared render cache, so the viewer's next class, rebuilt
// for a join, renders the peer anew. When that peer and the router then
// change together, the peer must not count as an overlay the viewer lost.
func TestStreamRouteOverlaySurvivesRerenderedPeer(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	viewer, peer, router := ids[0], ids[1], ids[2]
	route := netip.MustParsePrefix("10.0.0.0/24")

	n := mustNode(t, s, router).AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	n.ApprovedRoutes = []netip.Prefix{route}
	s.PutNodeInStoreForTest(*n)
	s.Connect(router)

	hub := NewHub()
	t.Cleanup(hub.Close)

	st := NewStream(cfg, hub, viewer, capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	behind := NewStream(cfg, hub, router, capVer)
	_, err = behind.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])
	update := func() {
		t.Helper()

		resps, err := st.Update(s.Snapshot())
		require.NoError(t, err)

		for _, resp := range resps {
			client.apply(resp)
		}

		st.Delivered()
	}

	scalingEndpoint(t, s, peer, 1)
	stale := s.Snapshot()
	scalingEndpoint(t, s, peer, 2)
	update()

	// The router's session renders the snapshot it read before the last write.
	_, err = behind.Update(stale)
	require.NoError(t, err)

	joined := mustNode(t, s, peer).AsStruct()
	joined.ID = types.NodeID(1 << 40)
	joined.Hostname, joined.GivenName = "joined", "joined"
	joined.IPv4, joined.IPv6 = new(netip.MustParseAddr("100.100.100.100")), nil
	s.PutNodeInStoreForTest(*joined)
	update()

	held, _ := st.sent.peer(peer.NodeID())
	plain, _ := st.r.lastClass.Get(peer.NodeID())
	require.NotSame(t, plain, held, "fixture must leave the viewer an equal render under another pointer")

	scalingEndpoint(t, s, peer, 3)
	scalingEndpoint(t, s, router, 1)
	update()

	sent, ok := st.sent.peer(router.NodeID())
	require.True(t, ok)
	assert.Contains(t, sent.AllowedIPs, route, "the router keeps the viewer's route")

	fresh, err := NewStream(cfg, NewHub(), viewer, capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, client.sameAs(newModelClient(fresh[0])))
}

// TestViewersGivenTheSameRoutesShareRoutedPeers holds what a session keeps
// for its routed peers to what it is given: the sessions given the same
// routes of a router hold one render of it, and the sessions of a class
// given the same routes of every router hold one peer map. So a session
// costs the same however many routers it shares with the others, where a
// copy of every routed peer per session would cost the control plane
// sessions × routers.
func TestViewersGivenTheSameRoutesShareRoutedPeers(t *testing.T) {
	const nodes, extra = 160, 40

	perSession := map[int]int64{}

	for _, routers := range []int{4, 64} {
		cfg, s := benchState(t, nodes, 4)
		all := s.ListNodes()

		for i := range routers {
			n := all.At(i).AsStruct()
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 0}), 24)
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{p}}
			n.ApprovedRoutes = []netip.Prefix{p}
			s.PutNodeInStoreForTest(*n)
			s.Connect(n.ID)
		}

		snap := s.Snapshot()
		hub := NewHub()

		streams := make([]*Stream, 0, nodes)

		for _, nv := range all.All() {
			st := NewStream(cfg, hub, nv.ID(), capVer)
			_, err := st.Initial(snap)
			require.NoError(t, err)

			streams = append(streams, st)
		}

		// The most renders any router is held in beyond the routes it gives.
		worst, held := 0, 0

		for i := range routers {
			router := mustNode(t, s, all.At(i).ID())
			answers, copies := map[string]struct{}{}, map[*tailcfg.Node]struct{}{}

			for _, st := range streams {
				if st.nodeID == router.ID() {
					continue
				}

				routes := snap.RoutesForPeer(mustNode(t, s, st.nodeID), router)
				require.NotEmpty(t, routes, "test sanity: every viewer is given router %d's route", i)
				answers[fmt.Sprint(routes)] = struct{}{}

				p, ok := st.sent.peer(router.ID().NodeID())
				require.True(t, ok)
				require.Contains(t, p.AllowedIPs, routes[0])

				copies[p] = struct{}{}
			}

			if extra := len(copies) - len(answers); extra > worst {
				worst, held = extra, len(copies)
			}
		}

		assert.Zero(t, worst, "%d routers: %d viewers given one route of a router hold %d renders of it", routers, nodes-1, held)

		peerMaps := map[*peerMap]struct{}{}
		for _, st := range streams {
			peerMaps[st.sent.peers] = struct{}{}
		}

		assert.Equal(t, 1, len(peerMaps), "%d routers: the sessions of one class given the same routes share one peer map", routers) //nolint:testifylint // the count is the message

		// More sessions of members, which share every router with the rest.
		perSession[routers] = heapPerSession(t, extra, func(k int) *Stream {
			st := NewStream(cfg, hub, all.At(routers+k).ID(), capVer)
			_, err := st.Initial(snap)
			require.NoError(t, err)

			return st
		})

		runtime.KeepAlive(streams)
	}

	t.Logf("heap kept per session: %d B with 4 routers, %d B with 64", perSession[4], perSession[64])
	assert.Less(t, perSession[64]-perSession[4], int64(2048),
		"sixty more routers shared with every other session must not grow a session")
}

// heapPerSession returns what each of the n sessions add returns adds to the
// heap kept. The cleanups earlier tests leave run after a collection and free
// more, so the heap is read once a collection frees nothing more, and the
// median of three batches is taken.
func heapPerSession(t *testing.T, n int, add func(k int) *Stream) int64 {
	t.Helper()

	heap := func() int64 {
		var last int64

		for i := range 20 {
			runtime.GC()

			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)

			h := int64(ms.HeapAlloc) //nolint:gosec // a heap fits
			if i > 0 && h-last < 1024 && last-h < 1024 {
				return h
			}

			last = h

			runtime.Gosched()
		}

		return last
	}

	batches, added := make([]int64, 0, 3), make([]*Stream, 0, 3*n)

	for range 3 {
		before := heap()

		for k := range n {
			added = append(added, add(k))
		}

		batches = append(batches, (heap()-before)/int64(n))
	}

	runtime.KeepAlive(added)
	slices.Sort(batches)

	return batches[1]
}

// TestIdleSessionKeepsNoPeerList holds a session that has sent its first map
// and waits to what its peers' map costs, which its class shares: the list
// of peers the first map named is spent once the map is sent, so a session
// costs the same however many peers it holds.
func TestIdleSessionKeepsNoPeerList(t *testing.T) {
	const extra = 40

	perSession := map[int]int64{}

	for _, nodes := range []int{60, 660} {
		cfg, s := benchState(t, nodes, 4)
		all := s.ListNodes()
		snap := s.Snapshot()
		hub := NewHub()

		// The class's map, which every session shares, is built once.
		first := NewStream(cfg, hub, all.At(0).ID(), capVer)
		_, err := first.Initial(snap)
		require.NoError(t, err)

		perSession[nodes] = heapPerSession(t, extra, func(k int) *Stream {
			st := NewStream(cfg, hub, all.At(1+k).ID(), capVer)
			resps, err := st.Initial(snap)
			require.NoError(t, err)
			require.Len(t, resps[0].Peers, nodes-1, "test sanity: a session sees every other node")

			return st
		})

		runtime.KeepAlive(first)
	}

	t.Logf("heap kept per idle session: %d B with 59 peers, %d B with 659", perSession[60], perSession[660])
	assert.Less(t, perSession[660]-perSession[60], int64(600),
		"six hundred more peers, shared with every other session, must not grow an idle session")
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

	// As in scalingTailnet: the fixture's fsyncs are its cost on disk, and
	// the state reopens the file with its own settings.
	require.NoError(tb, database.DB.Exec("PRAGMA synchronous = OFF").Error)

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

	reach := runStreamsConverge(t, oracleAudited)

	require.Equal(t, failures, state.PolicyAuditFailures(), "incremental compiles must match compiles from scratch")

	reach.require(t)
}

// TestStreamsMatchTheCompileUnderRandomWrites runs the random writes of
// [TestStreamsConvergeUnderRandomWrites] with the policy audit off, as
// production runs, and holds what every session holds — its peers, its
// packet filter and each peer's routes — to what the compile, which
// serves none of them, gives for the same snapshot. A fresh session shares
// any mistake of the served path; the compile does not.
func TestStreamsMatchTheCompileUnderRandomWrites(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	// Either delivery, the source form as the suite runs it.
	for _, chunks := range []bool{false, true} {
		t.Run(fmt.Sprintf("filter_chunks=%t", chunks), func(t *testing.T) {
			t.Setenv(state.TestFilterChunksEnv, strconv.FormatBool(chunks))

			reach := runStreamsConverge(t, oracleCompile)
			reach.require(t)
			require.NotZero(t, reach.retuned, "a rule's port, protocol or app value edited in place at some step")
		})
	}
}

// TestRouteLeavesNoSessionStale holds routing to the snapshot with the
// policy audit off, as production runs: under every policy the random
// writes switch between, every kind of write, alone and coalesced with
// another, is routed as the hub routes it, the sessions it wakes update,
// and every session not waiting on a wake must hold what a fresh render
// gives. The fresh render has caches of its own and cuts filters afresh: a
// filter carried over on routing's word would share routing's mistake. A
// third of the sessions lag, taking their wakes every fourth write, so
// they render across several commits.
func TestRouteLeavesNoSessionStale(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	var reach oracleReach

	// Fallbacks reached, by label, in capability mode.
	fallbacks := map[string]int{}

	// One more document for this test alone: an app capability rule, a
	// rule over a protocol without ports, and a * source, each of which
	// capability form writes as addresses whatever the receiver.
	policies := append(slices.Clone(oraclePolicies), `{"groups":{"group:g":["u1@"]},"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
	  "grants":[{"src":["group:g"],"dst":["tag:a","u2@"],"app":{"example.com/cap/x":[{}]}},
	            {"src":["u2@"],"dst":["u1@"],"ip":["gre:*"]},
	            {"src":["autogroup:member"],"dst":["autogroup:member"],"ip":["tcp:22"]},
	            {"src":["*"],"dst":["tag:b","u1@"],"ip":["tcp:80"]}]}`)

	for pi, pol := range policies {
		t.Run(fmt.Sprintf("policy=%d", pi), func(t *testing.T) {
			r := rand.New(rand.NewPCG(uint64(pi), 11)) //nolint:gosec // deterministic test input
			// Draws of its own for what happens between coalesced commits,
			// and for the receiver facts and addresses it moves, so the
			// writes are those of the stream above.
			between := rand.New(rand.NewPCG(uint64(pi), 12)) //nolint:gosec // deterministic test input

			o, cfg, hub, sessions := newOracleRun(t, r, &reach)
			s := o.s

			_, err := s.SetPolicy([]byte(pol))
			if err != nil {
				// The random writes try it as a refused edit; op 10 does here.
				t.Skipf("the document is refused: %v", err)
			}

			for _, id := range slices.Sorted(maps.Keys(sessions)) {
				_, err := sessions[id].st.Update(s.Snapshot())
				require.NoError(t, err)
				sessions[id].st.Delivered()
			}

			last := s.Snapshot()
			pending := map[types.NodeID]bool{}
			step, routed := 0, 0

			// Sessions render through the hub, as the poll loop does, so it
			// knows which rendered a snapshot between coalesced commits.
			render := func(id types.NodeID, snap *state.Snapshot) {
				st := sessions[id].st
				if st.sess == nil {
					st.Attach(hub.Join(id, func() {}))
				}

				_, err := st.Update(snap)
				require.NoError(t, err)
				st.Delivered()

				pending[id] = false
			}

			var rendered []types.NodeID

			deliver := func() {
				snap := s.Snapshot()
				_, all, ids, _ := hub.route(last, snap)

				if !all && snap.Rev() > last.Rev() {
					routed++
				}

				last = snap

				for _, id := range slices.Sorted(maps.Keys(sessions)) {
					if _, live := snap.GetNode(id); !live {
						delete(sessions, id)
						delete(pending, id)

						continue
					}

					if _, ok := ids[id]; all || ok {
						pending[id] = true
					}

					if pending[id] && (id%3 != 0 || step%4 == 0) {
						render(id, snap)
					}
				}

				reach.betweenStale += heldStale(t, cfg, snap, rendered, sessions, pending)
				rendered = nil

				countFallbacks(t, snap, fallbacks)

				if hasServiceHost(snap) {
					reach.serviceHost++
				}

				if hasOneWayView(snap) {
					reach.oneWay++
				}

				requireNoStaleSession(t, step, cfg, snap, sessions, pending)

				if nodeInsideRoute(snap) {
					reach.inside++
				}

				step++
			}

			for round := range 3 {
				for op := range oracleWrites {
					nodes := s.ListNodes()
					nv := nodes.At(r.IntN(nodes.Len()))
					o.writeOp(op, step, nodes, nv, nv.ID())

					// Now and then a receiver fact or an address moves with
					// the write.
					if between.IntN(3) == 0 {
						moveReceiver(t, between, o)
					}

					if (op+round)%4 == 1 {
						// Now and then a node joins here and leaves with the
						// second write: neither end of the routing has it.
						var transient types.NodeID
						if between.IntN(3) == 0 {
							transient = o.addNode(fmt.Sprintf("transient-%d", step))
						}

						// Sessions woken earlier render meanwhile, holding a
						// snapshot neither end of the routing has.
						rendered = renderBetween(between, s.Snapshot(), sessions, pending, render)
						reach.between += len(rendered)

						// A second write the hub routes with the first, as
						// commits coalesce under load.
						if transient != 0 {
							require.NoError(t, s.DeleteNode(mustNode(t, s, transient)))

							reach.transient++
						} else {
							nodes = s.ListNodes()
							nv = nodes.At(r.IntN(nodes.Len()))
							o.writeOp(r.IntN(oracleWrites), step, nodes, nv, nv.ID())
						}
					}

					deliver()

					if string(s.Snapshot().PolicySource()) != pol {
						_, err := s.SetPolicy([]byte(pol))
						require.NoError(t, err)
						deliver()
					}
				}
			}

			require.Positive(t, routed, "some writes were routed to fewer than every session")
		})
	}

	require.NotZero(t, reach.inside, "a node inside another node's route at some step")
	require.NotZero(t, reach.retargeted, "a rule's source or destination moved to another selector")
	require.NotZero(t, reach.regrouped, "a group's members moved by a document edit")
	require.NotZero(t, reach.betweenStale, "a session rendered between coalesced commits held what the routing over both had to wake it for")
	require.NotZero(t, reach.transient, "a node joined and left between two routings")
	require.NotZero(t, reach.oneWay, "a node saw one that did not see it")

	if fallbacks["mode"] > 0 {
		for _, label := range policyv2.FallbackReasons() {
			if label != "address-mode" {
				require.NotZerof(t, fallbacks[label], "capability mode reached the %s fallback", label)
			}
		}

		require.NotZero(t, reach.serviceHost, "a node was sent addresses for being a service host alone")
	}

	t.Logf("fallbacks reached, by steps: %v", fallbacks)
	t.Logf("rendered between coalesced commits %d, of which woken again with something to send %d; transient nodes %d",
		reach.between, reach.betweenStale, reach.transient)
}

// moveReceiver moves a random node's receiver facts or address: its
// client turns unknown or known again, it becomes an app connector or
// stops, or it takes an address no node held.
func moveReceiver(t *testing.T, r *rand.Rand, o *oracleRun) {
	t.Helper()

	nodes := o.s.ListNodes()
	n := nodes.At(r.IntN(nodes.Len())).AsStruct()

	n.Hostinfo = n.Hostinfo.Clone()
	if n.Hostinfo == nil {
		n.Hostinfo = &tailcfg.Hostinfo{}
	}

	switch r.IntN(3) {
	case 0:
		if n.Hostinfo.App == "" {
			n.Hostinfo.App, n.Hostinfo.GoVersion = "tailscale-rs", ""
		} else {
			n.Hostinfo.App, n.Hostinfo.GoVersion = "", runtime.Version()
		}
	case 1:
		n.Hostinfo.AppConnector.Set(!n.Hostinfo.AppConnector.EqualBool(true))
	default:
		o.addrs++
		n.IPv4 = new(netip.MustParseAddr(fmt.Sprintf("100.64.%d.%d", 4+o.addrs/250, o.addrs%250)))
	}

	o.s.PutNodeInStoreForTest(*n)
}

// capabilityForm reports whether a receiver with facts f is sent
// capability sources: written here from the receiver rule, not read from
// the code it checks.
func capabilityForm(f policyv2.ReceiverFacts) bool {
	return f.Client && !f.Announces && !f.AppConnector && !f.ServiceHost
}

// capWork reads the served filters' work counters: filters cut, selector
// resolutions built and the members they listed.
func capWork() [3]uint64 {
	res, members := policyv2.ServedWorkForTest()

	return [3]uint64{state.FilterCuts(), res, members}
}

// hasOneWayView reports whether a node of snap sees one that does not see
// it.
func hasOneWayView(snap *state.Snapshot) bool {
	for _, n := range snap.ListNodes().All() {
		for _, p := range snap.PeerView(n.ID()) {
			if _, ok := slices.BinarySearch(snap.PeerView(p), n.ID()); p != n.ID() && !ok {
				return true
			}
		}
	}

	return false
}

// hasServiceHost reports whether, in capability mode, a node of snap is
// sent addresses for being a service host alone.
func hasServiceHost(snap *state.Snapshot) bool {
	if !snap.CapabilitySources() {
		return false
	}

	for _, n := range snap.ListNodes().All() {
		if snap.ReceiverFacts(n.ID()) == (policyv2.ReceiverFacts{Client: true, ServiceHost: true}) {
			return true
		}
	}

	return false
}

// countFallbacks adds, in capability mode, the fallbacks in force in snap
// to reached, by label, and the step to "mode".
func countFallbacks(t *testing.T, snap *state.Snapshot, reached map[string]int) {
	t.Helper()

	if !snap.CapabilitySources() {
		return
	}

	census, err := snap.FallbackCensus()
	require.NoError(t, err)

	receivers, rules := census.Labelled()
	for label, n := range receivers {
		if n > 0 {
			reached[label]++
		}
	}

	for label, n := range rules {
		if n > 0 && receivers[label] == 0 {
			reached[label]++
		}
	}

	reached["mode"]++
}

// renderBetween renders some of the sessions pending a wake at mid, as
// sessions woken earlier render while commits land, and returns them.
func renderBetween(r *rand.Rand, mid *state.Snapshot, sessions map[types.NodeID]*oracleSession, pending map[types.NodeID]bool,
	render func(types.NodeID, *state.Snapshot),
) []types.NodeID {
	var out []types.NodeID

	for _, id := range slices.Sorted(maps.Keys(pending)) {
		if _, live := mid.GetNode(id); live && pending[id] && !sessions[id].down && r.IntN(2) == 0 {
			render(id, mid)
			out = append(out, id)
		}
	}

	return out
}

// heldStale counts the sessions of ids pending a wake that hold a map other
// than a fresh render of snap: what they would be left with unwoken.
func heldStale(t *testing.T, cfg *types.Config, snap *state.Snapshot, ids []types.NodeID,
	sessions map[types.NodeID]*oracleSession, pending map[types.NodeID]bool,
) int {
	t.Helper()

	fresh := snap.Uncached()
	n := 0

	for _, id := range ids {
		if sess, ok := sessions[id]; ok && pending[id] && !sess.down {
			out, err := freshDiff(cfg, fresh, id, sess.capVer, sess.st.sent, &versionCache{})
			require.NoError(t, err)

			if len(out) > 0 {
				n++
			}
		}
	}

	return n
}

// nodeInsideRoute reports whether a node's address is inside another
// node's approved subnet route in snap.
func nodeInsideRoute(snap *state.Snapshot) bool {
	nodes := snap.ListNodes()

	for _, router := range nodes.All() {
		for _, p := range router.SubnetRoutes() {
			for _, n := range nodes.All() {
				if n.ID() != router.ID() && slices.ContainsFunc(n.IPs(), p.Contains) {
					return true
				}
			}
		}
	}

	return false
}

// retarget returns pol with one rule's source or destination moved to
// another selector pol names, or, given a group, its members moved, and
// what moved; false when pol has no rule.
func retarget(r *rand.Rand, pol string) (string, string, bool) {
	var doc map[string]any
	if json.Unmarshal([]byte(pol), &doc) != nil {
		return "", "", false
	}

	acls, _ := doc["acls"].([]any)
	grants, _ := doc["grants"].([]any)
	rules := slices.Concat(acls, grants)

	if groups, ok := doc["groups"].(map[string]any); ok && r.IntN(3) == 0 {
		groups["group:g"] = [][]any{{}, {"u1@"}, {"u2@"}, {"u1@", "u2@"}}[r.IntN(4)]

		out, err := json.Marshal(doc)

		return string(out), "group", err == nil
	}

	if len(rules) == 0 {
		return "", "", false
	}

	// An ACL destination carries its ports after the last colon.
	base := func(d string, acl bool) string {
		if i := strings.LastIndexByte(d, ':'); acl && i >= 0 {
			return d[:i]
		}

		return d
	}

	var named []string

	for _, v := range rules {
		rule, _ := v.(map[string]any)
		_, acl := rule["action"]

		for _, key := range []string{"src", "dst"} {
			vs, _ := rule[key].([]any)
			for _, sel := range vs {
				name, _ := sel.(string)
				if b := base(name, acl && key == "dst"); b != "autogroup:self" {
					named = append(named, b)
				}
			}
		}
	}

	rule, _ := rules[r.IntN(len(rules))].(map[string]any)
	_, acl := rule["action"]
	key := []string{"src", "dst"}[r.IntN(2)]

	vs, _ := rule[key].([]any)
	if len(vs) == 0 || len(named) == 0 {
		return "", "", false
	}

	i := r.IntN(len(vs))
	old, _ := vs[i].(string)
	to := named[r.IntN(len(named))]

	if key == "dst" && acl {
		to += old[len(base(old, true)):]
	}

	vs[i] = to

	out, err := json.Marshal(doc)

	return string(out), key, err == nil
}

// retune edits one rule of pol in place, a port, a protocol or an app
// capability's value, so a rule changes while its sources and destinations
// stay: what a chunk named without that field would miss.
func retune(r *rand.Rand, pol string) (string, bool) {
	var doc map[string]any
	if json.Unmarshal([]byte(pol), &doc) != nil {
		return "", false
	}

	var sites []func()

	grants, _ := doc["grants"].([]any)
	for _, g := range grants {
		rule, _ := g.(map[string]any)

		ips, _ := rule["ip"].([]any)
		for i, e := range ips {
			proto, port, ok := strings.Cut(fmt.Sprint(e), ":")
			if !ok {
				continue
			}

			sites = append(sites, func() {
				n, err := strconv.Atoi(port)
				if err != nil || r.IntN(2) == 0 {
					to := "tcp"
					if proto == "tcp" {
						to = "udp"
					}

					ips[i] = to + ":" + port

					return
				}

				ips[i] = proto + ":" + strconv.Itoa(n%60000+1)
			})
		}

		// One value of a capability's list, the others kept: a name that
		// read only some of them would miss it.
		app, _ := rule["app"].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(app)) {
			values, _ := app[k].([]any)
			for i := range values {
				sites = append(sites, func() { values[i] = map[string]any{"v": r.IntN(4)} })
			}
		}
	}

	acls, _ := doc["acls"].([]any)
	for _, a := range acls {
		rule, _ := a.(map[string]any)

		dsts, _ := rule["dst"].([]any)
		for i, d := range dsts {
			ds := fmt.Sprint(d)

			j := strings.LastIndexByte(ds, ':')
			if j < 0 {
				continue
			}

			n, err := strconv.Atoi(ds[j+1:])
			if err != nil {
				continue
			}

			sites = append(sites, func() { dsts[i] = ds[:j+1] + strconv.Itoa(n%60000+1) })
		}
	}

	if len(sites) == 0 {
		return "", false
	}

	sites[r.IntN(len(sites))]()

	out, err := json.Marshal(doc)

	return string(out), err == nil
}

// requireNoStaleSession checks every session not waiting on a wake holds
// what a fresh render of snap gives.
func requireNoStaleSession(t *testing.T, step int, cfg *types.Config, snap *state.Snapshot, sessions map[types.NodeID]*oracleSession, pending map[types.NodeID]bool) {
	t.Helper()

	fresh := snap.Uncached()
	caches := map[tailcfg.CapabilityVersion]*versionCache{}

	for _, id := range slices.Sorted(maps.Keys(sessions)) {
		sess := sessions[id]
		if pending[id] || sess.down {
			continue
		}

		pcv := peerCapVer(sess.capVer)
		if caches[pcv] == nil {
			caches[pcv] = &versionCache{}
		}

		out, err := freshDiff(cfg, fresh, id, sess.capVer, sess.st.sent, caches[pcv])
		require.NoError(t, err)

		if len(out) > 0 {
			t.Fatalf("step %d: session %d, waiting on no wake, holds a stale map: %s", step, id, describeResponses(out))
		}
	}
}

// oracleMode says what the random writes check besides each session
// against a fresh one.
type oracleMode int

const (
	// oracleAudited requires every snapshot audited.
	oracleAudited oracleMode = iota
	// oracleCompile holds every session to the compile.
	oracleCompile
)

func runStreamsConverge(t *testing.T, mode oracleMode) oracleReach {
	t.Helper()

	var reach oracleReach

	for seed := range uint64(6) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			got := testStreamsConverge(t, rand.New(rand.NewPCG(seed, 6)), mode) //nolint:gosec // deterministic test input
			reach.via += got.via
			reach.exit += got.exit
			reach.autoApproved += got.autoApproved
			reach.keysRotated += got.keysRotated
			reach.minCapVer += got.minCapVer
			reach.addressMoved += got.addressMoved
			reach.inside += got.inside
			reach.retuned += got.retuned
		})
	}

	return reach
}

// require fails unless every shape was reached: a shape the seeds never
// reach tests nothing.
func (reach oracleReach) require(t *testing.T) {
	t.Helper()

	require.NotZero(t, reach.via, "a via route served at some step")
	require.NotZero(t, reach.exit, "an exit route served to a client at some step")
	require.NotZero(t, reach.autoApproved, "a route auto-approved at some step")
	require.NotZero(t, reach.keysRotated, "a node's keys rotated at some step")
	require.NotZero(t, reach.minCapVer, "a session at the oldest supported capability version")
	require.NotZero(t, reach.addressMoved, "a node's address changed at some step")
	require.NotZero(t, reach.inside, "a node inside another node's route at some step")
}

// oracleReach counts how often the oracle reached the shapes its writes
// and policies are there for.
type oracleReach struct {
	via, exit, autoApproved, keysRotated, minCapVer, addressMoved int
	// inside counts steps with a node inside another node's route;
	// retargeted and regrouped the document edits that moved a rule's
	// source or destination to another selector, or a group's members;
	// retuned those that moved a port, a protocol or an app value alone.
	inside, retargeted, regrouped, retuned int
	// between counts sessions that rendered a snapshot between two
	// coalesced commits; betweenStale those of them the routing over
	// both had to wake again.
	between, betweenStale int
	// transient counts nodes that joined and left between two routings.
	transient int
	// serviceHost counts steps with a node sent addresses in capability
	// mode for being a service host alone.
	serviceHost int
	// oneWay counts steps where a node sees one that does not see it.
	oneWay int
}

// oraclePolicies are the documents the random writes switch between.
var oraclePolicies = []string{
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
	// A group, and rules over tailnet addresses some routes cover.
	`{"groups":{"group:g":["u1@"]},"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
	  "acls":[{"action":"accept","src":["group:g"],"dst":["tag:a:*","100.64.0.0/29:*"]},
	          {"action":"accept","src":["u2@","tag:b"],"dst":["group:g:*","tag:b:22"]}]}`,
	`{"hosts":{"lan":"10.0.0.0/24","h1":"100.64.0.1/32"},
	  "acls":[{"action":"accept","src":["u2@"],"dst":["lan:*","h1:22"]},
	          {"action":"accept","src":["u1@"],"dst":["u1@:*"]}]}`,
	// An exit node sees the sources of a capability grant whose destination
	// reaches the internet, which do not see it: a write of a source must
	// reach the exit node.
	`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
	  "autoApprovers":{"exitNode":["u1@","tag:a","tag:b"]},
	  "grants":[{"src":["u2@"],"dst":["8.8.8.0/24"],"app":{"example.com/cap/x":[{}]}},
	            {"src":["u1@"],"dst":["u1@"],"ip":["*"]}]}`,
	// Rules alike but for a port, a protocol or an app capability's value,
	// one capability with two values: each must reach the client apart, and
	// an edit of that field alone must too.
	`{"grants":[{"src":["u1@"],"dst":["u2@"],"ip":["tcp:22"]},
	            {"src":["u1@"],"dst":["u2@"],"ip":["udp:22"]},
	            {"src":["u1@"],"dst":["u2@"],"ip":["tcp:2222"]},
	            {"src":["u1@"],"dst":["u2@"],"app":{"example.com/cap/x":[{"v":1},{"v":3}]}},
	            {"src":["u1@"],"dst":["u2@"],"app":{"example.com/cap/x":[{"v":2}]}},
	            {"src":["u2@"],"dst":["u1@"],"ip":["tcp:80","udp:80"]}]}`,
	// Service hosts add their service IPs to their local nets: in
	// capability mode they are sent addresses, which follow u1's members.
	`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u1@"]},
	  "nodeAttrs":[{"target":["u2@","tag:b"],"attr":["service-host"]}],
	  "acls":[{"action":"accept","src":["u1@"],"dst":["u2@:*","tag:b:*"]},
	          {"action":"accept","src":["*"],"dst":["u1@:*"]}]}`,
}

// newOracleRun builds the random writes' tailnet: a node of u1 and u2 in
// turn beyond the fixture's, a tag:a router of the route, and a session
// per node.
func newOracleRun(t *testing.T, r *rand.Rand, reach *oracleReach) (*oracleRun, *types.Config, *Hub, map[types.NodeID]*oracleSession) {
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

	exitRoutes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

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

	o := &oracleRun{
		t: t, r: r, s: s, gens: map[types.NodeID]uint64{}, policies: oraclePolicies,
		route: route, exitRoutes: exitRoutes, router: router,
		u1: u1, u2: u2, open: open, addNode: addNode, reach: reach,
	}

	return o, cfg, hub, sessions
}

// testStreamsConverge runs one seed and returns what it reached, so the
// caller can tell every shape was exercised.
func testStreamsConverge(t *testing.T, r *rand.Rand, mode oracleMode) oracleReach {
	t.Helper()

	var reach oracleReach

	o, cfg, hub, sessions := newOracleRun(t, r, &reach)
	s := o.s

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

	handed := handedOut{}
	defer handed.requireUnchanged(t)

	// Clients reporting themselves otherwise, on a stream of their own:
	// each session's client must end holding what a fresh one is sent
	// across every change of its delivery.
	flips := rand.New(rand.NewPCG(11, 13)) //nolint:gosec // deterministic test input

	for step := range 400 {
		nodes := s.ListNodes()
		nv := nodes.At(r.IntN(nodes.Len()))
		id := nv.ID()

		o.write(step, nodes, nv, id)

		if flips.IntN(4) == 0 {
			moveClient(flips, o)
		}

		snap := s.Snapshot()

		if mode == oracleAudited {
			// The snapshot every session renders was audited at the commit
			// that last changed its membership.
			require.True(t, snap.MembershipAudited(), "step %d: the last change to membership was audited", step)
			require.True(t, snap.FilterAudited(), "step %d: every filter was expanded from templates and checked at the last change", step)
			require.True(t, snap.SidesAudited(), "step %d: peers, routes and via from roles were checked at the last change", step)
			require.True(t, snap.ViaElectionAudited() || snap.PolicyErr() != nil, "step %d: the via elections were checked against the plan", step)
		}

		advanceOracleSessions(t, r, cfg, hub, snap, wake(snap), sessions)
		requireOracleConverged(t, step, cfg, snap, sessions)

		for _, sess := range sessions {
			if !sess.down {
				handed.see(t, step, sess.st.sent.filter)
			}
		}

		if mode == oracleCompile {
			requireSessionsMatchCompile(t, step, snap, sessions)
		}

		if servesVia(snap) {
			reach.via++
		}

		if servesExit(sessions) {
			reach.exit++
		}

		if nodeInsideRoute(snap) {
			reach.inside++
		}
	}

	return reach
}

// moveClient makes a node's client report itself as Tailscale's current
// client, tailscale-rs, or a release before the oldest headscale serves:
// what decides how its filter is delivered, and in capability mode its
// form.
func moveClient(r *rand.Rand, o *oracleRun) {
	nodes := o.s.ListNodes()
	n := nodes.At(r.IntN(nodes.Len())).AsStruct()

	n.Hostinfo = n.Hostinfo.Clone()
	if n.Hostinfo == nil {
		n.Hostinfo = &tailcfg.Hostinfo{}
	}

	switch r.IntN(3) {
	case 0:
		n.Hostinfo.App, n.Hostinfo.GoVersion, n.Hostinfo.IPNVersion = "", runtime.Version(), version.Long()
	case 1:
		n.Hostinfo.App = "tailscale-rs"
	default:
		n.Hostinfo.IPNVersion = "1.0.0"
	}

	o.s.PutNodeInStoreForTest(*n)
}

// handedOut is every filter slice the served path handed a session, as
// it was encoded then. A session takes a slice handed out again for the
// same rules (the diff's identity check, [policyv2.FilterChunks.Recut]), so
// a producer that changed a filter in place after handing it out, or wrote
// another into its array, would leave a client holding stale chunks for
// the rest of its session.
type handedOut map[handedKey][]byte

type handedKey struct {
	first *tailcfg.FilterRule
	n     int
}

// see records rules, failing when the slice was handed out before holding
// other rules.
func (h handedOut) see(t *testing.T, step int, rules []tailcfg.FilterRule) {
	t.Helper()

	if len(rules) == 0 {
		return
	}

	enc, err := json.Marshal(rules)
	require.NoError(t, err)

	k := handedKey{&rules[0], len(rules)}
	if was, ok := h[k]; ok && !bytes.Equal(was, enc) {
		t.Fatalf("step %d: a filter handed out holds other rules now:\nthen %s\nnow  %s", step, was, enc)
	}

	h[k] = enc
}

// requireUnchanged fails when a filter handed out was changed since.
func (h handedOut) requireUnchanged(t *testing.T) {
	t.Helper()

	for k, was := range h {
		now, err := json.Marshal(unsafe.Slice(k.first, k.n))
		require.NoError(t, err)
		require.Equal(t, string(was), string(now), "a filter handed out was changed in place")
	}
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
	// addrs counts the addresses address changes handed out.
	addrs int
}

// oracleWrites is how many kinds of write [oracleRun.writeOp] makes.
const oracleWrites = 21

// write applies one random write to nv, at step, of the kinds a real
// server sees.
func (o *oracleRun) write(step int, nodes views.Slice[types.NodeView], nv types.NodeView, id types.NodeID) {
	o.writeOp(o.r.IntN(oracleWrites), step, nodes, nv, id)
}

// writeOp applies write kind op to nv, at step.
//
//nolint:gocyclo // one case per kind of write
func (o *oracleRun) writeOp(op, step int, nodes views.Slice[types.NodeView], nv types.NodeView, id types.NodeID) {
	t, r, s, gens, policies := o.t, o.r, o.s, o.gens, o.policies
	route, exitRoutes, router, u1, u2 := o.route, o.exitRoutes, o.router, o.u1, o.u2
	open, addNode := o.open, o.addNode

	switch op {
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

		// The subnet, the exit routes, or a route over tailnet addresses:
		// other nodes are then inside it.
		routes := [][]netip.Prefix{
			{route},
			{route},
			exitRoutes,
			{netip.MustParsePrefix("100.64.0.0/29")},
			{netip.MustParsePrefix("100.64.0.8/29")},
			{route, netip.MustParsePrefix("fd7a:115c:a1e0::/125")},
		}[r.IntN(6)]

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
	case 19:
		// An address change, a policy fact no other write moves: one
		// family, the other or both, to addresses no node held before.
		o.addrs++
		n := nv.AsStruct()
		v4 := netip.MustParseAddr(fmt.Sprintf("100.64.%d.%d", 4+o.addrs/250, o.addrs%250))
		v6 := netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0:4::%x", o.addrs))

		switch r.IntN(3) {
		case 0:
			n.IPv4 = &v4
		case 1:
			n.IPv6 = &v6
		default:
			n.IPv4, n.IPv6 = &v4, &v6
		}

		s.PutNodeInStoreForTest(*n)

		o.reach.addressMoved++
	case 20:
		// A document edit moving a rule's source or destination to another
		// selector the document names, or a group's members; now and then
		// one moving a rule's port, protocol or app value alone.
		if r.IntN(3) == 0 {
			if pol, ok := retune(r, string(s.Snapshot().PolicySource())); ok {
				if _, err := s.SetPolicy([]byte(pol)); err == nil { //nolint:noinlineerr
					o.reach.retuned++
				}

				return
			}
		}

		pol, kind, ok := retarget(r, string(s.Snapshot().PolicySource()))
		if !ok {
			return
		}

		_, err := s.SetPolicy([]byte(pol))
		if err == nil && kind == "group" {
			o.reach.regrouped++
		} else if err == nil {
			o.reach.retargeted++
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

// requireSessionsMatchCompile holds every live session's peers, packet
// filter and peers' routes to the compile's answers for snap: its pair scan
// for peers, its filter for the node, and its route composition (its
// matchers and its own via scopes) for each peer's routes.
func requireSessionsMatchCompile(t *testing.T, step int, snap *state.Snapshot, sessions map[types.NodeID]*oracleSession) {
	t.Helper()

	pm, ok := snap.Policy().(*policyv2.PolicyManager)
	require.True(t, ok)

	peerMap := pm.BuildPeerMap(snap.ListNodes())

	for _, id := range slices.Sorted(maps.Keys(sessions)) {
		sess := sessions[id]
		if sess.down {
			continue
		}

		self, ok := snap.GetNode(id)
		require.True(t, ok)

		want := slices.Clone(peerMap[id])
		slices.Sort(want)

		want = slices.DeleteFunc(want, func(p types.NodeID) bool { return p == id })

		got := make([]types.NodeID, 0, len(sess.client.peers))
		for pid := range sess.client.peers {
			got = append(got, types.NodeID(pid)) //nolint:gosec // node IDs fit
		}

		slices.Sort(got)

		if !slices.Equal(want, got) {
			t.Fatalf("step %d: session %d holds peers %v, the compile's pair scan %v", step, id, got, want)
		}

		filter, err := pm.FilterForNode(self)
		require.NoError(t, err)

		switch {
		case len(filter) == 0 && len(sess.client.filter) == 0:
		case !snap.CapabilitySources() && !sess.st.sent.chunked:
			// The whole filter under "base", as the compile writes it.
			if !reflect.DeepEqual(filter, sess.client.filter) {
				t.Fatalf("step %d: session %d holds filter %v, the compile's %v", step, id, sess.client.filter, filter)
			}
		default:
			// What the client enforces, from what it assembled (chunks in
			// key order, or capability sources looked up in its netmap),
			// must answer as the compile's filter does; nothing of the
			// chunking or of capability form is on the oracle's side.
			if d := heldDivergence(sess.client.filter, filter, clientLookup(sess.client), localNets(self), snap.ListNodes()); d != "" {
				t.Fatalf("step %d: session %d enforces otherwise than the compile: %s\nheld    %v\ncompile %v", step, id, d, sess.client.filter, filter)
			}

			if snap.CapabilitySources() {
				// And the filter served says what the compile says once each
				// capability is the addresses of the nodes this client holds
				// with it, as rule multisets.
				served, err := snap.FilterForNode(id)
				require.NoError(t, err)

				err = policyv2.AgreesWithAddressForm(served, filter, sess.client.capHolders)
				if err != nil {
					t.Fatalf("step %d: session %d: %v", step, id, err)
				}
			}
		}

		for pid, tn := range sess.client.peers {
			peer, ok := snap.GetNode(types.NodeID(pid)) //nolint:gosec // node IDs fit
			require.True(t, ok)

			routes, err := snap.CompiledRoutesForPeer(self, peer)
			require.NoError(t, err)

			if got, want := heldRoutes(tn), slices.SortedFunc(slices.Values(routes), netip.Prefix.Compare); !slices.Equal(got, want) {
				t.Fatalf("step %d: session %d holds routes %v of peer %d, the compile's %v", step, id, got, pid, want)
			}
		}
	}
}

// heldRoutes returns the routes a peer's AllowedIPs hold beyond its
// addresses, sorted.
func heldRoutes(tn *tailcfg.Node) []netip.Prefix {
	routes := slices.DeleteFunc(slices.Clone(tn.AllowedIPs), func(p netip.Prefix) bool { return slices.Contains(tn.Addresses, p) })
	slices.SortFunc(routes, netip.Prefix.Compare)

	return routes
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

// compiledPolicy returns snap's policy compile, whose address compile the
// tests hold what is served to.
func compiledPolicy(tb testing.TB, snap *state.Snapshot) *policyv2.PolicyManager {
	tb.Helper()

	pm, ok := snap.Policy().(*policyv2.PolicyManager)
	require.True(tb, ok, "test sanity: a v2 policy")

	return pm
}

// servesVia reports whether any node gets a route through a via grant.
func servesVia(snap *state.Snapshot) bool {
	pm, ok := snap.Policy().(*policyv2.PolicyManager)
	if !ok {
		return false
	}

	nodes := snap.ListNodes()
	for _, viewer := range nodes.All() {
		for _, peer := range nodes.All() {
			if len(pm.ViaRoutesForPeer(viewer, peer).Include) > 0 {
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
// render resolves via routes. The churn shapes (mesh, group-all, routers,
// selectors) are described with their policies in churn_test.go.
var scalingPolicies = map[string]string{
	"mesh":      meshPolicy,
	"group-all": groupAllPolicy(false),
	"routers":   routersPolicy(false),
	"selectors": selectorsPolicy(false),
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

	subnet := netip.MustParsePrefix("10.0.0.0/24")
	require.Contains(tb, snap.RoutesForPeer(viewer, mustNode(tb, s, router.ID())), subnet)
	require.NotContains(tb, snap.RoutesForPeer(viewer, mustNode(tb, s, standby.ID())), subnet)

	// And it is the via grant that serves it, not HA primaries under a
	// plain grant.
	via := compiledPolicy(tb, snap).ViaRoutesForPeer(viewer, mustNode(tb, s, router.ID()))
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

	// One fsync'd transaction per fixture node made setup, not the writes,
	// the cost of a run on disk. Only this setup connection skips them: the
	// state below reopens the file with its own settings.
	require.NoError(tb, database.DB.Exec("PRAGMA synchronous = OFF").Error)

	users := database.CreateUsersForTest(10, "u")

	nodes := make([]*types.Node, 0, n)
	for i, u := range users {
		nodes = append(nodes, database.CreateRegisteredNodesForTest(u, n/10+min(1, max(0, n%10-i)), u.Name)...)
	}

	shapeFixture(tb, database, shape, nodes)

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

	_, err = s.SetPolicy([]byte(shapePolicy(shape)))
	require.NoError(tb, err)

	if shape == "via" {
		scalingRouters(tb, s)
	}

	if shape == "routers" || shape == "rules" {
		subnetRouters(tb, s, shape)
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
// encodes its response and confirms delivery; encoded-bytes/op is what they
// send, compressed. BenchmarkSTUNEndpointReports separately measures public
// MapRequests, including SQL persistence. The churn kinds (join, leave, tag,
// group) go through the production entry points instead; see churnWrites.
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

	kinds := slices.Concat(slices.Collect(maps.Keys(scalingWrites)), slices.Collect(maps.Keys(churnWrites)))
	slices.Sort(kinds)

	for _, kind := range kinds {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			churn, isChurn := churnWrites[kind]
			if isChurn && !churn.applies(churnShapes[shape]) {
				continue
			}

			for _, n := range sizes {
				b.Run(fmt.Sprintf("%s/%s/nodes=%d", kind, shape, n), func(b *testing.B) {
					if isChurn {
						benchChurn(b, kind, shape, n)

						return
					}

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
					b.ReportMetric(float64(sc.encoded)/float64(i), "encoded-bytes/op")
				})
			}
		}
	}
}

// BenchmarkViaOnlineWrites keeps writer selection fixed across sizes. A failover
// disconnects and reconnects the elected router before delivery: the standby
// wins and keeps its election when the former winner returns. Every operation
// transfers the route, rather than amortizing one failover over ordinary writes.
func BenchmarkViaOnlineWrites(b *testing.B) {
	sizes := []int{100, 400, 1000}

	if value, ok := os.LookupEnv("HEADSCALE_SCALE_NODES"); ok {
		n, err := strconv.Atoi(value)
		require.NoError(b, err)

		sizes = []int{n}
	}

	for _, kind := range []string{"router-failover", "member-online", "unrelated-user"} {
		for _, n := range sizes {
			b.Run(fmt.Sprintf("%s/nodes=%d", kind, n), func(b *testing.B) {
				shape := "via"
				if kind == "unrelated-user" {
					shape = "users"
				}

				s, streams := scalingTailnet(b, n, shape)
				sc := newScalingRun(s, streams)
				write := func(tb testing.TB, s *state.State, _ types.NodeID, i int) {
					tb.Helper()

					id := streams[1].nodeID
					if kind == "router-failover" {
						id = streams[(i%2)*10].nodeID
					}

					scalingWrites["online"](tb, s, id, i)

					if kind == "router-failover" {
						scalingWrites["online"](tb, s, id, i)
					}
				}

				b.ReportAllocs()

				i := 0
				for b.Loop() {
					sc.step(b, write, i)
					i++
				}

				sc.requireSettled(b, "online")

				if kind == "router-failover" {
					snap := s.Snapshot()
					viewer := mustNode(b, s, streams[1].nodeID)
					winner := mustNode(b, s, streams[(i%2)*10].nodeID)
					require.Contains(b, snap.RoutesForPeer(viewer, winner), netip.MustParsePrefix("10.0.0.0/24"))
					require.Positive(b, sc.updates, "each failover must send route changes")
				}

				b.ReportMetric(float64(sc.woken)/float64(i), "woken/op")
				b.ReportMetric(float64(sc.updates)/float64(i), "updates/op")
				b.ReportMetric(float64(sc.rendered)/float64(i), "peer-renders/op")
			})
		}
	}
}

// BenchmarkViaMixedOnlineWrites isolates election moves under per-user peer
// views. The sparse case steers only u0, leaving other users' classes unrelated.
func BenchmarkViaMixedOnlineWrites(b *testing.B) {
	for _, shape := range []string{"self", "users", "sparse"} {
		for _, n := range []int{100, 400, 1000} {
			b.Run(fmt.Sprintf("%s/nodes=%d", shape, n), func(b *testing.B) {
				s, streams := scalingTailnet(b, n, "via")

				plain := `{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}`
				if shape == "users" {
					plain = `{"src":["u0@"],"dst":["u0@"],"ip":["*"]}`
				}

				source := "autogroup:member"
				if shape == "sparse" {
					source = "u0@"
				}

				_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:r":["u0@"]},"grants":[` + plain + `,
					{"src":["` + source + `"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:r"]}]}`))
				require.NoError(b, err)

				for _, st := range streams {
					_, err := st.Update(s.Snapshot())
					require.NoError(b, err)
					st.Delivered()
				}

				sc := newScalingRun(s, streams)
				write := func(tb testing.TB, s *state.State, _ types.NodeID, i int) {
					tb.Helper()

					id := streams[(i%2)*10].nodeID
					scalingWrites["online"](tb, s, id, i)
					scalingWrites["online"](tb, s, id, i)
				}

				b.ReportAllocs()

				i := 0
				for b.Loop() {
					sc.step(b, write, i)
					i++
				}

				sc.requireSettled(b, "online")

				snap := s.Snapshot()
				viewer := mustNode(b, s, streams[1].nodeID)
				winner := mustNode(b, s, streams[(i%2)*10].nodeID)
				require.Contains(b, snap.RoutesForPeer(viewer, winner), netip.MustParsePrefix("10.0.0.0/24"))
				require.Positive(b, sc.updates)
				b.ReportMetric(float64(sc.woken)/float64(i), "woken/op")
				b.ReportMetric(float64(sc.updates)/float64(i), "updates/op")
				b.ReportMetric(float64(sc.rendered)/float64(i), "peer-renders/op")
			})
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
	scalingWork

	s       *state.State
	streams []*Stream
	byNode  map[types.NodeID]*Stream
	last    *state.Snapshot

	// encode encodes each response sent; see sizedEncoder for the one
	// that also measures them.
	encode func(*tailcfg.MapResponse, bool) ([]byte, error)
	sized  *sizedEncoder

	// subjects are the nodes the write being delivered changed: what is
	// sent to them is the write's own, not fan-out.
	subjects map[types.NodeID]struct{}

	// watch makes a delivery do what hub's watcher does for each commit
	// besides waking sessions: advance its caches, and forget deleted
	// nodes, whose sessions it ends.
	watch bool
	hub   *Hub

	// observe, when set, sees what each woken session was sent.
	observe func(snap *state.Snapshot, id types.NodeID, out []*tailcfg.MapResponse)
}

// scalingWork is the work deliveries counted.
type scalingWork struct {
	woken, updates, rendered int

	// quiet counts writes that woke no session.
	quiet int

	// encoded counts the bytes sent, compressed, and commits the commits
	// delivered.
	encoded, commits int

	// With a sizedEncoder, the JSON bytes sent split into packet filters
	// sent to sessions other than the subjects', and how many of those
	// sessions were sent one; packet filters sent to the subjects; and
	// everything else. chunksSent and chunksDeleted count the filter
	// chunks every session was sent and told to delete.
	filterBytes, filterSends, selfFilterBytes, restBytes int
	chunksSent, chunksDeleted                            int
}

func newScalingRun(s *state.State, streams []*Stream) *scalingRun {
	sc := &scalingRun{
		s: s, streams: streams, byNode: make(map[types.NodeID]*Stream, len(streams)), last: s.Snapshot(),
		encode: benchEncode,
	}
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

// step makes write i on the i-th session's node and delivers it.
func (sc *scalingRun) step(tb testing.TB, write func(testing.TB, *state.State, types.NodeID, int), i int) {
	tb.Helper()

	write(tb, sc.s, sc.streams[i%len(sc.streams)].nodeID, i)
	sc.deliver(tb)
}

// deliver routes the commits since the last delivery as the hub does,
// and updates, encodes for and confirms delivery to the sessions they wake.
func (sc *scalingRun) deliver(tb testing.TB) {
	tb.Helper()

	snap := sc.s.Snapshot()
	change := snap.Since(sc.last)
	all, wake := Route(sc.last, snap, change)
	sc.commits += int(snap.Rev() - sc.last.Rev()) //nolint:gosec // revisions only grow
	sc.last = snap

	if sc.watch {
		sc.watched(snap, change)
	}

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

		if sc.observe != nil {
			sc.observe(snap, st.nodeID, out)
		}

		for _, resp := range out {
			data, err := st.hub.Encode(resp, true, sc.encode)
			if err != nil {
				tb.Fatal(err)
			}

			sc.encoded += len(data)

			if sc.sized != nil && !sc.account(st.nodeID, resp) {
				tb.Fatal("a response was sent that the sized encoder did not encode")
			}
		}

		st.Delivered()

		sc.rendered += st.r.rendered - before
	}

	if sc.sized != nil {
		clear(sc.sized.sizes)
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
		require.Empty(tb, st.hub.core.sentPeers[st.nodeID].attempts, "successful writes leave no failed-write history")
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
	// Pinned to address form: the counts are address mode's work; capability mode re-renders the peers whose stamps a write moves, and sends fewer filters (BenchmarkScalingWrites reports both).
	t.Setenv(state.TestCapabilitySourcesEnv, "false")

	const n, writes = 100, 4

	// Sessions woken, sessions sent an update and peers rendered, over the
	// writes. A session sees its own class of ten nodes under the self and
	// users shapes, and the two tags its tag reaches under tags.
	//
	// Policy rows add the setup write that expands visibility, which every
	// session renders, to the writes that only alternate its port.
	//
	// Rejoin is two commits the hub routes as one, compared end to end:
	// the node, changed back, and its viewers are woken, as an endpoint
	// write wakes them, and have nothing to send. A node the log names
	// cannot be told unchanged without its intermediate renders; that it
	// wakes its viewers is above need.
	//
	// The via shape sees what allow-all does, plus routes that differ per
	// viewer: a routed peer's routes are read again for a viewer when what
	// every route reads moved, as at the policy rows' writes, when the
	// viewer's side set did, as the rejoined node's does, or when the
	// peer's routes' cover did, and it renders again only when they differ:
	// viewers given the same routes of a render share one. A via election
	// move renders only the routers the election steers to or from. The first online write also
	// changes the router's own PrimaryRoutes. Rejoin restores its original
	// SessionStart, so final wire state is unchanged.
	//
	// The routers shape's first subject is a router, whose only viewers
	// are group:eng's members.
	ceilings := map[string][3]int{
		"derp/allow-all":           {400, 400, 0},
		"derp/group-all":           {400, 400, 0},
		"derp/mesh":                {400, 400, 0},
		"derp/routers":             {400, 400, 0},
		"derp/selectors":           {400, 400, 0},
		"derp/self":                {400, 400, 0},
		"derp/tags":                {400, 400, 0},
		"derp/users":               {400, 400, 0},
		"derp/via":                 {400, 400, 0},
		"endpoint/allow-all":       {400, 400, 396},
		"endpoint/group-all":       {400, 400, 396},
		"endpoint/mesh":            {400, 400, 396},
		"endpoint/routers":         {341, 341, 337},
		"endpoint/selectors":       {323, 323, 319},
		"endpoint/self":            {40, 40, 36},
		"endpoint/tags":            {44, 44, 40},
		"endpoint/users":           {40, 40, 36},
		"endpoint/via":             {400, 400, 396},
		"endpoints-x16/allow-all":  {400, 400, 6336},
		"endpoints-x16/group-all":  {400, 400, 5776},
		"endpoints-x16/mesh":       {400, 400, 6336},
		"endpoints-x16/routers":    {400, 400, 5349},
		"endpoints-x16/selectors":  {400, 400, 5632},
		"endpoints-x16/self":       {100, 100, 576},
		"endpoints-x16/tags":       {360, 360, 640},
		"endpoints-x16/users":      {100, 100, 576},
		"endpoints-x16/via":        {400, 400, 6336},
		"ignored-health/allow-all": {0, 0, 0},
		"ignored-health/group-all": {0, 0, 0},
		"ignored-health/mesh":      {0, 0, 0},
		"ignored-health/routers":   {0, 0, 0},
		"ignored-health/selectors": {0, 0, 0},
		"ignored-health/self":      {0, 0, 0},
		"ignored-health/tags":      {0, 0, 0},
		"ignored-health/users":     {0, 0, 0},
		"ignored-health/via":       {0, 0, 0},
		"online/allow-all":         {400, 396, 396},
		"online/group-all":         {400, 396, 396},
		"online/mesh":              {400, 396, 396},
		"online/routers":           {341, 337, 337},
		"online/selectors":         {323, 319, 319},
		"online/self":              {40, 36, 36},
		"online/tags":              {44, 40, 40},
		"online/users":             {40, 36, 36},
		"online/via":               {400, 397, 495},
		"policy/allow-all":         {500, 500, 0},
		"policy/group-all":         {500, 500, 2000},
		"policy/mesh":              {500, 500, 0},
		"policy/routers":           {500, 500, 1980},
		"policy/selectors":         {500, 500, 1860},
		"policy/self":              {500, 500, 9000},
		"policy/tags":              {500, 500, 8900},
		"policy/users":             {500, 500, 9000},
		"policy/via":               {500, 500, 0},
		"rejoin/allow-all":         {400, 0, 396},
		"rejoin/group-all":         {400, 0, 396},
		"rejoin/mesh":              {400, 0, 396},
		"rejoin/routers":           {341, 0, 337},
		"rejoin/selectors":         {323, 0, 319},
		"rejoin/self":              {40, 0, 36},
		"rejoin/tags":              {44, 0, 40},
		"rejoin/users":             {40, 0, 36},
		"rejoin/via":               {400, 0, 396},
		"rename/allow-all":         {400, 400, 396},
		"rename/group-all":         {400, 400, 396},
		"rename/mesh":              {400, 400, 396},
		"rename/routers":           {341, 341, 337},
		"rename/selectors":         {323, 323, 319},
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

// TestScalingWriteWorkCapability is [TestScalingWriteWork] in capability
// mode, adding the served filters' work on the way: filters cut, selector
// resolutions built, the members those listed, and sorts of every node's
// addresses.
func TestScalingWriteWorkCapability(t *testing.T) {
	t.Setenv(state.TestCapabilitySourcesEnv, "true")
	// The audit cuts filters of its own, which the counts would include.
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	const n, writes = 100, 4

	// Sessions woken, updated and peers rendered are address mode's (see
	// TestScalingWriteWork) except where a write moves stamps: the policy
	// rows' setup write replaces the shape's policy with one naming no
	// identity, so every stamped node loses its stamps and every viewer is
	// sent it again. Filters cut: a port edit moves every node's filter;
	// nothing else cuts one. No write resolves a selector: capability form
	// reads none.
	ceilings := map[string][6]int{
		"derp/allow-all":           {400, 400, 0, 0, 0, 0},
		"derp/group-all":           {400, 400, 0, 0, 0, 0},
		"derp/mesh":                {400, 400, 0, 0, 0, 0},
		"derp/routers":             {400, 400, 0, 0, 0, 0},
		"derp/selectors":           {400, 400, 0, 0, 0, 0},
		"derp/self":                {400, 400, 0, 0, 0, 0},
		"derp/tags":                {400, 400, 0, 0, 0, 0},
		"derp/users":               {400, 400, 0, 0, 0, 0},
		"derp/via":                 {400, 400, 0, 0, 0, 0},
		"endpoint/allow-all":       {400, 400, 396, 0, 0, 0},
		"endpoint/group-all":       {400, 400, 396, 0, 0, 0},
		"endpoint/mesh":            {400, 400, 396, 0, 0, 0},
		"endpoint/routers":         {341, 341, 337, 0, 0, 0},
		"endpoint/selectors":       {323, 323, 319, 0, 0, 0},
		"endpoint/self":            {40, 40, 36, 0, 0, 0},
		"endpoint/tags":            {44, 44, 40, 0, 0, 0},
		"endpoint/users":           {40, 40, 36, 0, 0, 0},
		"endpoint/via":             {400, 400, 396, 0, 0, 0},
		"endpoints-x16/allow-all":  {400, 400, 6336, 0, 0, 0},
		"endpoints-x16/group-all":  {400, 400, 5776, 0, 0, 0},
		"endpoints-x16/mesh":       {400, 400, 6336, 0, 0, 0},
		"endpoints-x16/routers":    {400, 400, 5349, 0, 0, 0},
		"endpoints-x16/selectors":  {400, 400, 5632, 0, 0, 0},
		"endpoints-x16/self":       {100, 100, 576, 0, 0, 0},
		"endpoints-x16/tags":       {360, 360, 640, 0, 0, 0},
		"endpoints-x16/users":      {100, 100, 576, 0, 0, 0},
		"endpoints-x16/via":        {400, 400, 6336, 0, 0, 0},
		"ignored-health/allow-all": {0, 0, 0, 0, 0, 0},
		"ignored-health/group-all": {0, 0, 0, 0, 0, 0},
		"ignored-health/mesh":      {0, 0, 0, 0, 0, 0},
		"ignored-health/routers":   {0, 0, 0, 0, 0, 0},
		"ignored-health/selectors": {0, 0, 0, 0, 0, 0},
		"ignored-health/self":      {0, 0, 0, 0, 0, 0},
		"ignored-health/tags":      {0, 0, 0, 0, 0, 0},
		"ignored-health/users":     {0, 0, 0, 0, 0, 0},
		"ignored-health/via":       {0, 0, 0, 0, 0, 0},
		"online/allow-all":         {400, 396, 396, 0, 0, 0},
		"online/group-all":         {400, 396, 396, 0, 0, 0},
		"online/mesh":              {400, 396, 396, 0, 0, 0},
		"online/routers":           {341, 337, 337, 0, 0, 0},
		"online/selectors":         {323, 319, 319, 0, 0, 0},
		"online/self":              {40, 36, 36, 0, 0, 0},
		"online/tags":              {44, 40, 40, 0, 0, 0},
		"online/users":             {40, 36, 36, 0, 0, 0},
		"online/via":               {400, 397, 495, 0, 0, 0},
		"policy/allow-all":         {500, 500, 0, 400, 0, 0},
		"policy/group-all":         {500, 500, 6950, 400, 0, 0},
		"policy/mesh":              {500, 500, 9900, 400, 0, 0},
		"policy/routers":           {500, 500, 9100, 400, 0, 0},
		"policy/selectors":         {500, 500, 9348, 400, 0, 0},
		"policy/self":              {500, 500, 9900, 400, 0, 0},
		"policy/tags":              {500, 500, 9900, 400, 0, 0},
		"policy/users":             {500, 500, 9900, 400, 0, 0},
		"policy/via":               {500, 500, 0, 400, 0, 0},
		"rejoin/allow-all":         {400, 0, 396, 0, 0, 0},
		"rejoin/group-all":         {400, 0, 396, 0, 0, 0},
		"rejoin/mesh":              {400, 0, 396, 0, 0, 0},
		"rejoin/routers":           {341, 0, 337, 0, 0, 0},
		"rejoin/selectors":         {323, 0, 319, 0, 0, 0},
		"rejoin/self":              {40, 0, 36, 0, 0, 0},
		"rejoin/tags":              {44, 0, 40, 0, 0, 0},
		"rejoin/users":             {40, 0, 36, 0, 0, 0},
		"rejoin/via":               {400, 0, 396, 0, 0, 0},
		"rename/allow-all":         {400, 400, 396, 0, 0, 0},
		"rename/group-all":         {400, 400, 396, 0, 0, 0},
		"rename/mesh":              {400, 400, 396, 0, 0, 0},
		"rename/routers":           {341, 341, 337, 0, 0, 0},
		"rename/selectors":         {323, 323, 319, 0, 0, 0},
		"rename/self":              {40, 40, 36, 0, 0, 0},
		"rename/tags":              {44, 44, 40, 0, 0, 0},
		"rename/users":             {40, 40, 36, 0, 0, 0},
		"rename/via":               {400, 400, 396, 0, 0, 0},
	}

	for _, kind := range slices.Sorted(maps.Keys(scalingWrites)) {
		for _, shape := range slices.Sorted(maps.Keys(scalingPolicies)) {
			t.Run(kind+"/"+shape, func(t *testing.T) {
				s, streams := scalingTailnet(t, n, shape)
				sc := newScalingRun(s, streams)
				sc.warm(t, kind)

				var work [3]uint64

				for i := range writes {
					before := capWork()

					sc.step(t, scalingWrites[kind], i)

					for k, v := range capWork() {
						work[k] += v - before[k]
					}
				}

				sc.requireSettled(t, kind)

				got := [6]int{sc.woken, sc.updates, sc.rendered, int(work[0]), int(work[1]), int(work[2])} //nolint:gosec // small
				limit, ok := ceilings[kind+"/"+shape]
				require.True(t, ok, "no ceiling for %s/%s", kind, shape)
				assert.Equal(t, limit, got, "sessions woken, updated, peers rendered, filters cut, resolutions built, members listed")
			})
		}
	}
}

// BenchmarkHubSessionsCoalescedWrites measures what the hub does for two
// endpoint writes that land together, with every node's session a
// goroutine attached to a watched hub as poll runs it: the routings, the
// wakes, every session's render and its end in the render log, and the
// next routing's weighing of those renders. Under a mesh both writes wake
// every session; an op ends when every session rendered the second. ns/op
// is wall time, allocs/op every goroutine's.
func BenchmarkHubSessionsCoalescedWrites(b *testing.B) {
	for _, n := range benchSizes(b, 1000) {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s, fixture := scalingTailnet(b, n, "mesh")
			cfg := fixture[0].cfg

			hub := NewHub()
			defer hub.Close()

			hub.Watch(s)

			var (
				renders atomic.Int64
				wg      sync.WaitGroup
			)

			nodes := s.ListNodes()
			last := make([]atomic.Uint64, nodes.Len())
			quit := make(chan struct{})

			for i, nv := range nodes.All() {
				sess := hub.Join(nv.ID(), func() {})
				st := NewStream(cfg, hub, nv.ID(), capVer)
				st.Attach(sess)

				_, err := st.Initial(s.Snapshot())
				require.NoError(b, err)
				st.Delivered()

				wg.Go(func() {
					for {
						select {
						case <-quit:
							return
						case <-sess.Wakes():
							snap := s.Snapshot()

							_, err := st.Update(snap)
							if err == nil {
								st.Delivered()
							}

							last[i].Store(snap.Rev())
							renders.Add(1)
						}
					}
				})
			}

			b.ReportAllocs()
			b.ResetTimer()

			i := 0
			for b.Loop() {
				scalingEndpoint(b, s, nodes.At(i%nodes.Len()).ID(), i)
				scalingEndpoint(b, s, nodes.At((i+1)%nodes.Len()).ID(), i)

				want := s.Snapshot().Rev()

				for j := range last {
					for last[j].Load() < want {
						runtime.Gosched()
					}
				}

				i++
			}

			b.StopTimer()
			close(quit)
			wg.Wait()

			b.ReportMetric(float64(renders.Load())/float64(i), "renders/op")
		})
	}
}

// BenchmarkHubPollStyle is [BenchmarkHubSessionsCoalescedWrites] with the
// sessions run as poll runs them: each waits out a batch delay after a
// wake and takes its own snapshot of the state, and the watcher waits a
// moment before each commit, so its routings coalesce and renders land
// between their ends. An op is four writes 1 ms apart, every one waking
// every session; it ends when every session rendered the last. It reports
// the watcher's time per routing and its worst.
func BenchmarkHubPollStyle(b *testing.B) {
	for _, n := range benchSizes(b, 1000, 5000) {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			const delay = 5 * time.Millisecond

			s, fixture := scalingTailnet(b, n, "mesh")
			cfg := fixture[0].cfg

			hub := NewHub()
			defer hub.Close()

			var (
				mu                 sync.Mutex
				start              time.Time
				routings           int
				routingNs, worstNs int64
				renders            atomic.Int64
				wg                 sync.WaitGroup
			)

			hub.beforeRoute = func() {
				time.Sleep(time.Millisecond) //nolint:forbidigo // a slow watcher, not a wait

				mu.Lock()
				start = time.Now()
				mu.Unlock()
			}
			hub.routed = func(_, _ uint64, _ int) {
				mu.Lock()
				d := time.Since(start).Nanoseconds()
				routings++
				routingNs += d
				worstNs = max(worstNs, d)
				mu.Unlock()
			}
			hub.Watch(s)

			nodes := s.ListNodes()
			last := make([]atomic.Uint64, nodes.Len())
			quit := make(chan struct{})

			for i, nv := range nodes.All() {
				sess := hub.Join(nv.ID(), func() {})
				st := NewStream(cfg, hub, nv.ID(), capVer)
				st.Attach(sess)

				_, err := st.Initial(s.Snapshot())
				require.NoError(b, err)
				st.Delivered()

				wg.Go(func() {
					for {
						select {
						case <-quit:
							return
						case <-sess.Wakes():
							select {
							case <-quit:
								return
							case <-time.After(delay):
							}

							snap := s.Snapshot()

							_, err := st.Update(snap)
							if err == nil {
								st.Delivered()
							}

							last[i].Store(snap.Rev())
							renders.Add(1)
						}
					}
				})
			}

			b.ReportAllocs()
			b.ResetTimer()

			i := 0

			for b.Loop() {
				for k := range 4 {
					scalingEndpoint(b, s, nodes.At((i*4+k)%nodes.Len()).ID(), i)
					time.Sleep(time.Millisecond) //nolint:forbidigo // writes spread out, not a wait
				}

				want := s.Snapshot().Rev()

				for j := range last {
					for last[j].Load() < want {
						time.Sleep(100 * time.Microsecond) //nolint:forbidigo // waiting on the sessions
					}
				}

				i++
			}

			b.StopTimer()
			close(quit)
			wg.Wait()

			mu.Lock()
			defer mu.Unlock()

			b.ReportMetric(float64(renders.Load())/float64(i), "renders/op")
			b.ReportMetric(float64(routingNs)/float64(max(routings, 1))/1e6, "ms/routing")
			b.ReportMetric(float64(worstNs)/1e6, "worst-ms/routing")
		})
	}
}

// BenchmarkRenderLog measures the render log's paths at 10,000 sessions on
// their own, in a 1,000 node mesh: every session's render ending, 8 at a
// time, before the routing that covers it (end); the same after a routing
// went past it, each asking Route (end-past); a routing over coalesced
// commits weighing 10,000 renders of one commit between its ends (between);
// and a wake of every session (wake), which no longer touches the log.
// Every session holds a snapshot of its own, as poll takes them.
func BenchmarkRenderLog(b *testing.B) {
	const n = 10_000

	s, _ := scalingTailnet(b, 1000, "mesh")
	nodes := s.ListNodes()

	from := s.Snapshot()
	scalingEndpoint(b, s, nodes.At(0).ID(), 1)

	mids := make([]*state.Snapshot, n)
	for i := range mids {
		mids[i] = s.Snapshot()
	}

	scalingEndpoint(b, s, nodes.At(1).ID(), 2)
	to := s.Snapshot()

	hub := NewHub()
	defer hub.Close()

	// Sessions of nodes the snapshots do not have: the log weighs them as
	// any other, and no routing names them.
	sessions := make([]*Session, n)
	for i := range sessions {
		sessions[i] = hub.Join(types.NodeID(2000+i), func() {}) //nolint:gosec // small
	}

	ends := func() {
		var wg sync.WaitGroup

		for w := range 8 {
			wg.Go(func() {
				for i := w; i < n; i += 8 {
					hub.renders.end(sessions[i], mids[i], true)
				}
			})
		}

		wg.Wait()
	}

	// reset routes to from, so mid is past no routing; past routes to to.
	reset := func() { hub.renders.between(nil, from, false) }
	past := func() { hub.renders.between(nil, to, false) }

	b.Run("end", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			b.StopTimer()
			reset()
			b.StartTimer()

			ends()
		}

		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/render")
	})

	b.Run("end-past", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			b.StopTimer()
			past()
			b.StartTimer()

			ends()
		}

		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/render")
	})

	b.Run("between", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			b.StopTimer()
			reset()
			ends()
			b.StartTimer()

			hub.renders.between(from, to, false)
		}
	})

	b.Run("wake", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			hub.wake(true, nil)

			b.StopTimer()

			for _, sess := range sessions {
				select {
				case <-sess.wakes:
				default:
				}
			}

			b.StartTimer()
		}
	})
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
// walk each shared holder list that reads them once, not once per changed
// node. The work tests count woken sessions and renders, which a repeated
// walk of the same list does not change.
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

	walked := 0
	for _, v := range reachedViews(old, changed) {
		walked += len(v)
	}

	// Under allow-all the lists are those of the atoms every node holds
	// and the changed nodes' owners' own; once per changed node is 20 times
	// that.
	assert.LessOrEqual(t, walked, 3*nodes.Len(), "each list walked once")

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
				via := compiledPolicy(t, live).ViaRoutesForPeer(v, routerView)
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

func TestViaMoveRendersOnlyChangedRouters(t *testing.T) {
	t.Parallel()

	for _, shape := range []string{"via", "self", "users", "sparse"} {
		t.Run(shape, func(t *testing.T) {
			t.Parallel()

			s, streams := scalingTailnet(t, 100, "via")
			policy := scalingPolicies["via"]

			if shape != "via" {
				plain := `{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}`
				if shape == "users" {
					plain = `{"src":["u0@"],"dst":["u0@"],"ip":["*"]}`
				}

				source := "autogroup:member"
				if shape == "sparse" {
					source = "u0@"
				}

				policy = `{"tagOwners":{"tag:r":["u0@"]},"grants":[` + plain + `,
					{"src":["` + source + `"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:r"]}]}`
			}

			_, err := s.SetPolicy([]byte(policy))
			require.NoError(t, err)

			before := s.Snapshot()
			reference := make([]*Stream, len(streams))
			clients := make([]*modelClient, len(streams))

			hub, referenceHub := NewHub(), NewHub()
			for i, st := range streams {
				streams[i] = NewStream(st.cfg, hub, st.nodeID, capVer)
				initial, err := streams[i].Initial(before)
				require.NoError(t, err)

				clients[i] = newModelClient(initial[0])
				streams[i].Delivered()
				reference[i] = NewStream(st.cfg, referenceHub, st.nodeID, capVer)
				_, err = reference[i].Initial(before)
				require.NoError(t, err)
				reference[i].Delivered()
			}

			for step := range 4 {
				winner := streams[(step%2)*10].nodeID
				require.NoError(t, s.Disconnect(winner, mustNode(t, s, winner).SessionEpoch()))
				s.Connect(winner)
				snap := s.Snapshot()
				require.Equal(t, before.CapsRev(), snap.CapsRev(), "only availability changes")

				renders := 0

				for i, st := range streams {
					old := st.sent
					count := st.r.rendered
					responses, err := st.Update(snap)
					require.NoError(t, err)

					renders += st.r.rendered - count
					// Force the reference to revisit every routed peer, as before
					// election invalidation was narrowed to its changed winners.
					reference[i].r.lastKey.routes = ^uint64(0)
					want, err := reference[i].Update(snap)
					require.NoError(t, err)
					require.Equal(t, want, responses, "step %d viewer %d: identical wire deltas", step, st.nodeID)

					for _, response := range responses {
						clients[i].apply(response)
					}

					st.Delivered()
					reference[i].Delivered()

					fresh, err := NewStream(st.cfg, NewHub(), st.nodeID, capVer).Initial(snap)
					require.NoError(t, err)
					require.Empty(t, clients[i].sameAs(newModelClient(fresh[0])))

					for _, unrelated := range streams[20:] {
						was, _ := old.peer(unrelated.nodeID.NodeID())
						now, _ := st.sent.peer(unrelated.nodeID.NodeID())
						require.Same(t, was, now, "step %d viewer %d: unrelated peer %d", step, st.nodeID, unrelated.nodeID)
					}
				}

				if shape == "via" {
					assert.Equal(t, 198, renders, "only the losing and gaining routers change")
				}
			}

			old, err := NewStream(streams[1].cfg, NewHub(), streams[1].nodeID, capVer).Initial(before)
			require.NoError(t, err)
			require.Empty(t, clients[1].sameAs(newModelClient(old[0])), "four failovers restore the original wire map")
		})
	}
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

	routed := func() int {
		if st.r.set == nil {
			return 0
		}

		return len(st.r.set.routes)
	}

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

func TestFrameClassification(t *testing.T) {
	at := time.Now()
	for _, tc := range []struct {
		name     string
		classify func(*tailcfg.MapResponse) bool
		response tailcfg.MapResponse
		payload  string
	}{
		{"patch", patchOnly, tailcfg.MapResponse{ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}}, "PeersChangedPatch"},
		{"derp", derpOnly, tailcfg.MapResponse{ControlTime: &at, DERPMap: &tailcfg.DERPMap{}}, "DERPMap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.True(t, tc.classify(&tc.response))

			missingTime := tc.response
			missingTime.ControlTime = nil
			require.False(t, tc.classify(&missingTime))

			zeroTime := time.Time{}
			withZeroTime := tc.response
			withZeroTime.ControlTime = &zeroTime
			require.True(t, tc.classify(&withZeroTime), "a present zero time is still a control time")

			// Discover every field so dependency additions cannot silently bypass classification.
			typ := reflect.TypeFor[tailcfg.MapResponse]()
			for i := range typ.NumField() {
				field := typ.Field(i)
				if field.Name == tc.payload || field.Name == "ControlTime" {
					continue
				}

				t.Run(field.Name, func(t *testing.T) {
					response := tc.response

					value := reflect.ValueOf(&response).Elem().Field(i)
					switch value.Kind() { //nolint:exhaustive // Fail new field kinds until a nonzero test value is added.
					case reflect.Slice:
						value.Set(reflect.MakeSlice(value.Type(), 0, 0))
						require.False(t, tc.classify(&response), "nonnil empty slice is an extra field")
						value.Set(reflect.MakeSlice(value.Type(), 1, 1))
					case reflect.Map:
						value.Set(reflect.MakeMap(value.Type()))
						require.False(t, tc.classify(&response), "nonnil empty map is an extra field")
						value.SetMapIndex(reflect.Zero(value.Type().Key()), reflect.Zero(value.Type().Elem()))
					case reflect.Pointer:
						value.Set(reflect.New(value.Type().Elem()))
					case reflect.String:
						value.SetString("set")
					case reflect.Bool:
						value.SetBool(true)
					case reflect.Int64:
						value.SetInt(1)
					default:
						t.Fatalf("add a nonzero test value for %s (%s)", field.Name, field.Type)
					}

					before := response
					require.False(t, tc.classify(&response), "extra field must prevent sharing")
					require.Equal(t, before, response, "classification must not mutate the response")
				})
			}
		})
	}

	for _, patches := range [][]*tailcfg.PeerChange{nil, {}, {{}, {}}} {
		require.False(t, patchOnly(&tailcfg.MapResponse{ControlTime: &at, PeersChangedPatch: patches}))
	}

	require.True(t, patchOnly(&tailcfg.MapResponse{ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{nil}}))
	require.False(t, derpOnly(&tailcfg.MapResponse{ControlTime: &at}))
}

func TestFrameClassificationAllocs(t *testing.T) {
	at := time.Now()
	patch := &tailcfg.MapResponse{ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}}
	derp := &tailcfg.MapResponse{ControlTime: &at, DERPMap: &tailcfg.DERPMap{}}
	allocs := testing.AllocsPerRun(100, func() {
		if !patchOnly(patch) || !derpOnly(derp) {
			t.Fatal("single patch and DERP frames must be shareable")
		}
	})
	require.Zero(t, allocs, "classification must not allocate per viewer")
}

func TestFrameSharingKeepsCommitTimes(t *testing.T) {
	at := time.Now()
	for name, response := range map[string]tailcfg.MapResponse{
		"patch": {ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}},
		"derp":  {ControlTime: &at, DERPMap: &tailcfg.DERPMap{}},
	} {
		t.Run(name, func(t *testing.T) {
			var cache frameCache

			first := response
			require.Same(t, &first, cache.share(&first))

			equalTime := at
			same := response
			same.ControlTime = &equalTime
			require.Same(t, &first, cache.share(&same))

			later := at.Add(time.Second)
			newer := response
			newer.ControlTime = &later
			require.Same(t, &newer, cache.share(&newer))
			require.Same(t, &same, cache.share(&same), "older commits cannot reuse a newer frame")
			require.Len(t, cache.frames, 1)
			require.Len(t, cache.byResp, 1)
		})
	}
}

func BenchmarkFrameClassification(b *testing.B) {
	at := time.Now()
	for name, response := range map[string]*tailcfg.MapResponse{
		"patch":        {ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}},
		"derp":         {ControlTime: &at, DERPMap: &tailcfg.DERPMap{}},
		"mixed":        {ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}, DERPMap: &tailcfg.DERPMap{}},
		"empty-filter": {ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}, PacketFilters: map[string][]tailcfg.FilterRule{}},
		"no-time":      {PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}}},
		"two-patches":  {ControlTime: &at, PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 1}, {NodeID: 2}}},
	} {
		for classifier, classify := range map[string]func(*tailcfg.MapResponse) bool{"patchOnly": patchOnly, "derpOnly": derpOnly} {
			b.Run(classifier+"/"+name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					classify(response)
				}
			})
		}
	}
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

	require.Empty(t, hub.core.sentPeers[ids[0]].attempts, "folding does not mean a reconnect was delivered")
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

// BenchmarkPeerRenderCIChurn replays fixed snapshots with warm class maps,
// isolating each session's render after CI replacements or endpoint writes.
// The 802 tags and 402 grants include shared services, per-app CI access,
// developer access and an administrator. Class construction is untimed.
func BenchmarkPeerRenderCIChurn(b *testing.B) {
	tags := make([]string, 0, 802)
	tags = append(tags, "tag:admin", "tag:ci-common")
	common, ci := make([]string, 0, 100), make([]string, 0, 301)

	ci = append(ci, "tag:ci-common")
	for i := range 100 {
		common = append(common, fmt.Sprintf("tag:common%d", i))
		tags = append(tags, fmt.Sprintf("tag:dev%d", i), common[i])
	}

	grants := make([]map[string]any, 0, 402)
	grants = append(grants, map[string]any{"src": []string{"tag:admin"}, "dst": []string{"*"}, "ip": []string{"tcp:22", "tcp:80", "tcp:443"}})

	for i := range 300 {
		app, worker := fmt.Sprintf("tag:app%d", i), fmt.Sprintf("tag:ci-app%d", i)
		tags = append(tags, app, worker)
		ci = append(ci, worker)
		grants = append(grants, map[string]any{"src": []string{worker}, "dst": []string{app}, "ip": []string{"tcp:80"}})
	}

	grants = append(grants, map[string]any{"src": ci, "dst": common, "ip": []string{"tcp:80"}})
	for i := range 100 {
		grants = append(grants, map[string]any{
			"src": []string{fmt.Sprintf("tag:dev%d", i)},
			"dst": []string{fmt.Sprintf("tag:app%d", i), fmt.Sprintf("tag:app%d", i+100), fmt.Sprintf("tag:app%d", i+200)},
			"ip":  []string{"tcp:80"},
		})
	}

	owners := make(map[string][]string, len(tags))
	for _, tag := range tags {
		owners[tag] = []string{"u-0@"}
	}

	policy, err := json.Marshal(map[string]any{"tagOwners": owners, "grants": grants})
	require.NoError(b, err)
	require.Len(b, tags, 802)
	require.Len(b, grants, 402)

	for _, n := range []int{1000, 6600} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			cfg, s := benchState(b, n, 10)
			roles := make(map[string]types.NodeID)

			var workers []*types.Node

			for i, nv := range s.ListNodes().All() {
				node := nv.AsStruct()
				tag := tags[i%len(tags)]
				node.Tags = []string{tag}
				s.PutNodeInStoreForTest(*node)

				roles[tag] = node.ID
				if strings.HasPrefix(tag, "tag:ci-app") {
					workers = append(workers, node)
				}
			}

			_, err := s.SetPolicy(policy)
			require.NoError(b, err)
			require.GreaterOrEqual(b, len(workers), 16)

			for _, kind := range []string{"endpoint", "replace", "replace-x16"} {
				before := s.Snapshot()

				count := 1
				if kind == "replace-x16" {
					count = 16
				}

				var replacements []types.NodeID

				for i, original := range workers[:count] {
					node := original.Clone()
					if kind == "endpoint" {
						node.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}
					} else {
						s.DeleteNodeFromStoreForTest(node.ID)
						node.ID = types.NodeID(1<<40 + i) //nolint:gosec // bounded fixture
						node.Hostname, node.GivenName = fmt.Sprintf("replacement-%d", i), fmt.Sprintf("replacement-%d", i)
						replacements = append(replacements, node.ID)
					}

					s.PutNodeInStoreForTest(*node)
				}

				after := s.Snapshot()

				for _, role := range []string{"tag:admin", "tag:common0", "tag:app0"} {
					b.Run(kind+"/"+role, func(b *testing.B) {
						hub := NewHub()
						b.Cleanup(hub.Close)
						r := newRenderer(cfg, hub, roles[role], capVer)
						_, err := r.render(before)
						require.NoError(b, err)

						previous := *r
						warm, err := r.render(after)
						require.NoError(b, err)

						freshHub := NewHub()
						b.Cleanup(freshHub.Close)
						fresh, err := newRenderer(cfg, freshHub, roles[role], capVer).render(after)
						require.NoError(b, err)
						require.Equal(b, maps.Collect(fresh.allPeers()), maps.Collect(warm.allPeers()))
						require.Equal(b, maps.Collect(fresh.profiles.All()), maps.Collect(warm.profiles.All()))

						misses := graph.MapLogMisses()

						b.ReportAllocs()

						for b.Loop() {
							*r = previous

							_, err := r.render(after)
							if err != nil {
								b.Fatal(err)
							}
						}

						b.ReportMetric(float64(graph.MapLogMisses()-misses)/float64(b.N), "map-log-misses/op")
						b.ReportMetric(float64(warm.peers.Len()), "class-peers")
					})
				}

				for _, id := range replacements {
					s.DeleteNodeFromStoreForTest(id)
				}

				for _, original := range workers[:count] {
					s.PutNodeInStoreForTest(*original)
				}
			}
		})
	}
}

// BenchmarkClassMapsBuild isolates rebuilding a class after its view identity
// changes, with the individual peer renders already cached.
func BenchmarkClassMapsBuild(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			cfg, s := benchState(b, n, 10)
			snap := s.Snapshot()
			view := snap.PeerViews()[0]
			require.Len(b, view, n)

			var (
				renders peerRenders
				warm    classMaps
			)
			warm.get(cfg, &renders, snap, view, capVer, 0, nil)
			b.ReportAllocs()

			var (
				peers    *peerMap
				profiles *profileMap
			)

			for b.Loop() {
				var cm classMaps

				peers, profiles, _ = cm.get(cfg, &renders, snap, view, capVer, 0, nil)
			}

			require.Equal(b, n, peers.Len())
			require.Equal(b, 10, profiles.Len())
			b.ReportMetric(float64(n), "peers/op")
		})
	}
}

// BenchmarkClassMapsUpdate replays a fixed delta against cached class maps.
// Peer renders are warm; snapshot writes and cursor resets are untimed.
func BenchmarkClassMapsUpdate(b *testing.B) {
	for _, shape := range []string{"small-classes", "dense"} {
		for _, delta := range []string{"unchanged", "endpoint", "repeated-endpoint", "global-caps"} {
			b.Run(shape+"/"+delta, func(b *testing.B) {
				cfg, s := benchState(b, 1000, 100)
				if shape == "small-classes" {
					_, err := s.SetPolicy([]byte(`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}]}`))
					require.NoError(b, err)
				}

				before := s.Snapshot()

				var (
					cm      classMaps
					renders peerRenders
				)
				for _, view := range before.PeerViews() {
					cm.get(cfg, &renders, before, view, capVer, before.CapsRev(), before.NodeCaps)
				}

				previous := make(map[*classEntry]*classPeers, len(cm.m))
				for _, entry := range cm.m {
					previous[entry] = entry.cur
				}

				if delta != "unchanged" {
					nodes := s.ListNodes()

					limit := 1
					if delta == "repeated-endpoint" {
						limit = 128
					}

					if delta == "global-caps" {
						limit = 100
					}

					for i := range limit {
						index := i
						if delta == "repeated-endpoint" {
							index = 0
						}

						n := nodes.At(index).AsStruct()
						n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("192.0.2.1:%d", i+1))}
						s.PutNodeInStoreForTest(*n)
					}

					if delta == "global-caps" {
						policy := `{"nodeAttrs":[{"target":["*"],"attr":["custom:probe"]}]}`
						if shape == "small-classes" {
							policy = `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}],"nodeAttrs":[{"target":["*"],"attr":["custom:probe"]}]}`
						}

						_, err := s.SetPolicy([]byte(policy))
						require.NoError(b, err)
					}
				}

				after := s.Snapshot()
				touched, ok := after.NodesTouchedSince(before.NodesVersion())
				require.True(b, ok, "the delta stays within the node edit log")

				if delta == "global-caps" {
					require.Len(b, after.CapsChangedSince(before.CapsVersion()), 1000)
					require.Len(b, touched, 100)
				}

				views := slices.DeleteFunc(slices.Clone(after.PeerViews()), func(v []types.NodeID) bool { return len(v) == 0 })
				require.Len(b, views, len(previous), "the delta keeps the classes")

				for _, view := range views {
					require.NotNil(b, cm.m[classKey{view: &view[0], n: len(view)}], "the delta keeps view identity")
					cm.get(cfg, &renders, after, view, capVer, after.CapsRev(), after.NodeCaps)
				}

				b.ReportAllocs()

				for b.Loop() {
					b.StopTimer()

					for entry, cur := range previous {
						entry.cur = cur
					}

					b.StartTimer()

					for _, view := range views {
						cm.get(cfg, &renders, after, view, capVer, after.CapsRev(), after.NodeCaps)
					}
				}
			})
		}
	}
}

// TestClassMapsChangedCandidates catches lost in-view updates or deletions
// when global deltas also contain repeated IDs outside an immutable view.
func TestClassMapsChangedCandidates(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	sparse := mustNode(t, s, ids[1]).AsStruct()
	s.DeleteNodeFromStoreForTest(ids[1])

	sparse.ID = types.NodeID(1 << 40)
	ids[1] = sparse.ID
	s.PutNodeInStoreForTest(*sparse)

	view := slices.Clone(ids[:2])

	var (
		cm      classMaps
		renders peerRenders
	)

	before := s.Snapshot()
	old, oldProfiles, _ := cm.get(cfg, &renders, before, view, capVer, before.CapsRev(), before.NodeCaps)

	oldNodes := maps.Collect(old.All())
	for id, node := range oldNodes {
		oldNodes[id] = node.Clone()
	}

	oldOwners := maps.Collect(oldProfiles.All())

	for range 2 {
		for _, id := range ids {
			n := mustNode(t, s, id).AsStruct()
			n.Hostname += "-changed"
			s.PutNodeInStoreForTest(*n)
		}
	}

	_, err := s.SetPolicy([]byte(`{"nodeAttrs":[{"target":["*"],"attr":["custom:probe"]}]}`))
	require.NoError(t, err)
	n := mustNode(t, s, ids[1]).AsStruct()
	owner := mustNode(t, s, ids[2]).User().AsStruct()
	n.UserID, n.User = &owner.ID, owner
	s.PutNodeInStoreForTest(*n)

	check := func() {
		t.Helper()

		snap := s.Snapshot()
		cm.pruned = snap.PeersRev() // Keep testing the supplied view after a deletion changes live classes.
		got, profiles, _ := cm.get(cfg, &renders, snap, view, capVer, snap.CapsRev(), snap.NodeCaps)

		var fresh classMaps

		want, wantProfiles, _ := fresh.get(cfg, &renders, snap, view, capVer, snap.CapsRev(), snap.NodeCaps)
		require.Equal(t, maps.Collect(want.All()), maps.Collect(got.All()))
		require.Equal(t, maps.Collect(wantProfiles.All()), maps.Collect(profiles.All()))

		_, outside := got.Get(ids[2].NodeID())
		require.False(t, outside)
		require.Equal(t, oldNodes, maps.Collect(old.All()), "old peer maps stay immutable")
		require.Equal(t, oldOwners, maps.Collect(oldProfiles.All()), "old profiles stay immutable")
	}
	check()
	s.DeleteNodeFromStoreForTest(ids[1])
	check()

	stale, staleProfiles, _ := cm.get(cfg, &renders, before, view, capVer, before.CapsRev(), before.NodeCaps)
	require.Equal(t, oldNodes, maps.Collect(stale.All()))
	require.Equal(t, oldOwners, maps.Collect(staleProfiles.All()))
	check()

	for _, empty := range [][]types.NodeID{nil, {}} {
		peers, profiles, cursor := cm.get(cfg, &renders, s.Snapshot(), empty, capVer, 0, nil)
		require.Zero(t, peers.Len())
		require.Zero(t, profiles.Len())
		require.Equal(t, state.NodesVersion{}, cursor, "an empty view needs no node cursor")
	}
}

func BenchmarkClassOwnersSet(b *testing.B) {
	owners := make([]types.UserView, 10)
	for i := range owners {
		u := &types.User{Name: fmt.Sprintf("owner-%d", i)}
		u.ID = uint(i + 1)
		owners[i] = u.View()
	}

	for _, n := range []int{100, 1000, 10000} {
		for _, kind := range []string{"build", "unchanged"} {
			b.Run(fmt.Sprintf("%s/nodes=%d", kind, n), func(b *testing.B) {
				base := newClassOwners()
				if kind == "unchanged" {
					e := base.edit()
					for i := range n {
						e.set(tailcfg.NodeID(i+1), owners[i%len(owners)])
					}

					base = e.done()
				}

				b.ReportAllocs()

				var next classOwners

				for b.Loop() {
					e := base.edit()
					for i := range n {
						e.set(tailcfg.NodeID(i+1), owners[i%len(owners)])
					}

					next = e.done()
				}

				require.Equal(b, n, next.of.Len())
				require.Equal(b, 10, next.profiles.Len())
				b.ReportMetric(float64(n), "sets/op")
			})
		}
	}
}

func TestClassOwnersUnchangedDoesNotAllocate(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1
	e := newClassOwners().edit()
	e.set(1, alice.View())
	base := e.done()
	e = base.edit()

	allocs := testing.AllocsPerRun(100, func() { e.set(1, alice.View()) })
	require.Zero(t, allocs, "an unchanged owner must not rebuild its profile")

	next := e.done()
	require.Same(t, base.profiles, next.profiles)
	require.Same(t, base.of, next.of)
	require.Same(t, base.nodes, next.nodes)
}

func TestClassOwnersProfileAndOwnershipChanges(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1
	bob := &types.User{Name: "bob"}
	bob.ID = 2

	e := newClassOwners().edit()
	e.set(1, alice.View())
	e.set(2, alice.View())
	base := e.done()

	renamed := *alice
	renamed.DisplayName = "Alice Updated"
	e = base.edit()
	e.set(1, renamed.View())
	e.set(2, renamed.View())
	updated := e.done()
	p, ok := updated.profiles.Get(1)
	require.True(t, ok)
	require.Equal(t, renamed.TailscaleUserProfile(), p)
	p, _ = base.profiles.Get(1)
	require.Equal(t, alice.TailscaleUserProfile(), p, "old snapshots keep their profiles")

	e = updated.edit()
	e.set(1, bob.View())
	e.set(2, types.UserView{})
	next := e.done()
	require.Equal(t, 1, next.of.Len())
	uid, ok := next.of.Get(1)
	require.True(t, ok)
	require.Equal(t, tailcfg.UserID(2), uid)

	count, ok := next.nodes.Get(2)
	require.True(t, ok)
	require.Equal(t, 1, count)
	require.Equal(t, 1, next.profiles.Len())
	p, _ = next.profiles.Get(2)
	require.Equal(t, bob.TailscaleUserProfile(), p)
	require.Equal(t, 2, updated.of.Len())
}

// BenchmarkFirstMap separates a reconnect on a warm hub from the first
// render on a cold hub and from reopening state (including Close). The last
// includes DB load, policy compile and peer construction, but not process
// startup, HTTP/Noise, or a concurrent reconnect storm.
func BenchmarkFirstMap(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			benchFirstMap(b, n, "allow-all", nil)
		})
	}
}

// BenchmarkFirstMapShapes is [BenchmarkFirstMap] under policies whose peers
// hold several source identities: users in groups, tagged nodes, a member
// mesh. That is where a map naming sources by capability grows each peer's
// CapMap. filter-bytes/op is the JSON of the map's packet filter, and
// rest-bytes/op the JSON of everything else. HEADSCALE_SCALE_NODES runs one
// size instead.
func BenchmarkFirstMapShapes(b *testing.B) {
	for _, shape := range []string{"mesh", "selectors", "tags", "rules"} {
		for _, n := range benchSizes(b, 1000, 10000) {
			b.Run(fmt.Sprintf("%s/nodes=%d", shape, n), func(b *testing.B) {
				benchFirstMap(b, n, shape, newSizedEncoder())
			})
		}
	}
}

// benchFirstMap runs [BenchmarkFirstMap] for one tailnet. A sized encoder,
// when given, encodes in place of benchEncode and splits the bytes.
func benchFirstMap(b *testing.B, n int, shape string, sized *sizedEncoder) {
	b.Helper()

	encode := benchEncode
	if sized != nil {
		encode = sized.fn
	}

	s, streams := scalingTailnet(b, n, shape)
	st := streams[len(streams)/2]
	snap := s.Snapshot()

	for _, cache := range []string{"warm-hub", "cold-hub", "new-state"} {
		for _, encoding := range []string{"json", "zstd"} {
			b.Run(cache+"/"+encoding, func(b *testing.B) {
				if cache == "warm-hub" {
					first := NewStream(st.cfg, st.hub, st.nodeID, capVer)
					resps, err := first.Initial(snap)
					require.NoError(b, err)
					_, err = st.hub.Encode(resps[0], encoding == "zstd", encode)
					require.NoError(b, err)
					first.Delivered()
				}

				b.ReportAllocs()

				var (
					first *Stream
					size  int
					split responseSize
					found bool
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
					data, err := hub.Encode(resps[0], encoding == "zstd", encode)
					require.NoError(b, err)
					first.Delivered()

					size = len(data)

					if sized != nil {
						split, found = sized.sizes[resps[0]]
						clear(sized.sizes)
					}

					if reopened != nil {
						require.NoError(b, reopened.Close())
					}
				}

				require.NotNil(b, first)
				require.Nil(b, first.pending, "successful reconnects confirm delivery even when attempts would fold")

				if cache == "warm-hub" {
					require.Empty(b, st.hub.core.sentPeers[st.nodeID].attempts, "successful reconnects leave no failed-write history")
				}

				b.ReportMetric(float64(size), "encoded-bytes/op")

				if sized != nil {
					require.True(b, found, "the sized encoder encoded the first map")
					b.ReportMetric(float64(split.filter), "filter-bytes/op")
					b.ReportMetric(float64(split.json-split.filter), "rest-bytes/op")
				}
			})
		}
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

	// Every node's session has read its filter: an edit across selectors
	// compares what was served, and names a node nobody was served one for.
	before := s.Snapshot()
	for _, nv := range before.ListNodes().All() {
		_, err := before.FilterForNode(nv.ID())
		require.NoError(t, err)
	}

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
	// Pinned to address form: its recompile keeps the policy's caps, not the stamps, which name the selectors the document uses.
	t.Setenv(state.TestCapabilitySourcesEnv, "false")

	cfg, s, ids := streamTestState(t, ownUserOnly)

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	before := s.Snapshot()
	peer, _ := st.r.last.peer(ids[1].NodeID())
	require.NotNil(t, peer)

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	require.NotEqual(t, before.PolicyRev(), s.Snapshot().PolicyRev(), "test sanity: the policy recompiles")

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
	retained, attempts := h.core.retained, len(h.core.sentPeers[viewer].attempts)
	h.mu.Unlock()
	require.LessOrEqual(t, retained, h.core.maxHistoryIDs)
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
		cm.get(cfg, &renders, snap, snap.PeerView(id), capVer, snap.CapsRev(), nil)
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
	attempts := hub.core.sentPeers[ids[0]].attempts
	hub.mu.Unlock()
	assert.Empty(t, attempts, "a delivery at the same revision clears its attempt")
}

// TestAFirstMapSharesTheHistoryAnotherSessionHeld pins a first map reading
// the peer history an earlier session of its node left: a second session
// on the same snapshot shares it, a delivery of its own revision leaves
// the bookkeeping the route audit reads clean, and a later first map
// announces its removals from that history.
func TestAFirstMapSharesTheHistoryAnotherSessionHeld(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hub := NewHub()
	snap := s.Snapshot()

	a := NewStream(cfg, hub, ids[0], capVer)
	_, err := a.Initial(snap)
	require.NoError(t, err)
	a.Delivered()

	held := hub.lastPeers(ids[0])
	require.Len(t, held, 3, "test sanity: the node held itself and both peers")

	// A second session of the node is a first map on the same snapshot:
	// it shares the history a left rather than starting from none.
	b := NewStream(cfg, hub, ids[0], capVer)
	_, err = b.Initial(snap)
	require.NoError(t, err)
	assert.Equal(t, held, b.pending.ids, "the first map shares the history another session held")

	b.Delivered()

	hub.mu.Lock()
	got, attempts := hub.core.sentPeers[ids[0]].ids, hub.core.sentPeers[ids[0]].attempts
	hub.mu.Unlock()
	assert.Empty(t, attempts, "a delivery at the same revision clears its attempt")
	assert.Equal(t, held, got, "the shared history stays recorded")

	// A peer the node's client held goes away while it has no stream: the
	// next first map announces its removal from the shared history.
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))

	c := NewStream(cfg, hub, ids[0], capVer)
	resps, err := c.Initial(s.Snapshot())
	require.NoError(t, err)

	var removed []tailcfg.NodeID
	for _, resp := range resps {
		removed = append(removed, resp.PeersRemoved...)
	}

	assert.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, removed, "a reconnect announces the removal its shared history held")
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
	attempts := len(h.core.sentPeers[1].attempts)
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
			v, kept := hub.core.sentPeers[ids[0]]
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
		generations = append(generations, hub.core.sentPeers[id].rev)
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

	return cost + len(hub.core.offlineAt)
}

// historyArrays returns the distinct views hub's histories retain, by
// backing array.
func historyArrays(hub *Hub) map[*types.NodeID][]types.NodeID {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	arrays := make(map[*types.NodeID][]types.NodeID, len(hub.core.sentPeers))

	for _, history := range hub.core.sentPeers {
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
	hub.core.maxHistoryIDs = 40

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
		require.LessOrEqual(t, retained, hub.core.maxHistoryIDs, "after %d leaves", i+1)

		hub.mu.Lock()
		counted := hub.core.retained
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
	hub.core.sentPeers[id] = v
	hub.mu.Unlock()

	require.False(t, hub.Leave(hub.Join(id, func() {})))
}

func retainedOf(hub *Hub) int {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	return hub.core.retained
}

// TestHubCapsEmptyOfflineHistories disconnects more isolated nodes, whose
// histories hold no IDs, than the cap: the entries themselves are bounded,
// oldest first.
func TestHubCapsEmptyOfflineHistories(t *testing.T) {
	hub := NewHub()
	hub.core.maxHistoryIDs = 4

	for i := range 12 {
		leaveWithHistory(t, hub, types.NodeID(100+i), sentView{rev: uint64(i + 1)})

		hub.mu.Lock()
		entries := len(hub.core.offlineAt)
		hub.mu.Unlock()

		require.LessOrEqual(t, entries, hub.core.maxHistoryIDs, "after %d leaves", i+1)
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
	hub.core.maxHistoryIDs = 20

	for i := range 10 {
		id := types.NodeID(100 + i)
		attempt := []types.NodeID{id + 1, id + 2, id + 3, id + 4}
		leaveWithHistory(t, hub, id, sentView{rev: uint64(i + 1), attempts: [][]types.NodeID{attempt}})

		require.LessOrEqual(t, historyCost(hub), hub.core.maxHistoryIDs, "after %d leaves", i+1)
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
			hub.core.maxHistoryIDs = 8

			const id = types.NodeID(1)

			sessions := []*Session{hub.Join(id, func() {}), hub.Join(id, func() {})}

			for i := range 48 {
				v := sentView{ids: []types.NodeID{types.NodeID(1000 + i)}, rev: uint64(i + 1)}
				by := sessions[i%2]

				hub.mayHavePeers(by, id, v)

				if delivered {
					hub.setLastPeers(by, id, v)
				}

				require.LessOrEqual(t, retainedOf(hub), hub.core.maxHistoryIDs, "after %d attempts", i+1)
				require.LessOrEqual(t, len(hub.lastPeers(id)), hub.core.maxHistoryIDs+maxPeerAttempts,
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
	cur := hub.core.sentPeers[id]
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
						histories := len(hub.core.sentPeers)
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

// TestClassMapsBuildAndEdit checks bulk owner counts before incremental
// transfers and removals consume them, while retained maps remain immutable.
func TestClassMapsBuildAndEdit(t *testing.T) {
	for _, kind := range []string{"user", "tagged", "ownerless", "invalid-peer"} {
		t.Run(kind, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")
			n := mustNode(t, s, ids[2]).AsStruct()
			firstOwner := mustNode(t, s, ids[0]).Owner().TailscaleUserProfile()
			lastOwner := n.View().Owner().TailscaleUserProfile()
			wantPeers := 3
			wantOwners := map[tailcfg.NodeID]tailcfg.UserID{
				ids[0].NodeID(): firstOwner.ID,
				ids[1].NodeID(): firstOwner.ID,
				ids[2].NodeID(): lastOwner.ID,
			}
			wantCounts := map[tailcfg.UserID]int{firstOwner.ID: 2, lastOwner.ID: 1}
			wantProfiles := map[tailcfg.UserID]tailcfg.UserProfile{firstOwner.ID: firstOwner, lastOwner.ID: lastOwner}

			switch kind {
			case "tagged":
				n.Tags = []string{"tag:service"}
				p := types.TaggedDevices.TailscaleUserProfile()
				wantOwners[ids[2].NodeID()] = p.ID
				delete(wantCounts, lastOwner.ID)
				wantCounts[p.ID] = 1
				delete(wantProfiles, lastOwner.ID)
				wantProfiles[p.ID] = p
			case "ownerless", "invalid-peer":
				if kind == "ownerless" {
					n.UserID, n.User = nil, nil
				} else {
					n.Expiry = new(time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC))
					wantPeers = 2
				}

				delete(wantOwners, ids[2].NodeID())
				delete(wantCounts, lastOwner.ID)
				delete(wantProfiles, lastOwner.ID)
			}

			s.PutNodeInStoreForTest(*n)

			var (
				cm      classMaps
				renders peerRenders
			)

			before := s.Snapshot()
			view := before.PeerView(ids[0])
			peers, profiles, _ := cm.get(cfg, &renders, before, view, capVer, before.CapsRev(), nil)
			entry := cm.m[classKey{view: &view[0], n: len(view)}]
			require.NotNil(t, entry)
			owners := entry.cur.owners

			require.Equal(t, wantPeers, peers.Len())
			require.Equal(t, wantOwners, maps.Collect(owners.of.All()))
			require.Equal(t, wantCounts, maps.Collect(owners.nodes.All()))
			require.Equal(t, wantProfiles, maps.Collect(profiles.All()))
			oldPeers := maps.Collect(peers.All())
			oldSequence := peers.All()

			// Transfer the first owner's second node to the last owner,
			// then orphan its first: the first owner's count must reach zero.
			moved := mustNode(t, s, ids[1]).AsStruct()
			moved.UserID, moved.User = n.UserID, n.User
			moved.Tags = slices.Clone(n.Tags)
			s.PutNodeInStoreForTest(*moved)
			after := s.Snapshot()
			require.Same(t, &view[0], &after.PeerView(ids[0])[0], "ownership preserves the allow-all class")
			cm.get(cfg, &renders, after, view, capVer, after.CapsRev(), nil)

			orphan := mustNode(t, s, ids[0]).AsStruct()
			orphan.UserID, orphan.User = nil, nil
			s.PutNodeInStoreForTest(*orphan)
			after = s.Snapshot()
			require.Same(t, &view[0], &after.PeerView(ids[0])[0], "orphaning preserves the allow-all class")
			updated, updatedProfiles, _ := cm.get(cfg, &renders, after, view, capVer, after.CapsRev(), nil)

			var fresh classMaps

			expected, expectedProfiles, _ := fresh.get(cfg, &renders, after, view, capVer, after.CapsRev(), nil)
			require.Equal(t, maps.Collect(expected.All()), maps.Collect(updated.All()))
			require.Equal(t, maps.Collect(expectedProfiles.All()), maps.Collect(updatedProfiles.All()))

			freshOwners := fresh.m[classKey{view: &view[0], n: len(view)}].cur.owners
			require.Equal(t, maps.Collect(freshOwners.of.All()), maps.Collect(entry.cur.owners.of.All()))
			require.Equal(t, maps.Collect(freshOwners.nodes.All()), maps.Collect(entry.cur.owners.nodes.All()))
			require.Equal(t, oldPeers, maps.Collect(peers.All()), "retained map changed")
			require.Equal(t, oldPeers, maps.Collect(oldSequence), "retained sequence changed")
			require.Equal(t, wantOwners, maps.Collect(owners.of.All()), "retained ownership changed")
			require.Equal(t, wantCounts, maps.Collect(owners.nodes.All()), "retained counts changed")
			require.Equal(t, wantProfiles, maps.Collect(profiles.All()), "retained profiles changed")
		})
	}
}

// TestClassMapsBuildAllocationWork bounds cold construction separately from
// peer rendering, so persistent path copies per insertion cannot return.
func TestClassMapsBuildAllocationWork(t *testing.T) {
	const n = 1000

	cfg, s := benchState(t, n, 10)
	snap := s.Snapshot()
	view := snap.PeerViews()[0]
	require.Len(t, view, n)

	var (
		renders peerRenders
		warm    classMaps
	)
	warm.get(cfg, &renders, snap, view, capVer, 0, nil)

	allocs := testing.AllocsPerRun(5, func() {
		var cm classMaps

		peers, profiles, _ := cm.get(cfg, &renders, snap, view, capVer, 0, nil)
		require.Equal(t, n, peers.Len())
		require.Equal(t, 10, profiles.Len())
	})
	require.Less(t, allocs, float64(10*n), "bulk construction must not copy HAMT paths for every peer")
}

func TestStreamSelfCacheTracksInputs(t *testing.T) {
	const rules = `"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"tagOwners":{"tag:test":["u1@"]}`

	policy := func(attrs string) string { return `{` + rules + `,"nodeAttrs":` + attrs + `}` }
	cfg, s, ids := streamTestState(t, policy(`[]`), func(cfg *types.Config) {
		cfg.DNSConfig.Certificates.Enabled = true
	})
	self, backup := ids[0], ids[1]
	route := netip.MustParsePrefix("10.0.0.0/24")

	for _, id := range []types.NodeID{self, backup} {
		n := mustNode(t, s, id).AsStruct()
		n.Hostinfo = &tailcfg.Hostinfo{Hostname: n.Hostname, OS: "linux", RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
		s.PutNodeInStoreForTest(*n)
	}

	gen := s.Connect(backup)
	s.Connect(self)
	st := NewStream(cfg, NewHub(), self, capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(initial[0])

	st.Delivered()

	var (
		snapshots []*state.Snapshot
		retained  []*tailcfg.Node
		encoded   [][]byte
	)

	check := func(reuse bool) {
		t.Helper()

		before := st.sent.self
		snap := s.Snapshot()
		out, err := st.Update(snap)
		require.NoError(t, err)

		if reuse {
			assert.Same(t, before, st.sent.self)

			for _, response := range out {
				assert.Nil(t, response.Node, "unchanged self must send no update")
			}
		} else {
			assert.NotSame(t, before, st.sent.self)
		}

		for _, response := range out {
			client.apply(response)
		}

		st.Delivered()

		fresh, err := NewStream(cfg, NewHub(), self, capVer).Initial(snap)
		require.NoError(t, err)
		require.Empty(t, client.sameAs(newModelClient(fresh[0])))
		assert.Empty(t, st.sent.self.Hostinfo.OS(), "self Hostinfo stays sanitized")

		for i, old := range retained {
			got, err := json.Marshal(old)
			require.NoError(t, err)
			assert.Equal(t, encoded[i], got, "retained render %d was mutated", i)
			oldMap, err := NewStream(cfg, NewHub(), self, capVer).Initial(snapshots[i])
			require.NoError(t, err)
			assert.Equal(t, old, oldMap[0].Node, "retained snapshot %d was mutated", i)
		}

		data, err := json.Marshal(st.sent.self)
		require.NoError(t, err)

		snapshots = append(snapshots, snap)
		retained = append(retained, st.sent.self)
		encoded = append(encoded, data)
	}
	setPolicy := func(attrs string) {
		t.Helper()

		_, err := s.SetPolicy([]byte(policy(attrs)))
		require.NoError(t, err)
	}

	check(true)

	before := s.Snapshot()
	other := s.CreateRegisteredNodeForTest(mustNode(t, s, ids[2]).User().AsStruct(), "other")
	s.PutNodeInStoreForTest(*other)
	require.NotEqual(t, before.PolicyRev(), s.Snapshot().PolicyRev())
	check(true)
	require.NoError(t, s.DeleteNode(mustNode(t, s, other.ID)))
	check(true)
	setPolicy(`[{"target":["u2@"],"attr":["custom:other"]}]`)
	check(true)
	setPolicy(`[{"target":["*"],"attr":["custom:self"]}]`)
	check(false)
	assert.Contains(t, st.sent.self.CapMap, nodecap.Cap("custom:self"))

	before = s.Snapshot()

	setPolicy(`[{"target":["*"],"attr":["custom:self"]},{"target":["u2@"],"attr":["custom:other"]}]`)
	require.NotEqual(t, before.PolicyRev(), s.Snapshot().PolicyRev())
	check(true)
	setPolicy(`[{"target":["*"],"attr":["nextdns:first"]}]`)
	check(false)

	caps := st.sent.self.CapMap

	setPolicy(`[{"target":["*"],"attr":["nextdns:second"]}]`)
	check(false)
	assert.False(t, caps.Equal(st.sent.self.CapMap), "parameterized capability changes invalidate self")
	setPolicy(`[{"target":["*"],"attr":["disable-ipv4"]}]`)
	check(false)
	assert.NotContains(t, st.sent.self.Addresses, mustNode(t, s, self).Prefixes()[0])
	setPolicy(`[]`)
	check(false)
	assert.Contains(t, st.sent.self.Addresses, mustNode(t, s, self).Prefixes()[0])

	n := mustNode(t, s, self).AsStruct()
	n.Hostinfo.Services = []tailcfg.Service{{Proto: "tcp", Port: 8080}}
	s.PutNodeInStoreForTest(*n)
	check(false)

	_, err = s.RenameNode(self, "renamed")
	require.NoError(t, err)
	check(false)

	_, err = s.RenameUser(mustNode(t, s, self).TypedUserID(), "renamed-user")
	require.NoError(t, err)
	check(false)

	_, err = s.SetNodeTags(self, []string{"tag:test"})
	require.NoError(t, err)
	check(false)
	assert.Equal(t, taggedSelfUserID(self), st.sent.self.User)
	setPolicy(`[{"target":["u2@"],"attr":["custom:other"]}]`)
	check(true)
	assert.Equal(t, taggedSelfUserID(self), st.sent.self.User)

	require.NotContains(t, st.sent.self.PrimaryRoutes, route)
	selfBefore := mustNode(t, s, self)
	require.NoError(t, s.Disconnect(backup, gen))
	require.Equal(t, selfBefore, mustNode(t, s, self), "HA move must not change the self view")
	check(false)
	assert.Contains(t, st.sent.self.PrimaryRoutes, route)
	s.SetExtraRecords([]tailcfg.DNSRecord{{Name: strings.TrimSuffix(st.sent.self.Name, "."), Value: "100.64.0.99"}})
	check(false)
	assert.NotContains(t, st.sent.self.CapMap, nodecap.HTTPS)
	s.SetExtraRecords(nil)
	check(false)
	assert.Contains(t, st.sent.self.CapMap, nodecap.HTTPS)
}

func TestStreamSelfCacheRetriesFailedRender(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	before := st.sent.self
	n := mustNode(t, s, ids[0]).AsStruct()
	n.Expiry = new(time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC))
	s.PutNodeInStoreForTest(*n)

	for range 2 {
		_, err := st.Update(s.Snapshot())
		require.ErrorIs(t, err, types.ErrExpiryOutOfRange)
		assert.Same(t, before, st.r.self)
		assert.Same(t, before, st.sent.self)
	}

	n.GivenName = "recovered"
	n.Expiry = nil
	s.PutNodeInStoreForTest(*n)
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, out)
	require.NotNil(t, out[0].Node)
	assert.Equal(t, "recovered.headscale.test.", out[0].Node.Name)

	fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	assert.Equal(t, fresh[0].Node, out[0].Node)
}

// BenchmarkSelfCache measures sparse sessions after a policy recompile and one
// session after its own Hostinfo write; fixture construction is outside the loop.
func BenchmarkSelfCache(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		for _, kind := range []string{"policy", "own-hostinfo"} {
			b.Run(fmt.Sprintf("nodes=%d/%s", n, kind), func(b *testing.B) {
				s, streams := scalingTailnet(b, n, "users")
				st := streams[0]
				policy := strings.TrimSuffix(scalingPolicies["users"], "}") + `,"nodeAttrs":[{"target":["*"],"attr":["custom:self"]}]}`
				_, err := s.SetPolicy([]byte(policy))
				require.NoError(b, err)

				for _, stream := range streams {
					_, err := stream.Update(s.Snapshot())
					require.NoError(b, err)
					stream.Delivered()
				}

				i, renders := 0, 0

				for b.Loop() {
					if kind == "policy" {
						p := strings.ReplaceAll(policy, ":*", fmt.Sprintf(":%d", 443+i%2))
						_, err := s.SetPolicy([]byte(p))
						require.NoError(b, err)
					} else {
						node := mustNode(b, s, st.nodeID).AsStruct()
						node.Hostinfo = &tailcfg.Hostinfo{Hostname: fmt.Sprintf("self-%d", i)}
						s.PutNodeInStoreForTest(*node)
					}

					updated := streams[:1]
					if kind == "policy" {
						updated = streams
					}

					for _, stream := range updated {
						before := stream.sent.self
						_, err := stream.Update(s.Snapshot())
						require.NoError(b, err)
						stream.Delivered()

						if before != stream.sent.self {
							renders++
						}
					}

					i++
				}

				b.ReportMetric(float64(renders)/float64(i), "self-renders/op")
			})
		}
	}
}

func TestStreamCapabilityVersionLifetime(t *testing.T) {
	for _, mode := range []string{"advance", "release"} {
		t.Run(mode, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, ownUserOnly)
			hub := NewHub()
			t.Cleanup(hub.Close)
			st := NewStream(cfg, hub, ids[0], capVer)
			old := func() weak.Pointer[byte] {
				capability := "custom:retained-" + strings.Repeat("x", 64<<10)
				policy := strings.TrimSuffix(ownUserOnly, "}") + fmt.Sprintf(`,"nodeAttrs":[{"target":[%q],"attr":[%q]}]}`, mustNode(t, s, ids[2]).IPs()[0].String(), capability)
				_, err := s.SetPolicy([]byte(policy))
				require.NoError(t, err)
				_, err = st.Initial(s.Snapshot())
				require.NoError(t, err)
				st.Delivered()

				caps := s.Snapshot().Policy().NodeCapMaps()[ids[2]]
				require.Len(t, caps, 1)

				for name := range caps {
					// Track the allocated string behind an invisible node's cap key.
					return weak.Make(unsafe.StringData(string(name)))
				}

				return weak.Pointer[byte]{}
			}()

			_, err := s.SetPolicy([]byte(ownUserOnly))
			require.NoError(t, err)
			hub.advance(s.Snapshot())
			active := NewStream(cfg, hub, ids[1], capVer)
			_, err = active.Initial(s.Snapshot())
			require.NoError(t, err)
			active.Delivered()
			runtime.GC()
			require.NotNil(t, old.Value(), "an idle stream retains its capability version")

			if mode == "advance" {
				_, err = st.Update(s.Snapshot())
				require.NoError(t, err)
				st.Delivered()
			} else {
				st = nil
			}

			require.Eventually(t, func() bool {
				runtime.GC()
				return old.Value() == nil
			}, 30*time.Second, 10*time.Millisecond, "advancing or releasing the stream must release old capability data")
			runtime.KeepAlive(st)
			runtime.KeepAlive(active)
			runtime.KeepAlive(s)
		})
	}
}

func TestStreamDoesNotRetainObsoletePolicy(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	hub := NewHub()
	t.Cleanup(hub.Close)
	st := NewStream(cfg, hub, ids[0], capVer)
	old := func() weak.Pointer[policyv2.PolicyManager] {
		pm, ok := s.Snapshot().Policy().(*policyv2.PolicyManager)
		require.True(t, ok)

		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		st.Delivered()

		return weak.Make(pm)
	}()
	// An invisible enrollment recompiles policy without waking this stream.
	u2 := mustNode(t, s, ids[2]).User().AsStruct()
	n := s.DB().CreateRegisteredNodeForTest(u2, "unrelated-enrollment")
	s.PutNodeInStoreForTest(*n)
	hub.advance(s.Snapshot())
	pm, ok := s.Snapshot().Policy().(*policyv2.PolicyManager)
	require.True(t, ok)

	current := weak.Make(pm)
	require.NotEqual(t, old, current)
	require.Eventually(t, func() bool {
		runtime.GC()
		return old.Value() == nil
	}, 30*time.Second, 10*time.Millisecond, "idle stream must not own an obsolete compiled policy")
	require.NotNil(t, current.Value(), "live world must retain its current policy")
	runtime.KeepAlive(st)
	runtime.KeepAlive(s)
}

func TestRoutedCandidatesAfterElectionCollection(t *testing.T) {
	s, streams := scalingTailnet(t, 30, "via")
	st := streams[1]
	old := st.r.routedVia
	winner := streams[0].nodeID
	require.NoError(t, s.Disconnect(winner, mustNode(t, s, winner).SessionEpoch()))
	s.Connect(winner)
	st.hub.advance(s.Snapshot())
	require.NotEqual(t, old, weak.Make(s.Snapshot().ViaElection()), "fixture must move the election binding")
	require.Eventually(t, func() bool {
		runtime.GC()
		return old.Value() == nil
	}, 30*time.Second, 10*time.Millisecond, "streams must not retain the old election binding")

	snap := s.Snapshot()
	got := st.r.routedCandidates(snap, mustNode(t, s, st.nodeID), st.r.lastKey, false)
	want := []tailcfg.NodeID{winner.NodeID(), streams[10].nodeID.NodeID()}
	require.ElementsMatch(t, want, got, "collected history must include exactly the losing and gaining routers")
}

// TestHubRouteAudit runs the hub's route audit on live sessions: after
// each commit routed to fewer than every session it renders afresh each
// session routing did not wake that rendered since its last wake. Sessions
// that took every wake pass. One left holding a map from before a change
// that reached it, as a dropped wake would leave it, fails at the next
// commit it is not woken for.
func TestHubRouteAudit(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	cfg, s, ids := streamTestState(t, ownUserOnly)

	h := NewHub()
	t.Cleanup(h.Close)
	h.Watch(s)

	streams := map[types.NodeID]*Stream{}
	sessions := map[types.NodeID]*Session{}

	for _, id := range ids {
		sessions[id] = h.Join(id, func() {})
		streams[id] = NewStream(cfg, h, id, capVer)
		streams[id].Attach(sessions[id])

		_, err := streams[id].Initial(s.Snapshot())
		require.NoError(t, err)
		streams[id].Delivered()
	}

	// settle waits for the hub to route the latest commit and brings the
	// woken sessions to it, as their poll loops would.
	settle := func(runs uint64) {
		t.Helper()

		require.Eventually(t, func() bool { return RouteAuditRuns() >= runs }, 5*time.Second, time.Millisecond)

		for _, id := range ids {
			select {
			case <-sessions[id].Wakes():
				_, err := streams[id].Update(s.Snapshot())
				require.NoError(t, err)
				streams[id].Delivered()
			default:
			}
		}
	}

	failures := RouteAuditFailures()

	// Only n2 sees n2: the sessions of n1 and n1b are not woken, and are
	// audited.
	runs := RouteAuditRuns()

	scalingEndpoint(t, s, ids[2], 1)
	settle(runs + 2)

	stale := streams[ids[0]].sent

	runs = RouteAuditRuns()

	scalingEndpoint(t, s, ids[1], 2)
	settle(runs + 1)
	require.Equal(t, failures, RouteAuditFailures(), "sessions that took every wake hold fresh maps")

	// Integration runs fail on the line the audit logs, so it is what is
	// checked, and kept out of this test's output.
	logged := tapLog(t)

	sessions[ids[0]].sent.Store(&sentRecord{nm: stale, rev: s.Snapshot().Rev(), cfg: cfg, capVer: capVer})

	scalingEndpoint(t, s, ids[2], 3)
	require.Eventually(t, func() bool { return RouteAuditFailures() > failures }, 5*time.Second, time.Millisecond,
		"a session holding a map without n1b's endpoint is stale")
	// The audit counts the failure before it logs it.
	require.Eventually(t, func() bool { return strings.Contains(logged(), "policy audit: route") },
		5*time.Second, time.Millisecond, "the failure is logged")
}

// TestHubRouteAuditCoversCoalescedCommits audits a change routed across
// two commits, as the hub routes them under load: the sessions it does not
// wake are rendered afresh like those of a single commit.
func TestHubRouteAuditCoversCoalescedCommits(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	cfg, s, ids := streamTestState(t, ownUserOnly)
	h := NewHub()

	for _, id := range ids {
		st := NewStream(cfg, h, id, capVer)
		st.Attach(h.Join(id, func() {}))

		_, err := st.Initial(s.Snapshot())
		require.NoError(t, err)
		st.Delivered()
	}

	before := s.Snapshot()
	scalingEndpoint(t, s, ids[2], 1)
	scalingEndpoint(t, s, ids[2], 2)
	after := s.Snapshot()
	require.Greater(t, after.Rev(), before.Rev()+1, "test sanity: the commits coalesce")

	all, wake := Route(before, after, after.Since(before))
	require.False(t, all, "test sanity: node writes alone wake their viewers")

	runs, failures := RouteAuditRuns(), RouteAuditFailures()

	h.wakeAt(all, wake, after.Rev())
	h.auditRoutes(after, wake)

	assert.Equal(t, runs+uint64(len(ids)-len(wake)), RouteAuditRuns(), "every session not woken was rendered afresh") //nolint:gosec // a handful
	assert.Equal(t, failures, RouteAuditFailures())
}

// handHub is a hub routed by hand: sessions render the snapshots a test
// hands them, at the points it chooses, and routings deliver their wakes.
type handHub struct {
	t        *testing.T
	cfg      *types.Config
	s        *state.State
	h        *Hub
	u1       *types.User
	streams  map[types.NodeID]*Stream
	sessions map[types.NodeID]*Session
}

// newHandHub is u1's two nodes, which see each other, and u2's node, which
// sees itself, under [ownUserOnly], each with a session that rendered its
// first map; more makes that many more nodes of u1 with sessions.
func newHandHub(t *testing.T, more int) (*handHub, [3]types.NodeID) {
	t.Helper()

	cfg, s, ids := streamTestState(t, ownUserOnly)

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	hh := &handHub{t: t, cfg: cfg, s: s, h: NewHub(), u1: u1, streams: map[types.NodeID]*Stream{}, sessions: map[types.NodeID]*Session{}}

	for _, id := range ids {
		hh.open(id)
	}

	for i := range more {
		hh.open(hh.addNode(fmt.Sprintf("more-%d", i)))
	}

	return hh, ids
}

// addNode registers a node of u1, which u1's nodes see.
func (hh *handHub) addNode(name string) types.NodeID {
	n := hh.s.CreateRegisteredNodeForTest(hh.u1, name)
	n.User = hh.u1
	hh.s.PutNodeInStoreForTest(*n)

	return n.ID
}

// open opens a session of id and renders its first map.
func (hh *handHub) open(id types.NodeID) {
	hh.t.Helper()

	st := hh.attach(id)

	_, err := st.Initial(hh.s.Snapshot())
	require.NoError(hh.t, err)
	st.Delivered()
}

// attach opens a new session of id, its first map the test's to render;
// it replaces the node's session the test holds.
func (hh *handHub) attach(id types.NodeID) *Stream {
	st := NewStream(hh.cfg, hh.h, id, capVer)
	sess := hh.h.Join(id, func() {})
	st.Attach(sess)

	hh.streams[id], hh.sessions[id] = st, sess

	return st
}

// render renders id's session from snap.
func (hh *handHub) render(id types.NodeID, snap *state.Snapshot) {
	hh.t.Helper()

	_, err := hh.streams[id].Update(snap)
	require.NoError(hh.t, err)
	hh.streams[id].Delivered()
}

// route routes from last to snap as the watcher does and wakes what it
// reaches; it returns that.
func (hh *handHub) route(last, snap *state.Snapshot) map[types.NodeID]struct{} {
	all, wake := hubWake(hh.h, last, snap)
	hh.h.wake(all, wake)

	return wake
}

// settled renders every session woken, from the latest snapshot, until
// none is, without routing, then holds every session to a fresh render of
// that snapshot.
func (hh *handHub) settled(why string) {
	hh.t.Helper()

	for woke := true; woke; {
		woke = false

		for id, sess := range hh.sessions {
			select {
			case <-sess.Wakes():
				hh.render(id, hh.s.Snapshot())

				woke = true
			default:
			}
		}
	}

	fresh := hh.s.Snapshot().Uncached()

	for id, st := range hh.streams {
		out, err := freshDiff(hh.cfg, fresh, id, capVer, st.sent, &versionCache{})
		require.NoError(hh.t, err)
		require.Emptyf(hh.t, out, "%s: node %d holds a stale map: %s", why, id, describeResponses(out))
	}
}

// transient has a node of u1 join, returns the snapshot holding it, and
// has it leave.
func (hh *handHub) transient(name string) *state.Snapshot {
	id := hh.addNode(name)
	mid := hh.s.Snapshot()
	hh.s.DeleteNodeFromStoreForTest(id)

	return mid
}

// TestHubWakesSessionsRenderedBetweenCoalescedCommits pins how the hub
// routes commits that coalesced: their two ends are compared, which is
// exact for a session holding the first end's render; a session that
// rendered a snapshot in between is woken again when the change from that
// snapshot reaches it, by the routing if its render ended first and at
// once if the routing went first; a session woken but not yet rendering is
// not woken again, since what it takes is at least as new. A node that
// joins and leaves between two routings is the case only these wakes
// reach: neither end has it, so neither end's viewers are its viewers.
func TestHubWakesSessionsRenderedBetweenCoalescedCommits(t *testing.T) {
	hh, ids := newHandHub(t, 0)
	s := hh.s

	start := s.Snapshot()
	hh.route(start, start)

	mid := hh.transient("transient")
	end := s.Snapshot()
	require.Greater(t, end.Rev(), start.Rev()+1, "test sanity: the commits coalesce")

	hh.render(ids[0], mid)

	all, wake := Route(start, end, end.Since(start))
	require.False(t, all, "coalesced commits are not woken wholesale")
	require.NotContains(t, wake, ids[0], "test sanity: comparing the ends alone leaves it out")

	wake = hh.route(start, end)
	assert.Contains(t, wake, ids[0], "the session that rendered in between is woken")

	for _, id := range ids[1:] {
		assert.NotContains(t, wake, id, "a session holding the first end's render, which equals the last's, is not woken")
	}

	hh.settled("rendered in between")

	// Woken and not yet rendering: not woken again by a routing over
	// coalesced commits, whatever they were.
	from := s.Snapshot()
	scalingEndpoint(t, s, ids[1], 1)

	woken := hh.route(from, s.Snapshot())
	require.Contains(t, woken, ids[0], "test sanity: the endpoint write of ids[1] wakes ids[0]")

	from = s.Snapshot()
	scalingEndpoint(t, s, ids[2], 1)
	scalingEndpoint(t, s, ids[2], 2)

	wake = hh.route(from, s.Snapshot())
	assert.NotContains(t, wake, ids[0], "a session woken that has not taken a snapshot is not woken again")
	hh.settled("woken before")

	// A client reconnecting: its new session's first map is of a snapshot
	// holding a node that joins and leaves, and ends after the routing over
	// both, which nothing in it names: the render itself asks.
	from = s.Snapshot()
	mid = hh.transient("transient-again")
	hh.route(from, s.Snapshot())

	again := hh.attach(ids[1])
	_, err := again.Initial(mid)
	require.NoError(t, err)
	again.Delivered()
	require.Len(t, hh.sessions[ids[1]].wakes, 1, "a first map of a snapshot a routing went past is woken again")

	hh.settled("reconnected")
}

// TestHubRoutesALateReadInTheFormServed routes a session that took a
// snapshot when woken for its own form flip, and cuts its filter from it
// only after the hub routed the next commit: a document edit that changes
// which selectors or grants there are. Its node held a cut of its other
// form alone there, which says nothing of the one it is served. The
// session must end holding what a fresh render of the edit gives, and the
// filters must name it themselves, whatever else wakes it. A merge position
// moved by an inserted grant reorders the address form, which the wire
// shows only for a whole filter; a member removed from a via grant takes
// away the access a router's address form gives, and route viewers woken
// wholesale (overwake/route-viewers) wake its router too.
func TestHubRoutesALateReadInTheFormServed(t *testing.T) {
	t.Setenv(state.TestFilterChunksEnv, "false")

	route := netip.MustParsePrefix("10.0.0.0/24")

	viaDoc := func(members, extra string) string {
		return fmt.Sprintf(`{"groups": {"group:g": [%s]}, "tagOwners": {"tag:r": ["u1@"]},
		"grants": [{"src": ["u1@"], "dst": ["u1@"], "ip": ["*"]}, {"src": ["u2@"], "dst": ["u2@"], "ip": ["*"]},
			{"src": ["u2@"], "dst": ["tag:r"], "ip": ["tcp:22"]}%s,
			{"src": ["group:g"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`, members, extra)
	}

	for _, tc := range []struct {
		name string
		// router makes the flipping node a tag:r router of route, not yet
		// announcing it; else it is u1's first node.
		router bool
		flip   func(*tailcfg.Hostinfo)
		// docs are the document at the start, the one committed with the
		// flip ("" for none) and the edit.
		docs [3]string
	}{
		{
			name: "merge position",
			flip: func(hi *tailcfg.Hostinfo) { hi.AppConnector.Set(true) },
			docs: [3]string{
				`{"grants": [{"src": ["u1@"], "dst": ["u1@"], "ip": ["tcp:22"]}, {"src": ["u2@"], "dst": ["u1@"], "ip": ["tcp:22"]}]}`,
				"",
				`{"grants": [{"src": ["u2@"], "dst": ["u2@"], "ip": ["tcp:22"]},
					{"src": ["u1@"], "dst": ["u1@"], "ip": ["tcp:22"]}, {"src": ["u2@"], "dst": ["u1@"], "ip": ["tcp:22"]}]}`,
			},
		},
		{
			name:   "via member removed",
			router: true,
			flip:   func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{route} },
			docs: [3]string{
				viaDoc(`"u1@", "u2@"`, ""),
				viaDoc(`"u1@", "u2@"`, `, {"src": ["u1@"], "dst": ["u1@"], "ip": ["tcp:22"]}`),
				viaDoc(`"u1@"`, ""),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, tc.docs[0], func(cfg *types.Config) { cfg.Policy.CapabilitySources = true })

			u1, err := s.GetUserByName("u1")
			require.NoError(t, err)

			hh := &handHub{t: t, cfg: cfg, s: s, h: NewHub(), u1: u1, streams: map[types.NodeID]*Stream{}, sessions: map[types.NodeID]*Session{}}

			official := func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{GoVersion: runtime.Version(), IPNVersion: version.Long()}
			}

			for _, id := range ids {
				n, ok := s.GetNodeByID(id)
				require.True(t, ok)

				nn := n.AsStruct()
				official(nn)
				s.PutNodeInStoreForTest(*nn)
			}

			all, x := ids[:], ids[0]

			if tc.router {
				router := s.CreateRegisteredNodeForTest(u1, "router")
				router.Tags = []string{"tag:r"}
				router.UserID, router.User = nil, nil
				router.ApprovedRoutes = []netip.Prefix{route}
				official(router)
				s.PutNodeInStoreForTest(*router)

				x = router.ID
				all = append(all, x)
			}

			for _, id := range all {
				hh.open(id)
			}

			// Every session reads the snapshot routed from, as the next
			// routing compares from it.
			start := s.Snapshot()
			hh.route(start, start)
			hh.settled("start")

			for _, id := range all {
				hh.render(id, start)
			}

			n, ok := s.GetNodeByID(x)
			require.True(t, ok)

			nn := n.AsStruct()
			nn.Hostinfo = nn.Hostinfo.Clone()
			tc.flip(nn.Hostinfo)
			s.PutNodeInStoreForTest(*nn)

			if tc.docs[1] != "" {
				_, err = s.SetPolicy([]byte(tc.docs[1]))
				require.NoError(t, err)
			}

			flipped := s.Snapshot()
			require.NotEqual(t, start.ReceiverFacts(x), flipped.ReceiverFacts(x), "test sanity: the node's form flips")
			require.Contains(t, hh.route(start, flipped), x, "test sanity: the flip wakes its session")

			// It takes the wake and the snapshot.
			<-hh.sessions[x].Wakes()

			_, err = s.SetPolicy([]byte(tc.docs[2]))
			require.NoError(t, err)

			edited := s.Snapshot()
			hh.route(flipped, edited)

			// What the routing read, before the late read cuts the form.
			filters := edited.Since(flipped).Filters

			was, err := flipped.FilterForNode(x)
			require.NoError(t, err)

			is, err := edited.Uncached().FilterForNode(x)
			require.NoError(t, err)
			require.NotEqual(t, was, is, "test sanity: the edit moves the filter it is served")

			assert.Contains(t, filters, x, "the filters name the node whose served form moved")

			hh.render(x, flipped)
			hh.settled("after the edit")
		})
	}
}

// TestHubSessionsRenderWhatReachesThemUnderChurn routes by hand, so no
// scheduling decides it: u1's two sessions are woken by two writes that
// reach them, take the wake and wait out a batch delay, as poll does, while
// writes to u2's node,
// which they cannot see, land three to a routing for fifty routings; then
// each renders a snapshot strictly between a routing's ends, once ending
// before the routing and once after it, while those writes go on. They are
// woken by nothing but the first routing: a session waiting to render is
// in no log, and a render is woken again only when what changed since its
// snapshot reaches it. No routing resyncs, which would wake everyone.
func TestHubSessionsRenderWhatReachesThemUnderChurn(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))

			hh, ids := newHandHub(t, 0)
			s, viewers := hh.s, ids[:2]

			last := s.Snapshot()
			port := 0

			churn := func(n int) {
				for range n {
					port++
					scalingEndpoint(t, s, ids[2], port)
				}
			}

			route := func() map[types.NodeID]struct{} {
				t.Helper()

				now := s.Snapshot()
				change, all, wake, _ := hh.h.route(last, now)
				require.False(t, change.Resync, "test sanity: the node log covers the routing")
				require.False(t, all)

				hh.h.wake(all, wake)

				last = now

				return wake
			}

			woken := func() int {
				n := 0
				for _, id := range viewers {
					n += len(hh.sessions[id].wakes)
				}

				return n
			}

			scalingEndpoint(t, s, ids[1], 1)
			scalingEndpoint(t, s, ids[1], 2)

			wake := route()
			for _, id := range viewers {
				require.Contains(t, wake, id, "test sanity: the writes reach u1's sessions")
			}

			// As poll does, each takes its wake and waits out the delay
			// before it takes a snapshot.
			for _, id := range viewers {
				<-hh.sessions[id].wakes
			}

			for range 50 {
				churn(3)
				route()
				require.Zero(t, woken(), "a session waiting to render is not woken again")
			}

			for _, id := range viewers {
				hh.render(id, s.Snapshot())
			}

			// A render of a snapshot between a routing's ends, ending before
			// the routing, then one ending after it.
			for _, id := range viewers {
				churn(1)

				x := s.Snapshot()

				churn(2)
				hh.render(id, x)
				route()
				churn(1)

				x = s.Snapshot()

				churn(2)
				route()
				hh.render(id, x)
			}

			require.Zero(t, woken(), "nothing the sessions cannot see woke them again")
			hh.settled("after the churn")
		})
	}
}

// TestHubRenderLogCases drives the render log by hand at the points its
// argument rests on, each session finally held to a fresh render.
func TestHubRenderLogCases(t *testing.T) {
	t.Run("woken while rendering", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		// ids[0] takes mid; the routing over the node's coming and going
		// and an endpoint write of ids[1] wakes it while it renders mid.
		from := s.Snapshot()
		mid := hh.transient("transient")

		scalingEndpoint(t, s, ids[1], 1)

		wake := hh.route(from, s.Snapshot())
		require.Contains(t, wake, ids[0], "test sanity: the endpoint write reaches ids[0]")

		hh.render(ids[0], mid)
		require.Len(t, hh.sessions[ids[0]].wakes, 1, "the wake that came during the render is pending")
		hh.settled("woken while rendering")
	})

	t.Run("a render a routing went past", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		// The routing's ends are equal and name nobody; ids[0]'s render of
		// mid ends after it, so the render asks.
		from := s.Snapshot()
		mid := hh.transient("transient")

		wake := hh.route(from, s.Snapshot())
		require.NotContains(t, wake, ids[0])

		hh.render(ids[0], mid)
		require.Len(t, hh.sessions[ids[0]].wakes, 1, "a render of a snapshot a routing went past, which the rest reaches, is woken")
		hh.settled("a routing went past")
	})

	t.Run("woken by a wake-all while rendering", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		from := s.Snapshot()
		mid := hh.transient("transient")

		hubWake(hh.h, from, s.Snapshot())
		hh.h.wake(true, nil)
		hh.render(ids[0], mid)
		require.Len(t, hh.sessions[ids[0]].wakes, 1, "the wake-all is pending")
		hh.settled("wake-all")
	})

	t.Run("a first map records the snapshot it rendered", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		a := s.Snapshot()
		hh.route(a, a)

		// ids[0] renders b, a snapshot holding a node that then leaves: the
		// hub's latest is b, which a first map handed a renders instead.
		id := hh.addNode("transient")
		b := s.Snapshot()
		hh.render(ids[0], b)
		s.DeleteNodeFromStoreForTest(id)
		c := s.Snapshot()

		hh.route(a, c)

		st := hh.attach(ids[1])
		_, err := st.Initial(a)
		require.NoError(t, err)
		st.Delivered()

		_, holds := st.sent.peer(id.NodeID())
		require.True(t, holds, "test sanity: the first map is of b, which holds the node")
		require.Len(t, hh.sessions[ids[1]].wakes, 1, "the first map is weighed by the snapshot it rendered")
		hh.settled("first map")
	})

	t.Run("a first map between a routing and the caches' advance", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		from := s.Snapshot()
		mid := hh.transient("transient")
		to := s.Snapshot()

		hubWake(hh.h, from, to)

		st := hh.attach(ids[1])
		_, err := st.Initial(mid)
		require.NoError(t, err)
		st.Delivered()
		hh.h.advance(to)

		hh.settled("first map before the advance")
	})

	t.Run("a render newer than the routing in progress", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		from := s.Snapshot()
		scalingEndpoint(t, s, ids[2], 1)
		to := s.Snapshot()

		// to+1: a node joins after the hub took to.
		id := hh.addNode("transient")
		next := s.Snapshot()
		require.Equal(t, to.Rev()+1, next.Rev(), "test sanity: the render is of to+1")

		hh.render(ids[0], next)
		hh.route(from, to)

		s.DeleteNodeFromStoreForTest(id)

		wake := hh.route(to, s.Snapshot())
		assert.Contains(t, wake, ids[0], "a render past the routing is kept for the next")
		hh.settled("newer than the routing")
	})

	t.Run("a render of from+1 in every shard", func(t *testing.T) {
		hh, ids := newHandHub(t, renderShards)
		s := hh.s

		// u1's nodes, one per shard: they see the node that joins.
		shards := map[*renderShard]types.NodeID{}

		for id, sess := range hh.sessions {
			if id != ids[2] {
				shards[hh.h.renders.shard(sess)] = id
			}
		}

		require.Len(t, shards, renderShards, "test sanity: a session in every shard")

		from := s.Snapshot()
		mid := hh.transient("transient")
		require.Equal(t, from.Rev()+1, mid.Rev(), "test sanity: the render is of from+1")

		for _, id := range shards {
			hh.render(id, mid)
		}

		wake := hh.route(from, s.Snapshot())

		for _, id := range shards {
			assert.Contains(t, wake, id, "every shard's render in between is weighed")
		}

		hh.settled("every shard")
	})

	t.Run("a routing at the point the render decides", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		from := s.Snapshot()
		mid := hh.transient("transient")
		to := s.Snapshot()

		// The routing runs where end has decided, if the shard's lock lets
		// it: it must not, or it must be seen.
		sh := hh.h.renders.shard(hh.sessions[ids[0]])
		routed := false
		hh.h.renders.hook = func(p renderPoint, _ *renderShard) {
			if p == renderDecided && !routed && sh.mu.TryLock() {
				sh.mu.Unlock()
				hh.route(from, to)

				routed = true
			}
		}

		hh.render(ids[0], mid)
		hh.h.renders.hook = nil

		if !routed {
			hh.route(from, to)
		}

		hh.settled("routed at the decision")
	})

	t.Run("a render ending where a routing drained its shard", func(t *testing.T) {
		hh, ids := newHandHub(t, 0)
		s := hh.s

		from := s.Snapshot()
		mid := hh.transient("transient")
		to := s.Snapshot()

		// The render ends where the routing has visited the session's shard,
		// if the shard's lock lets it: it must not, or the render must be
		// weighed.
		sh := hh.h.renders.shard(hh.sessions[ids[0]])
		rendered := false
		hh.h.renders.hook = func(p renderPoint, at *renderShard) {
			if p == routingDrained && at == sh && !rendered && sh.mu.TryLock() {
				sh.mu.Unlock()
				hh.render(ids[0], mid)

				rendered = true
			}
		}

		hh.route(from, to)
		hh.h.renders.hook = nil

		if !rendered {
			hh.render(ids[0], mid)
		}

		hh.settled("rendered at the drain")
	})
}

// TestViewDeltaKeysViewsByStartAndLength pins what names a view in the
// view walks sessions share: its first element's address and its length.
// The views the peer classes build never share a first element while
// differing in length, so no other test tells a key without the length
// apart; two views cut from one array do share it.
func TestViewDeltaKeysViewsByStartAndLength(t *testing.T) {
	var cm classMaps

	all := []types.NodeID{1, 2, 3, 4}
	short, long := all[:2], all[:3]
	to := []types.NodeID{1, 2, 3, 4}

	assert.Equal(t, []tailcfg.NodeID{3, 4}, cm.viewDelta(short, to))
	assert.Equal(t, []tailcfg.NodeID{4}, cm.viewDelta(long, to), "a view sharing another's start but not its length is another view")
	assert.Equal(t, []tailcfg.NodeID{1, 2, 3, 4}, cm.viewDelta(nil, to))
	assert.Empty(t, cm.viewDelta(to, to))
}

// hubWake is [Hub.route]'s sessions to wake, as the watcher wakes them.
func hubWake(h *Hub, last, snap *state.Snapshot) (bool, map[types.NodeID]struct{}) {
	_, all, wake, _ := h.route(last, snap)

	return all, wake
}

// TestHubWakesSessionAfterFailedRender pins that a session whose render
// failed is woken by the next routing, whatever that routing names: it
// holds what it held before, which no routing describes, and only a new
// snapshot can render otherwise; and one whose render fails after a
// routing went past its snapshot is woken at once, the next commit already
// there. Its node's given name is one no FQDN can be made of, as a corrupt
// row loads, so its own map cannot render; once the node is renamed, its
// next render holds what a fresh one gives, and it is woken for nothing
// more.
func TestHubWakesSessionAfterFailedRender(t *testing.T) {
	// u2's node sees only itself: its endpoint writes name no other node.
	cfg, s, ids := streamTestState(t, ownUserOnly)
	h := NewHub()

	st := NewStream(cfg, h, ids[0], capVer)
	sess := h.Join(ids[0], func() {})
	st.Attach(sess)

	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	start := s.Snapshot()
	hubWake(h, start, start)

	node := mustNode(t, s, ids[0]).AsStruct()
	name := node.GivenName
	node.GivenName = strings.Repeat("a", types.MaxHostnameLength+1)
	s.PutNodeInStoreForTest(*node)

	broken := s.Snapshot()
	_, wake := hubWake(h, start, broken)
	require.Contains(t, wake, ids[0], "test sanity: its own change wakes it")

	_, err = st.Update(broken)
	require.ErrorIs(t, err, types.ErrHostnameTooLong, "test sanity: its map cannot render")

	for i := range 2 {
		was := s.Snapshot()
		scalingEndpoint(t, s, ids[2], i+1)
		is := s.Snapshot()

		_, routed := Route(was, is, is.Since(was))
		require.NotContains(t, routed, ids[0], "test sanity: the write names only u2's node")

		_, wake = hubWake(h, was, is)
		assert.Contains(t, wake, ids[0], "a session whose render failed is woken by the next routing")

		_, err = st.Update(is)
		require.Error(t, err, "test sanity: it still cannot render")
	}

	// The render takes y; a routing past y names it not; the render fails.
	y := s.Snapshot()
	hubWake(h, y, y)
	scalingEndpoint(t, s, ids[2], 3)
	_, wake = hubWake(h, y, s.Snapshot())
	require.NotContains(t, wake, ids[0])

	_, err = st.Update(y)
	require.Error(t, err)
	assert.Len(t, sess.wakes, 1, "a render failing after a routing went past its snapshot is retried at once")

	select {
	case <-sess.wakes:
	default:
	}

	was := s.Snapshot()
	node.GivenName = name
	s.PutNodeInStoreForTest(*node)

	fixed := s.Snapshot()
	_, wake = hubWake(h, was, fixed)
	require.Contains(t, wake, ids[0])

	_, err = st.Update(fixed)
	require.NoError(t, err)
	st.Delivered()

	out, err := freshDiff(cfg, fixed.Uncached(), ids[0], capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, out, "once it renders, it holds what a fresh render gives")

	scalingEndpoint(t, s, ids[2], 4)
	_, wake = hubWake(h, fixed, s.Snapshot())
	assert.NotContains(t, wake, ids[0], "a session that rendered is not woken for a write it renders nothing of")
}

// logSink is where the package's tests log. A test that reads the hub's
// lines taps it: swapping the global logger would race with the hub's
// watcher, which logs from its own goroutine.
var logSink = &tapWriter{}

func TestMain(m *testing.M) {
	log.Logger = zerolog.New(logSink).With().Timestamp().Logger()

	m.Run()
}

// tapWriter writes to stderr, or to the writer a test taps it with.
type tapWriter struct {
	mu  sync.Mutex
	tap io.Writer
}

func (w *tapWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.tap != nil {
		return w.tap.Write(p)
	}

	return os.Stderr.Write(p)
}

// tapTo sends what is logged until the test ends to w instead of stderr.
// w is written under the sink's lock.
func tapTo(t *testing.T, w io.Writer) {
	t.Helper()

	logSink.mu.Lock()
	logSink.tap = w
	logSink.mu.Unlock()

	t.Cleanup(func() {
		logSink.mu.Lock()
		logSink.tap = nil
		logSink.mu.Unlock()
	})
}

// tapLog keeps what is logged until the test ends out of its output and
// returns a reader of it.
func tapLog(t *testing.T) func() string {
	t.Helper()

	var buf bytes.Buffer

	tapTo(t, &buf)

	return func() string {
		logSink.mu.Lock()
		defer logSink.mu.Unlock()

		return buf.String()
	}
}

// routerOf makes id a tag:r router serving route, online.
func routerOf(t *testing.T, s *state.State, id types.NodeID, route netip.Prefix) {
	t.Helper()

	taggedRouterOf(t, s, id, "tag:r", route)
}

// taggedRouterOf makes id a router of tag serving route, online.
func taggedRouterOf(t *testing.T, s *state.State, id types.NodeID, tag string, route netip.Prefix) {
	t.Helper()

	_, err := s.SetNodeTags(id, []string{tag})
	require.NoError(t, err)

	n := mustNode(t, s, id).AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	s.PutNodeInStoreForTest(*n)

	_, err = s.SetApprovedRoutes(id, []netip.Prefix{route})
	require.NoError(t, err)

	s.Connect(id)
}

// joinAt registers a node of user, as the random writes add one, at addr.
func joinAt(t *testing.T, s *state.State, user, name string, addr netip.Addr) types.NodeID {
	t.Helper()

	u, err := s.GetUserByName(user)
	require.NoError(t, err)

	n := s.CreateRegisteredNodeForTest(u, name)
	n.User, n.IPv4 = u, &addr
	s.PutNodeInStoreForTest(*n)

	return n.ID
}

// serve has id announce and approve routes, online, keeping its owner.
func serve(t *testing.T, s *state.State, id types.NodeID, routes ...netip.Prefix) {
	t.Helper()

	n := mustNode(t, s, id).AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
	s.PutNodeInStoreForTest(*n)

	_, err := s.SetApprovedRoutes(id, routes)
	require.NoError(t, err)

	s.Connect(id)
}

// TestRouteWakesTheNodesThatSeeAChangedNode pins that a write of a node
// wakes the nodes that see it, which visibility does not make the nodes it
// sees: an exit node sees every source of a capability grant whose
// destination reaches the internet, to host the service, and the source
// does not see the exit node. An endpoint write of the source must reach
// the exit node's session.
func TestRouteWakesTheNodesThatSeeAChangedNode(t *testing.T) {
	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))

			cfg, s, ids := streamTestState(t, `{"grants":[{"src":["u2@"],"dst":["8.8.8.0/24"],"app":{"example.com/cap/x":[{}]}}]}`)
			exit, src := ids[0], ids[2]

			serve(t, s, exit, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))

			before := s.Snapshot()
			require.Contains(t, before.PeerView(exit), src, "test sanity: the exit node sees the grant's source")
			require.NotContains(t, before.PeerView(src), exit, "test sanity: the source does not see the exit node")

			st := NewStream(cfg, NewHub(), exit, capVer)
			_, err := st.Initial(before)
			require.NoError(t, err)
			st.Delivered()

			scalingEndpoint(t, s, src, 1)

			after := s.Snapshot()
			all, wake := Route(before, after, after.Since(before))
			require.False(t, all)
			assert.Contains(t, wake, exit, "the exit node sees the written node")

			out, err := freshDiff(cfg, after.Uncached(), exit, capVer, st.sent, &versionCache{})
			require.NoError(t, err)
			require.NotEmpty(t, out, "test sanity: the exit node's map moved with the write")
		})
	}
}

// TestRouteWakesViewerOfRouterWhoseCoverMovedByPolicy moves a node into a
// group by a document edit, not a write: X, inside R's route, becomes a
// destination of V's rule to the group, so V may use R's route. V's filter,
// peers, side set and facts are as they were, and X is no node write, so
// nothing wakes V but its seeing R, whose cover moved.
func TestRouteWakesViewerOfRouterWhoseCoverMovedByPolicy(t *testing.T) {
	const doc = `{"groups":{"group:g":%s},"tagOwners":{"tag:r":["u1@"],"tag:m":["u1@"]},"acls":[
		{"action":"accept","src":["u2@"],"dst":["tag:r:*","tag:m:*","group:g:*"]}]}`

	cfg, s, ids := streamTestState(t, fmt.Sprintf(doc, `[]`))
	router, viewer := ids[0], ids[2]

	inside := netip.MustParsePrefix("100.64.0.8/29")
	routerOf(t, s, router, inside)

	// u1's other node joins no group.
	_, err := s.SetNodeTags(ids[1], []string{"tag:m"})
	require.NoError(t, err)

	x := joinAt(t, s, "u1", "x", netip.MustParseAddr("100.64.0.9"))
	serve(t, s, x, netip.MustParsePrefix("100.64.0.16/29"))

	m := joinAt(t, s, "u1", "m", netip.MustParseAddr("100.64.0.17"))
	_, err = s.SetNodeTags(m, []string{"tag:m"})
	require.NoError(t, err)

	st := NewStream(cfg, NewHub(), viewer, capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	held, ok := st.sent.peer(router.NodeID())
	require.True(t, ok, "test sanity: the viewer sees the router")
	_, ok = st.sent.peer(x.NodeID())
	require.True(t, ok, "test sanity: and X, whose route covers M")
	require.NotContains(t, held.AllowedIPs, inside, "test sanity: no destination of the viewer's is inside the router's route yet")

	before := s.Snapshot()
	_, err = s.SetPolicy(fmt.Appendf(nil, doc, `["u1@"]`))
	require.NoError(t, err)

	after := s.Snapshot()

	c := after.Since(before)
	require.Empty(t, c.Nodes, "test sanity: no node was written")
	require.NotContains(t, c.Filters, viewer, "test sanity: the viewer's filter did not move")
	require.NotContains(t, c.PeerSets, viewer, "test sanity: nor what it sees")
	require.NotContains(t, c.RouteViewers, viewer, "test sanity: nor its side set or facts")
	require.False(t, c.AllRouters, "test sanity: nor any rule a route reads")
	require.Contains(t, c.Routers, router, "the router's route gained a destination atom")

	all, wake := Route(before, after, c)
	require.False(t, all)
	require.Contains(t, wake, viewer, "it sees the router whose cover moved")

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()

	held, _ = st.sent.peer(router.NodeID())
	assert.Contains(t, held.AllowedIPs, inside, "the viewer may use the router's route")

	stale, err := freshDiff(cfg, after.Uncached(), viewer, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestRouteRerendersRoutedPeersWhenViewerServesTheirRoute has a router also
// serve a route another router serves as primary: a viewer serving a
// primary's route is given it, whatever the rules. The viewer's side set
// and facts do not move, it already serving a route; only its own routes
// do, which its own node write wakes it for, and it must render the
// primary again.
func TestRouteRerendersRoutedPeersWhenViewerServesTheirRoute(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:r":["u1@"]},"acls":[
		{"action":"accept","src":["u2@"],"dst":["tag:r:*"]}]}`)
	primary, viewer := ids[0], ids[2]

	shared, own := netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.2.0/24")
	routerOf(t, s, primary, shared)
	serve(t, s, viewer, own)

	st := NewStream(cfg, NewHub(), viewer, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	held, ok := st.sent.peer(primary.NodeID())
	require.True(t, ok, "test sanity: the viewer sees the primary")
	require.NotContains(t, held.AllowedIPs, shared, "test sanity: no rule gives the viewer the primary's route")

	// One write, as a map request announcing what the admin approved.
	before := s.Snapshot()
	n := mustNode(t, s, viewer).AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{own, shared}}
	n.ApprovedRoutes = []netip.Prefix{own, shared}
	s.PutNodeInStoreForTest(*n)
	after := s.Snapshot()

	c := after.Since(before)
	require.NotContains(t, c.RouteViewers, viewer, "test sanity: the viewer's side set and facts did not move")
	require.Equal(t, []netip.Prefix{shared}, after.PrimaryRoutesForNode(primary), "test sanity: the primary keeps the route")

	all, wake := Route(before, after, c)
	require.False(t, all)
	require.Contains(t, wake, viewer, "its own routes moved")

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()

	held, _ = st.sent.peer(primary.NodeID())
	assert.Contains(t, held.AllowedIPs, shared, "a viewer serving the primary's route is given it")

	stale, err := freshDiff(cfg, after.Uncached(), viewer, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestRouteSSHFollowsLocalpartEmail changes a source user's email under a
// localpart SSH rule: the destinations' SSH policies map another local
// user, though no filter, side set or node moved. That reaches their
// sessions only through the compile's SSH routing, alone and coalesced
// with another write; the dependency is stated here.
func TestRouteSSHFollowsLocalpartEmail(t *testing.T) {
	for _, coalesced := range []bool{false, true} {
		t.Run(fmt.Sprintf("coalesced=%t", coalesced), func(t *testing.T) {
			cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:b":["u1@"]},
				"acls":[{"action":"accept","src":["u1@"],"dst":["u1@:*"]}],
				"ssh":[{"action":"accept","src":["u1@"],"dst":["tag:b"],"users":["localpart:*@example.com"]}]}`)
			dest, other := ids[2], ids[1]

			u1, err := s.GetUserByName("u1")
			require.NoError(t, err)

			setEmail := func(email string) {
				t.Helper()

				_, err := s.UpdateUser(types.UserID(u1.ID), func(u *types.User) error {
					u.Email = email

					return nil
				})
				require.NoError(t, err)
			}

			setEmail("alice@example.com")

			_, err = s.SetNodeTags(dest, []string{"tag:b"})
			require.NoError(t, err)

			st := NewStream(cfg, NewHub(), dest, capVer)
			_, err = st.Initial(s.Snapshot())
			require.NoError(t, err)
			st.Delivered()

			localUsers := func() []string {
				out := make([]string, 0, len(st.sent.ssh.Rules))
				for _, rule := range st.sent.ssh.Rules {
					out = append(out, slices.Collect(maps.Keys(rule.SSHUsers))...)
				}

				slices.Sort(out)

				return out
			}

			require.Contains(t, localUsers(), "alice", "test sanity: the destination maps alice")

			before := s.Snapshot()

			setEmail("bob@example.com")

			if coalesced {
				n := mustNode(t, s, other).AsStruct()
				n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
				s.PutNodeInStoreForTest(*n)
			}

			after := s.Snapshot()
			require.Equal(t, coalesced, after.Rev() > before.Rev()+1, "test sanity: the commits coalesce or not")

			c := after.Since(before)
			require.NotContains(t, c.Nodes, dest, "test sanity: the destination was not written")

			all, wake := Route(before, after, c)
			if !all {
				require.Contains(t, wake, dest, "its SSH policy moved")
			}

			_, err = st.Update(after)
			require.NoError(t, err)
			st.Delivered()

			assert.Contains(t, localUsers(), "bob", "the destination maps the new localpart")
			assert.NotContains(t, localUsers(), "alice")
		})
	}
}

// TestRouteWakesCoveringRouterAsViewer joins a node inside a router's
// route: the router is then on the joiner's side of a rule (it routes for
// an address the rule names), so it may use another router's route it
// could not before. Neither the router nor anything it sees changed, nor
// did its filter, though a moved rule recuts every router; it does not
// render the other router again but because its side set moved. It sees
// the other router and not itself, so the routers whose cover moved,
// itself among them, wake only what they are seen by.
func TestRouteWakesCoveringRouterAsViewer(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"groups":{"group:eng":["u2@"]},"tagOwners":{"tag:c":["u1@"],"tag:r":["u1@"]},"acls":[
		{"action":"accept","src":["tag:c"],"dst":["tag:r:*"]},
		{"action":"accept","src":["group:eng"],"dst":["10.1.0.0/24:*"]}]}`)
	covering, other := ids[0], ids[1]

	inside := netip.MustParsePrefix("100.64.0.8/29")
	subnet := netip.MustParsePrefix("10.1.0.0/24")

	taggedRouterOf(t, s, covering, "tag:c", inside)
	routerOf(t, s, other, subnet)

	st := NewStream(cfg, NewHub(), covering, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	held, ok := st.sent.peer(other.NodeID())
	require.True(t, ok, "test sanity: the routers see each other")
	require.NotContains(t, held.AllowedIPs, subnet, "test sanity: no rule lets the covering router use the subnet yet")

	before := s.Snapshot()
	joinAt(t, s, "u2", "inside", netip.MustParseAddr("100.64.0.9"))
	after := s.Snapshot()

	c := after.Since(before)
	require.NotContains(t, c.PeerSets, covering, "test sanity: what it sees did not move")
	require.Contains(t, c.RouteViewers, covering, "its side set moved, which the routes it is offered read")

	all, wake := Route(before, after, c)
	require.False(t, all)
	require.Contains(t, wake, covering)

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()

	held, _ = st.sent.peer(other.NodeID())
	assert.Contains(t, held.AllowedIPs, subnet, "it renders the other router again, and may use its subnet")

	stale, err := freshDiff(cfg, after.Uncached(), covering, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestRouteWakesAddressSharerAsViewer joins a member of group:eng at the
// address of X, a node of another user: a source names nodes by address, so
// X is on group:eng's side of its rule and may use the route it grants.
// X's filter, peers and node are as they were, and X is no router: nothing
// wakes it but the move of its own side set.
func TestRouteWakesAddressSharerAsViewer(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"groups":{"group:eng":["u2@"]},"tagOwners":{"tag:r":["u1@"]},"acls":[
		{"action":"accept","src":["u1@"],"dst":["tag:r:*"]},
		{"action":"accept","src":["group:eng"],"dst":["10.1.0.0/24:*"]}]}`)
	router, x := ids[0], ids[1]

	subnet := netip.MustParsePrefix("10.1.0.0/24")
	routerOf(t, s, router, subnet)

	_, err := s.SetNodeTags(ids[2], []string{"tag:r"})
	require.NoError(t, err)

	st := NewStream(cfg, NewHub(), x, capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	held, ok := st.sent.peer(router.NodeID())
	require.True(t, ok, "test sanity: X sees the router")
	require.NotContains(t, held.AllowedIPs, subnet, "test sanity: X is no member of group:eng")

	before := s.Snapshot()
	joinAt(t, s, "u2", "sharer", mustNode(t, s, x).IPv4().Get())
	after := s.Snapshot()

	c := after.Since(before)
	require.NotContains(t, c.Filters, x, "test sanity: X's filter did not move")
	require.NotContains(t, c.PeerSets, x, "test sanity: nor what it sees")
	require.Contains(t, c.RouteViewers, x, "its side set moved")

	all, wake := Route(before, after, c)
	require.False(t, all)
	require.Contains(t, wake, x)

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()

	held, _ = st.sent.peer(router.NodeID())
	assert.Contains(t, held.AllowedIPs, subnet, "X may use the route by the address it shares")

	stale, err := freshDiff(cfg, after.Uncached(), x, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestRouteRerendersRouterWhoseCoverMoved joins a node inside a router's
// route that a viewer is the destination of a rule from: the router's
// route now overlaps the rule's sources, so the viewer may use it, though
// neither the router nor the viewer changed. The viewer sees the joiner
// and is woken for it; it must render the router again too.
func TestRouteRerendersRouterWhoseCoverMoved(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"groups":{"group:eng":["u2@"]},"tagOwners":{"tag:r":["u1@"]},"acls":[
		{"action":"accept","src":["u1@"],"dst":["tag:r:*"]},
		{"action":"accept","src":["group:eng"],"dst":["u1@:*"]}]}`)
	viewer, router := ids[0], ids[1]

	inside := netip.MustParsePrefix("100.64.0.8/29")
	routerOf(t, s, router, inside)

	st := NewStream(cfg, NewHub(), viewer, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	held, ok := st.sent.peer(router.NodeID())
	require.True(t, ok, "test sanity: the viewer sees the router")
	require.NotContains(t, held.AllowedIPs, inside, "test sanity: nothing inside the route is a source of the viewer's yet")

	before := s.Snapshot()
	joinAt(t, s, "u2", "inside", netip.MustParseAddr("100.64.0.9"))
	after := s.Snapshot()

	c := after.Since(before)
	require.Contains(t, c.Routers, router, "the router's route gained a source atom")

	all, wake := Route(before, after, c)
	require.False(t, all)
	require.Contains(t, wake, viewer)

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()

	held, _ = st.sent.peer(router.NodeID())
	assert.Contains(t, held.AllowedIPs, inside, "the viewer renders the router again, and may use its route")

	stale, err := freshDiff(cfg, after.Uncached(), viewer, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestRouteWakesRouterCoveringANewDestination joins a node of a rule's
// destination inside a router's route: the router's filter lists the
// destination's members it routes for, so it gains the joiner's address,
// though it neither sees the joiner nor is named by any source that moved.
func TestRouteWakesRouterCoveringANewDestination(t *testing.T) {
	// The router sees u1's node already, through the first rule, so the
	// join moves nothing it sees.
	cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:r":["u1@"]},"acls":[
		{"action":"accept","src":["tag:r"],"dst":["u1@:*"]},
		{"action":"accept","src":["u1@"],"dst":["u2@:22"]}]}`)
	router := ids[0]

	routerOf(t, s, router, netip.MustParsePrefix("100.64.0.8/29"))

	st := NewStream(cfg, NewHub(), router, capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()

	before := s.Snapshot()
	joinAt(t, s, "u2", "inside", netip.MustParseAddr("100.64.0.9"))
	after := s.Snapshot()

	c := after.Since(before)
	require.NotContains(t, c.PeerSets, router, "test sanity: the router sees nothing new")

	all, wake := Route(before, after, c)
	require.False(t, all)
	require.Contains(t, wake, router, "its filter gained the joiner's address")

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()

	require.True(t, slices.ContainsFunc(st.sent.filter, func(r tailcfg.FilterRule) bool {
		return slices.ContainsFunc(r.DstPorts, func(d tailcfg.NetPortRange) bool { return d.IP == "100.64.0.9" })
	}), "the router is served a filter naming the joiner, not a carried one: %v", st.sent.filter)

	stale, err := freshDiff(cfg, after.Uncached(), router, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestRouteReordersFilterWhenAnotherRuleSplitsItsKey pins that merge
// positions are global in IP form. N is in tag:s and tag:s2, so the rules
// from each have one merge key and V's rule from tag:s2 sits where the
// tag:s rule does, first. N leaving tag:s splits the key: V's rule moves
// behind its rule from tag:t, though none of V's own rules' members moved
// and the tag:s rule never reached V.
func TestRouteReordersFilterWhenAnotherRuleSplitsItsKey(t *testing.T) {
	// In capability mode the receiver is sent addresses (its client is not
	// known to apply capabilities): capability form keeps each grant's rules
	// apart, so only a receiver in address form has merge positions.
	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))
			routeReordersFilter(t, capSources)
		})
	}
}

func routeReordersFilter(t *testing.T, unknownClient bool) {
	t.Helper()

	cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:s":["u1@"],"tag:s2":["u1@"],"tag:a":["u1@"],"tag:t":["u1@"],"tag:v":["u1@"]},"acls":[
		{"action":"accept","src":["tag:s"],"dst":["tag:a:22"]},
		{"action":"accept","src":["tag:t"],"dst":["tag:v:80"]},
		{"action":"accept","src":["tag:s2"],"dst":["tag:v:443"]}]}`)

	u1, err := s.GetUserByName("u1")
	require.NoError(t, err)

	n, a, src := ids[0], ids[1], ids[2]

	vn := s.CreateRegisteredNodeForTest(u1, "v")
	vn.User = u1

	if unknownClient {
		vn.Hostinfo = &tailcfg.Hostinfo{App: "tailscale-rs"}
	}

	s.PutNodeInStoreForTest(*vn)
	v := vn.ID

	for id, tags := range map[types.NodeID][]string{n: {"tag:s", "tag:s2"}, a: {"tag:a"}, src: {"tag:t"}, v: {"tag:v"}} {
		_, err := s.SetNodeTags(id, tags)
		require.NoError(t, err)
	}

	ports := func(rules []tailcfg.FilterRule) []uint16 {
		out := make([]uint16, 0, len(rules))
		for _, r := range rules {
			out = append(out, r.DstPorts[0].Ports.First)
		}

		return out
	}

	st := NewStream(cfg, NewHub(), v, capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)
	st.Delivered()
	require.Equal(t, []uint16{443, 80}, ports(st.sent.filter), "test sanity: the tag:s2 rule sits where the tag:s rule does")

	before := s.Snapshot()
	_, err = s.SetNodeTags(n, []string{"tag:s2"})
	require.NoError(t, err)

	after := s.Snapshot()

	c := after.Since(before)
	require.Contains(t, c.Filters, v, "V's filter moved: its rule's merged position did")

	_, err = st.Update(after)
	require.NoError(t, err)
	st.Delivered()
	assert.Equal(t, []uint16{80, 443}, ports(st.sent.filter), "V is served its reordered filter")

	stale, err := freshDiff(cfg, after.Uncached(), v, capVer, st.sent, &versionCache{})
	require.NoError(t, err)
	assert.Empty(t, stale, "it holds what a fresh render gives: %s", describeResponses(stale))
}

// TestStreamStampRevocationSendsFullPeer pins how a viewer loses a peer's
// last source capability: the peer comes whole, its CapMap empty, as a
// patch would carry no CapMap and leave the viewer's in place; and a stamp
// that comes is sent, as a patch.
func TestStreamStampRevocationSendsFullPeer(t *testing.T) {
	const (
		stamped = `{"groups": {"group:g": ["u1@"]}, "acls": [
			{"action": "accept", "src": ["group:g"], "dst": ["*:*"]},
			{"action": "accept", "src": ["u2@"], "dst": ["*:*"]}]}`
		stamp = "https://headscale.net/cap/src/group:g"
	)

	cfg, s, ids := streamTestState(t, stamped, func(c *types.Config) { c.Policy.CapabilitySources = true })

	st := NewStream(cfg, NewHub(), ids[2], capVer)

	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, initial, 1)

	var peer *tailcfg.Node

	for _, p := range initial[0].Peers {
		if p.ID == ids[0].NodeID() {
			peer = p
		}
	}

	require.NotNil(t, peer)
	require.Contains(t, peer.CapMap, nodecap.Cap(stamp), "the peer comes stamped")

	_, err = s.SetPolicy([]byte(strings.Replace(stamped, `["u1@"]`, `[]`, 1)))
	require.NoError(t, err)

	resps, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	var full *tailcfg.Node

	for _, r := range resps {
		for _, p := range r.PeersChangedPatch {
			require.NotEqual(t, ids[0].NodeID(), p.NodeID, "a revoked stamp is not a patch")
		}

		for _, p := range r.PeersChanged {
			if p.ID == ids[0].NodeID() {
				full = p
			}
		}
	}

	require.NotNil(t, full, "the peer comes whole")
	require.Empty(t, full.CapMap)

	_, err = s.SetPolicy([]byte(stamped))
	require.NoError(t, err)

	resps, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(resps, func(r *tailcfg.MapResponse) bool {
		return slices.ContainsFunc(r.PeersChangedPatch, func(p *tailcfg.PeerChange) bool {
			_, ok := p.CapMap[nodecap.Cap(stamp)]

			return p.NodeID == ids[0].NodeID() && ok
		})
	}), "a stamp that comes is a patch: %v", resps)
}

// TestStreamRemovalOfSharedAddressSendsPeerList pins that, in capability
// mode, a peer removed while another peer holds one of its addresses comes
// with a whole peer list, the one response that indexes the address again
// on the client; a removal sharing nothing goes as a removal alone.
func TestStreamRemovalOfSharedAddressSendsPeerList(t *testing.T) {
	const pol = `{"acls": [{"action": "accept", "src": ["u1@"], "dst": ["*:*"]}]}`

	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, "false")
			cfg, s, ids := streamTestState(t, pol, func(c *types.Config) { c.Policy.CapabilitySources = capSources })

			n1, n1b := mustNode(t, s, ids[0]), mustNode(t, s, ids[1])

			// n1b holds n1's IPv4 address besides its own IPv6 one.
			shared := n1b.AsStruct()
			shared.IPv4 = n1.AsStruct().IPv4
			s.PutNodeInStoreForTest(*shared)

			st := NewStream(cfg, NewHub(), ids[2], capVer)

			_, err := st.Initial(s.Snapshot())
			require.NoError(t, err)

			s.DeleteNodeFromStoreForTest(ids[1])

			resps, err := st.Update(s.Snapshot())
			require.NoError(t, err)

			peerList := slices.ContainsFunc(resps, func(r *tailcfg.MapResponse) bool { return r.Peers != nil })
			require.Equal(t, capSources, peerList, "a whole peer list follows the removal: %s", describeResponses(resps))
			require.True(t, slices.ContainsFunc(resps, func(r *tailcfg.MapResponse) bool {
				return slices.Contains(r.PeersRemoved, ids[1].NodeID())
			}), "the removal is sent: %s", describeResponses(resps))

			// n1 removed in turn shares no address any more.
			s.DeleteNodeFromStoreForTest(ids[0])

			resps, err = st.Update(s.Snapshot())
			require.NoError(t, err)
			require.False(t, slices.ContainsFunc(resps, func(r *tailcfg.MapResponse) bool { return r.Peers != nil }),
				"a removal sharing nothing goes alone: %s", describeResponses(resps))
		})
	}
}

// TestRouteWakesViewersOfARevokedStamp edits a group's members by policy,
// in capability mode: the rule naming the group stays, no node's policy
// capabilities move, and only the removed member's stamp goes. Every node
// it is sent to must wake and be sent the peer without it.
func TestRouteWakesViewersOfARevokedStamp(t *testing.T) {
	const (
		pol = `{"groups": {"group:g": ["u1@", "u2@"]}, "acls": [
			{"action": "accept", "src": ["group:g"], "dst": ["*:*"]}]}`
		stamp = nodecap.Cap("https://headscale.net/cap/src/group:g")
	)

	cfg, s, ids := streamTestState(t, pol, func(c *types.Config) { c.Policy.CapabilitySources = true })

	st := NewStream(cfg, NewHub(), ids[2], capVer)

	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	before := s.Snapshot()
	require.Contains(t, before.NodeCaps(ids[0]), stamp)

	_, err = s.SetPolicy([]byte(strings.Replace(pol, `["u1@", "u2@"]`, `["u2@"]`, 1)))
	require.NoError(t, err)

	after := s.Snapshot()
	require.NotContains(t, after.NodeCaps(ids[0]), stamp)

	all, wake := Route(before, after, after.Since(before))
	require.True(t, all || slices.Contains(slices.Collect(maps.Keys(wake)), ids[2]), "u2's node, sent n1, wakes: %v", wake)

	resps, err := st.Update(after)
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(resps, func(r *tailcfg.MapResponse) bool {
		return slices.ContainsFunc(r.PeersChanged, func(p *tailcfg.Node) bool {
			_, held := p.CapMap[stamp]

			return p.ID == ids[0].NodeID() && !held
		})
	}), "n1 comes without the stamp: %s", describeResponses(resps))
}
