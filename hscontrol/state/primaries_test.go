package state

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// mp wraps netip.MustParsePrefix.
func mp(prefix string) netip.Prefix {
	return netip.MustParsePrefix(prefix)
}

// primariesFixture builds a NodeStore with the requested node IDs
// pre-registered (offline, no routes) and provides terse helpers for
// driving the kinds of state transitions the algorithm cares about.
type primariesFixture struct {
	t  *testing.T
	ns *world

	// clock orders the control sessions advertise and approveRoutes open.
	clock time.Time
}

// session returns an update that opens a control session, as State.Connect
// does, when the node is offline: each opens later than the one before.
func (f *primariesFixture) session() func(*types.Node) {
	f.clock = f.clock.Add(time.Second)
	start := f.clock

	return func(n *types.Node) {
		if !n.Online() {
			n.SessionStart = start
		}

		n.IsOnline = new(true)
	}
}

func newPrimariesFixture(t *testing.T, ids ...types.NodeID) *primariesFixture {
	t.Helper()

	ns := newTestWorld(t)

	for _, id := range ids {
		ns.PutNode(nodeForRapid(id))
	}

	return &primariesFixture{t: t, ns: ns}
}

// advertise mirrors State.Connect: marks the node online, clears
// Unhealthy, and sets approved + announced routes to prefs. An empty
// prefs argument leaves the node online but advertising nothing.
func (f *primariesFixture) advertise(id types.NodeID, prefs ...netip.Prefix) {
	f.t.Helper()

	connect := f.session()
	f.ns.UpdateNode(id, func(n *types.Node) {
		connect(n)
		n.Unhealthy = false
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
		n.ApprovedRoutes = prefs
	})
}

// approveRoutes mirrors State.SetApprovedRoutes / Hostinfo updates:
// it changes the node's announced + approved set without touching
// Unhealthy.
func (f *primariesFixture) approveRoutes(id types.NodeID, prefs ...netip.Prefix) {
	f.t.Helper()

	connect := f.session()
	f.ns.UpdateNode(id, func(n *types.Node) {
		connect(n)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
		n.ApprovedRoutes = prefs
	})
}

// disconnect mirrors State.Disconnect: marks the node offline. The
// the election can still keep its approved route as an unavailable fallback.
func (f *primariesFixture) disconnect(id types.NodeID) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = new(false)
	})
}

// unhealthy mirrors State.SetNodeHealth(id, false).
func (f *primariesFixture) unhealthy(id types.NodeID) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.Unhealthy = true
	})
}

// healthy mirrors State.SetNodeHealth(id, true).
func (f *primariesFixture) healthy(id types.NodeID) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.Unhealthy = false
	})
}

// requirePrimary asserts that prefix has node id as its primary.
func (f *primariesFixture) requirePrimary(prefix netip.Prefix, id types.NodeID) {
	f.t.Helper()
	got, ok := f.ns.snapshot().PrimaryRouteFor(prefix)
	require.True(f.t, ok, "expected a primary for %s, got none", prefix)
	require.Equal(f.t, id, got, "primary for %s", prefix)
}

// requireNoPrimary asserts that prefix has no primary at all.
func (f *primariesFixture) requireNoPrimary(prefix netip.Prefix) {
	f.t.Helper()
	_, ok := f.ns.snapshot().PrimaryRouteFor(prefix)
	require.False(f.t, ok, "expected no primary for %s", prefix)
}

// requireNodeRoutes asserts the set of prefixes for which id is the
// primary, regardless of order.
func (f *primariesFixture) requireNodeRoutes(id types.NodeID, want ...netip.Prefix) {
	f.t.Helper()
	got := f.ns.snapshot().PrimaryRoutesForNode(id)

	gotSorted := slices.Clone(got)
	wantSorted := slices.Clone(want)

	slices.SortFunc(gotSorted, netip.Prefix.Compare)
	slices.SortFunc(wantSorted, netip.Prefix.Compare)

	require.Equal(f.t, wantSorted, gotSorted, "primary routes for node %d", id)
}

func TestPrimaries_SingleNodeSingleRoute(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))

	f.requirePrimary(mp("192.168.1.0/24"), 1)
	f.requireNodeRoutes(1, mp("192.168.1.0/24"))
}

func TestPrimaries_TwoNodesDifferentRoutes(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.2.0/24"))

	f.requirePrimary(mp("192.168.1.0/24"), 1)
	f.requirePrimary(mp("192.168.2.0/24"), 2)
}

func TestPrimaries_OverlappingRoutesLowerIDWins(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))

	f.requirePrimary(mp("192.168.1.0/24"), 1)
	f.requireNodeRoutes(1, mp("192.168.1.0/24"))
	f.requireNodeRoutes(2)
}

func TestPrimaries_ReconnectJoinsAsStandby(t *testing.T) {
	// A primary that disappears (advertiser leaves the set) should
	// trigger failover. When the original primary returns on a new
	// session, the new primary's session is older and keeps the route.
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.disconnect(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)

	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 2)
}

func TestPrimaries_ClearRoutesDropsPrimary(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.approveRoutes(1)
	f.requireNoPrimary(mp("192.168.1.0/24"))
}

func TestPrimaries_DisconnectKeepsLastRouterPrimary(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.disconnect(1)
	f.requirePrimary(mp("192.168.1.0/24"), 1)
}

func TestPrimaries_NoRouterAvailable(t *testing.T) {
	prefix := mp("10.0.0.0/24")
	expire := func(f *primariesFixture, id types.NodeID) {
		f.ns.UpdateNode(id, func(n *types.Node) {
			n.Expiry = new(time.Now().Add(-time.Minute))
		})
	}
	unapprove := func(f *primariesFixture, id types.NodeID) {
		f.ns.UpdateNode(id, func(n *types.Node) { n.ApprovedRoutes = nil })
	}

	tests := []struct {
		name  string
		setup func(*primariesFixture)
		want  types.NodeID
	}{
		{
			name: "expired router keeps its route",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				expire(f, 1)
			},
			want: 1,
		},
		{
			name: "previous primary kept over a lower ID",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				f.disconnect(1)
				f.disconnect(2)
			},
			want: 2,
		},
		{
			name: "lowest ID approver once the previous primary is gone",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				f.advertise(3, prefix)
				f.disconnect(2)
				f.disconnect(3)
				f.disconnect(1)
				unapprove(f, 1)
			},
			want: 2,
		},
		{
			name: "unhealthy router passed over",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				f.advertise(3, prefix)
				f.disconnect(2)
				f.unhealthy(1)
				f.disconnect(3)
				unapprove(f, 3)
			},
			want: 2,
		},
		{
			name: "only unhealthy routers left",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(3, prefix)
				f.unhealthy(1)
				unapprove(f, 3)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPrimariesFixture(t, 1, 2, 3)
			tt.setup(f)

			if tt.want == 0 {
				f.requireNoPrimary(prefix)
			} else {
				f.requirePrimary(prefix, tt.want)
			}
		})
	}
}

func TestPrimaries_UnhealthyTriggersFailover(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.unhealthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)
}

func TestPrimaries_OldestSessionWins(t *testing.T) {
	prefix := mp("192.168.1.0/24")
	withdraw := func(f *primariesFixture, id types.NodeID) {
		f.ns.UpdateNode(id, func(n *types.Node) { n.Hostinfo = &tailcfg.Hostinfo{} })
	}

	tests := []struct {
		name  string
		setup func(*primariesFixture)
		want  types.NodeID
	}{
		{
			name: "older session over lower ID",
			setup: func(f *primariesFixture) {
				f.advertise(2, prefix)
				f.advertise(1, prefix)
			},
			want: 2,
		},
		{
			name: "healthy again takes the route back",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				f.unhealthy(1)
				f.healthy(1)
			},
			want: 1,
		},
		{
			name: "approved again takes the route back",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				f.approveRoutes(1)
				f.approveRoutes(1, prefix)
			},
			want: 1,
		},
		{
			name: "advertised again takes the route back",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				withdraw(f, 1)
				f.requirePrimary(prefix, 2)
				f.approveRoutes(1, prefix)
			},
			want: 1,
		},
		{
			name: "reconnected router stays standby",
			setup: func(f *primariesFixture) {
				f.advertise(1, prefix)
				f.advertise(2, prefix)
				f.disconnect(1)
				f.advertise(1, prefix)
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPrimariesFixture(t, 1, 2)
			tt.setup(f)
			f.requirePrimary(prefix, tt.want)
		})
	}
}

func TestPrimaries_AllUnhealthyKeepsAPrimary(t *testing.T) {
	// Anti-blackhole: when every advertiser is unhealthy the
	// algorithm keeps *some* primary so peers can recover once one
	// flips healthy. The specific node is the prev primary when
	// reachable (see PreservesPrevious); this test only pins the
	// existence rule.
	prefix := mp("192.168.1.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.unhealthy(1)
	f.unhealthy(2)

	_, ok := f.ns.snapshot().PrimaryRouteFor(prefix)
	require.True(t, ok, "all-unhealthy must still produce some primary")
}

func TestPrimaries_AllUnhealthyPreservesPrevious(t *testing.T) {
	// Once a failover has moved primary to a higher-ID node, a
	// subsequent all-unhealthy state must NOT churn primary back to
	// the lowest-ID candidate. Under cable-pull semantics both nodes
	// can linger as IsOnline=true (half-open TCP) and both go
	// Unhealthy — naive `candidates[0]` would flap the primary to a
	// node that is itself unreachable.
	prefix := mp("10.0.0.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.requirePrimary(prefix, 1)

	f.unhealthy(1)
	f.requirePrimary(prefix, 2)

	f.unhealthy(2)
	f.requirePrimary(prefix, 2)
}

func TestPrimaries_ExpiredRouterNotElected(t *testing.T) {
	// Expiry alone takes a router out of the election, even while its
	// cached online flag still says connected.
	prefix := mp("10.0.0.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.requirePrimary(prefix, 1)
	_, ok := f.ns.snapshot().RouterSession(1)
	require.True(t, ok)

	f.ns.UpdateNode(1, func(n *types.Node) {
		n.Expiry = new(time.Now().Add(-time.Minute))
	})

	f.requirePrimary(prefix, 2)
	_, ok = f.ns.snapshot().RouterSession(1)
	require.False(t, ok)

	_, ok = f.ns.snapshot().RouterSession(2)
	require.True(t, ok)
}

func TestPrimaries_ExitRouteNotElected(t *testing.T) {
	// Exit routes (0.0.0.0/0, ::/0) are not subject to HA primary
	// election — every approved exit-route advertiser keeps it.
	f := newPrimariesFixture(t, 1)
	exitV4 := mp("0.0.0.0/0")
	f.advertise(1, exitV4)

	f.requireNoPrimary(exitV4)
}

func TestPrimaries_BothOfflineThenOneReturns(t *testing.T) {
	// With two HA advertisers both offline, the last primary keeps the
	// prefix. The snapshot recomputes primaries on every NodeStore
	// write, so the first advertiser to return must be elected.
	prefix := mp("10.0.0.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.requirePrimary(prefix, 1)

	f.disconnect(1)
	f.requirePrimary(prefix, 2)

	f.disconnect(2)
	f.requirePrimary(prefix, 2)

	f.advertise(1, prefix)
	f.requirePrimary(prefix, 1)
}

func TestPrimaries_HANodes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*primariesFixture)
		want  map[netip.Prefix][]types.NodeID
	}{
		{
			name: "single-node-not-ha",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
		{
			name: "unhealthy-node-left-alone-is-still-monitored",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
				f.unhealthy(1)
				f.approveRoutes(2)
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1},
			},
		},
		{
			name: "node-left-alone-not-ha-once-healthy",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
				f.unhealthy(1)
				f.approveRoutes(2)
				f.healthy(1)
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
		{
			name: "two-nodes-same-prefix-is-ha",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2},
			},
		},
		{
			name: "two-nodes-different-prefixes-not-ha",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.2.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
		{
			name: "three-nodes-two-share-prefix",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
				f.advertise(3, mp("10.0.0.0/8"))
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2},
			},
		},
		{
			name: "three-nodes-all-share",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
				f.advertise(3, mp("192.168.1.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2, 3},
			},
		},
		{
			name: "empty",
			setup: func(*primariesFixture) {
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPrimariesFixture(t, 1, 2, 3)
			tt.setup(f)

			got := f.ns.snapshot().HANodes()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUndecidedHANodes(t *testing.T) {
	office := mp("10.70.0.0/24")
	lab := mp("10.80.0.0/24")
	shared := mp("10.90.0.0/24")

	tests := []struct {
		name     string
		haNodes  map[netip.Prefix][]types.NodeID
		deferred []types.NodeID
		want     []types.NodeID
	}{
		{
			name: "nothing deferred",
			haNodes: map[netip.Prefix][]types.NodeID{
				office: {1, 2},
				lab:    {3, 4},
			},
		},
		{
			name: "disjoint prefixes",
			haNodes: map[netip.Prefix][]types.NodeID{
				office: {1, 2},
				lab:    {3, 4},
			},
			deferred: []types.NodeID{3},
			want:     []types.NodeID{3, 4},
		},
		{
			name: "shared router carries the deferral across",
			haNodes: map[netip.Prefix][]types.NodeID{
				office: {1, 2},
				shared: {2, 5},
				lab:    {3, 4},
			},
			deferred: []types.NodeID{5},
			want:     []types.NodeID{1, 2, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deferred := xsync.NewMap[types.NodeID, struct{}]()
			for _, id := range tt.deferred {
				deferred.Store(id, struct{}{})
			}

			got := undecidedHANodes(tt.haNodes, deferred)
			assert.ElementsMatch(t, tt.want, got.Slice())
		})
	}
}

func TestViaElectionRestart(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	u1 := database.CreateUserForTest("u1")
	u2 := database.CreateUserForTest("u2")
	viewer := database.CreateRegisteredNodeForTest(u2, "viewer")
	r1 := database.CreateRegisteredNodeForTest(u1, "r1")
	r2 := database.CreateRegisteredNodeForTest(u1, "r2")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)

	closed := false

	t.Cleanup(func() {
		if !closed {
			_ = s.Close()
		}
	})

	pol := `{"tagOwners":{"tag:via":["u1@"]},"grants":[` +
		`{"src":["u2@"],"dst":["10.2.0.0/24"],"ip":["*"],"via":["tag:via"]}]}`

	_, err = s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	// SetPolicy publishes to the world only; the reopened state reads
	// the database, so the document must live there too.
	_, err = s.SetPolicyInDB(pol)
	require.NoError(t, err)

	route := mp("10.2.0.0/24")

	serve := func(st *State, id types.NodeID) {
		t.Helper()

		live, ok := st.GetNodeByID(id)
		require.True(t, ok)

		require.NoError(t, st.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{
			NodeKey:  live.NodeKey(),
			DiscoKey: live.DiscoKey(),
			Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
		}))

		_, err := st.SetApprovedRoutes(id, []netip.Prefix{route})
		require.NoError(t, err)
	}

	epochs := map[types.NodeID]uint64{}

	for _, id := range []types.NodeID{r1.ID, r2.ID} {
		_, err := s.SetNodeTags(id, []string{"tag:via"})
		require.NoError(t, err)
		serve(s, id)
		epochs[id] = s.Connect(id)
	}

	s.Connect(viewer.ID)

	winner := func(snap *Snapshot) types.NodeID {
		t.Helper()

		v, _ := snap.GetNode(viewer.ID)
		matchers, err := snap.Policy().MatchersForNode(v)
		require.NoError(t, err)

		for _, id := range []types.NodeID{r1.ID, r2.ID} {
			peer, _ := snap.GetNode(id)
			if slices.Contains(snap.RoutesForPeer(v, peer, matchers), route) {
				return id
			}
		}

		return 0
	}

	require.Equal(t, r1.ID, winner(s.Snapshot()), "the lowest-ID healthy router wins")

	// Fail over to the second router before the restart.
	require.NoError(t, s.Disconnect(r1.ID, epochs[r1.ID]))
	require.Equal(t, r2.ID, winner(s.Snapshot()), "failover moves the route to the surviving router")

	// The reopen must not share the database with a live state.
	closed = true

	require.NoError(t, s.Close())

	reopened, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	// Everything durable comes back from the database; only online state
	// is new. One commit brings both routers back, so a restored
	// incumbent (r2 held the route before the restart) would keep it;
	// a fresh election gives it to the lowest-ID router.
	reopened.world.UpdateNodes(map[types.NodeID]UpdateNodeFunc{
		r1.ID: func(n *types.Node) { n.IsOnline = new(true) },
		r2.ID: func(n *types.Node) { n.IsOnline = new(true) },
	})

	restarted := reopened.Snapshot()

	// The via scope must be what elected: the reopened state read the
	// persisted document, not the empty default.
	via := restarted.s.Get(reopened.world.primaries).via
	require.NotEmpty(t, via.ChangedNodes(nil), "the via scope elects at restart")
	require.Equal(t, r1.ID, winner(restarted), "a restart restores no incumbent: both routers back in one commit elect the lowest ID")

	reopened.Connect(viewer.ID)
	require.Equal(t, r1.ID, winner(reopened.Snapshot()), "the viewer keeps seeing the elected router after it reconnects")
}

func TestUnavailableRouterFallbackByScope(t *testing.T) {
	for _, lowUnhealthy := range []bool{false, true} {
		t.Run(fmt.Sprintf("lowest-unhealthy=%t", lowUnhealthy), func(t *testing.T) {
			first := nodeForRapid(1)
			second := nodeForRapid(2)
			first.IsOnline = new(false)
			second.IsOnline = new(false)
			first.Unhealthy = lowUnhealthy
			nodes := graph.NewMap(graph.Same[*types.Node], map[types.NodeID]*types.Node{1: &first, 2: &second})
			candidates := views.SliceOf([]types.NodeID{1, 2})
			global, ok := electPrimary(nodes, candidates, 2)
			require.True(t, ok)
			assert.Equal(t, types.NodeID(2), global, "global fallback retains its approving incumbent")

			via, ok := electViaPrimary(nodes, candidates, 2)
			require.True(t, ok)
			assert.Equal(t, types.NodeID(1), via, "via fallback uses the lowest approving ID regardless of incumbent")
		})
	}
}
