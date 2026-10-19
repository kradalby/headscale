package state

import (
	"fmt"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
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
	ns *NodeStore
}

func newPrimariesFixture(t *testing.T, ids ...types.NodeID) *primariesFixture {
	t.Helper()

	ns := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
	ns.Start()
	t.Cleanup(ns.Stop)

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
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = new(true)
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
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = new(true)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
		n.ApprovedRoutes = prefs
	})
}

// disconnect mirrors State.Disconnect: marks the node offline. The
// snapshot rebuild treats an offline node as a non-advertiser.
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
	got, ok := f.ns.PrimaryRouteFor(prefix)
	require.True(f.t, ok, "expected a primary for %s, got none", prefix)
	require.Equal(f.t, id, got, "primary for %s", prefix)
}

// requireNoPrimary asserts that prefix has no primary at all.
func (f *primariesFixture) requireNoPrimary(prefix netip.Prefix) {
	f.t.Helper()
	_, ok := f.ns.PrimaryRouteFor(prefix)
	require.False(f.t, ok, "expected no primary for %s", prefix)
}

// requireNodeRoutes asserts the set of prefixes for which id is the
// primary, regardless of order.
func (f *primariesFixture) requireNodeRoutes(id types.NodeID, want ...netip.Prefix) {
	f.t.Helper()
	got := f.ns.PrimaryRoutesForNode(id)

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

func TestPrimaries_AntiFlapPreservesCurrentPrimary(t *testing.T) {
	// A primary that disappears (advertiser leaves the set) should
	// trigger failover. When the original primary returns, the new
	// primary keeps the assignment — anti-flap.
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

func TestPrimaries_DisconnectDropsLastAdvertiserPrimary(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.disconnect(1)
	f.requireNoPrimary(mp("192.168.1.0/24"))
}

func TestPrimaries_UnhealthyTriggersFailover(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.unhealthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)
}

func TestPrimaries_RecoveryFromUnhealthyNoFlap(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.unhealthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)

	f.healthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)
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

	_, ok := f.ns.PrimaryRouteFor(prefix)
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

func TestPrimaries_ExitRouteNotElected(t *testing.T) {
	// Exit routes (0.0.0.0/0, ::/0) are not subject to HA primary
	// election — every approved exit-route advertiser keeps it.
	f := newPrimariesFixture(t, 1)
	exitV4 := mp("0.0.0.0/0")
	f.advertise(1, exitV4)

	f.requireNoPrimary(exitV4)
}

func TestPrimaries_BothOfflineThenOneReturns(t *testing.T) {
	// With two HA advertisers, dropping both then bringing one back
	// used to leave the prefix without any primary. The snapshot
	// recomputes primaries on every NodeStore write, so the
	// returning advertiser must be elected.
	prefix := mp("10.0.0.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.requirePrimary(prefix, 1)

	f.disconnect(1)
	f.requirePrimary(prefix, 2)

	f.disconnect(2)
	f.requireNoPrimary(prefix)

	f.advertise(2, prefix)
	f.requirePrimary(prefix, 2)
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

			got := f.ns.HANodes()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRouteAdvertisersMatchOriginal(t *testing.T) {
	prefixes := [][]netip.Prefix{
		nil,
		{},
		{mp("0.0.0.0/0"), mp("::/0")},
		{mp("10.0.0.0/24")},
		{mp("10.0.0.7/24")},
		{netip.Prefix{}},
		{mp("10.0.0.0/24"), mp("10.0.0.0/24"), mp("::/0")},
		{mp("2001:db8::/64"), mp("::ffff:192.0.2.1/120")},
		{mp("10.0.0.1/0"), mp("2001:db8::1/0"), mp("fe80::1/128")},
	}

	for onlineIndex, online := range []*bool{nil, new(false), new(true)} {
		for announcedIndex, announced := range prefixes {
			for approvedIndex, approved := range prefixes {
				t.Run(fmt.Sprintf("online=%d/announced=%d/approved=%d",
					onlineIndex, announcedIndex, approvedIndex), func(t *testing.T) {
					const highID types.NodeID = 1 << 63

					nodes := map[types.NodeID]types.Node{
						0: {
							ID: 0, IsOnline: online, ApprovedRoutes: approved,
							Hostinfo: &tailcfg.Hostinfo{RoutableIPs: announced},
						},
						7: {
							ID: 7, IsOnline: new(true), ApprovedRoutes: approved,
							Hostinfo: &tailcfg.Hostinfo{RoutableIPs: announced},
						},
						highID: {
							ID:             highID,
							IsOnline:       new(true),
							Unhealthy:      true,
							ApprovedRoutes: approved,
							Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
						},
						11: {ID: 11, IsOnline: new(true), ApprovedRoutes: approved},
						12: {
							ID:       12,
							IsOnline: new(true),
							Hostinfo: &tailcfg.Hostinfo{RoutableIPs: announced},
						},
					}

					var store NodeStore
					store.data.Store(&Snapshot{nodesByID: nodes})
					require.Equal(
						t,
						store.routeAdvertiserOriginalHANodes(),
						store.HANodes(),
					)

					for _, previousID := range []types.NodeID{0, 7, highID, 99} {
						previous := make(map[netip.Prefix]types.NodeID)
						for _, prefix := range announced {
							previous[prefix] = previousID
						}

						want, wantPrimary := routeAdvertiserOriginalElection(
							nodes,
							previous,
						)
						got, gotPrimary := electPrimaryRoutes(nodes, previous)
						require.Equal(t, want, got)
						require.Equal(t, wantPrimary, gotPrimary)
					}

					want, wantPrimary := routeAdvertiserOriginalElection(nodes, nil)
					got, gotPrimary := electPrimaryRoutes(nodes, nil)
					require.Equal(t, want, got)
					require.Equal(t, wantPrimary, gotPrimary)
				})
			}
		}
	}
}

func TestRouteAdvertisersMatchOriginalHistory(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2, 3)
	prefix := mp("10.0.0.0/24")
	steps := []struct {
		name string
		run  func()
	}{
		{"first advertiser", func() { f.advertise(2, prefix) }},
		{"lower ID keeps primary", func() { f.advertise(1, prefix) }},
		{"duplicates and exits", func() { f.advertise(3, prefix, prefix, mp("::/0")) }},
		{"unhealthy primary", func() { f.unhealthy(2) }},
		{"unhealthy second", func() { f.unhealthy(1) }},
		{"all unhealthy", func() { f.unhealthy(3) }},
		{"delete primary", func() { f.ns.DeleteNode(3) }},
		{"recover", func() { f.healthy(2) }},
		{"disconnect", func() { f.disconnect(2) }},
		{"reconnect", func() { f.advertise(2, prefix) }},
		{"approval revoked", func() {
			f.ns.UpdateNode(2, func(n *types.Node) { n.ApprovedRoutes = nil })
		}},
		{"approval restored", func() { f.approveRoutes(2, prefix) }},
		{"announcement withdrawn", func() {
			f.ns.UpdateNode(2, func(n *types.Node) { n.Hostinfo = nil })
		}},
		{"reinsert", func() { f.ns.PutNode(nodeForRapid(3)) }},
		{"unusual prefixes", func() {
			f.advertise(
				3,
				netip.Prefix{},
				mp("10.0.0.7/24"),
				mp("::ffff:192.0.2.1/120"),
			)
		}},
		{"exit only", func() { f.approveRoutes(3, mp("0.0.0.0/0"), mp("::/0")) }},
	}
	previous := f.ns.data.Load()

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.run()

			got := f.ns.data.Load()
			want := routeAdvertiserOriginalSnapshot(
				got.nodesByID,
				allowAllPeersFunc,
				previous,
				false,
				false,
			)
			require.Equal(t, want.routes, got.routes)
			require.Equal(t, want.isPrimaryRoute, got.isPrimaryRoute)
			require.Equal(t, want.primaryRoutesByNode, got.primaryRoutesByNode)
			require.Equal(t, f.ns.routeAdvertiserOriginalHANodes(), f.ns.HANodes())

			previous = &want
		})
	}
}

func TestRouteAdvertiserOnlineBatchMatchesOriginal(t *testing.T) {
	nodes := primaryRouteBenchmarkNodes(16, 4, 2)
	noPeers := func([]types.NodeView) map[types.NodeID][]types.NodeID { return nil }
	original := &NodeStore{peersFunc: noPeers}
	current := &NodeStore{peersFunc: noPeers}
	initial := routeAdvertiserOriginalSnapshot(nodes, noPeers, nil, false, false)
	original.data.Store(&initial)
	current.data.Store(&initial)

	for range 6 {
		for _, id := range []types.NodeID{1, 2, 16} {
			for _, impl := range []struct {
				store *NodeStore
				apply func(*NodeStore, []work)
			}{
				{original, (*NodeStore).routeAdvertiserOriginalApplyBatch},
				{current, (*NodeStore).applyBatch},
			} {
				impl.apply(impl.store, []work{{
					op: updateMulti, result: make(chan struct{}),
					multiUpdates: map[types.NodeID]UpdateNodeFunc{
						id: func(n *types.Node) { n.IsOnline = new(!n.Online()) },
					},
				}})
			}

			want, got := original.data.Load(), current.data.Load()
			require.Equal(t, want.nodesByID, got.nodesByID)
			require.Equal(t, want.routes, got.routes)
			require.Equal(t, want.isPrimaryRoute, got.isPrimaryRoute)
			require.Equal(t, want.primaryRoutesByNode, got.primaryRoutesByNode)
			require.Equal(t, want.peersByNode, got.peersByNode)
			require.Equal(
				t,
				original.routeAdvertiserOriginalHANodes(),
				current.HANodes(),
			)
		}
	}
}

func BenchmarkRouteAdvertisers(b *testing.B) {
	for _, shape := range []struct{ nodes, routers, prefixes int }{
		{100, 0, 1},
		{100, 2, 1},
		{100, 100, 1},
		{1000, 0, 1},
		{1000, 2, 1},
		{1000, 1000, 1},
		{10000, 0, 1},
		{10000, 2, 1},
		{10000, 10000, 1},
		{1000, 16, 128},
	} {
		b.Run(
			fmt.Sprintf(
				"nodes=%d/routers=%d/prefixes=%d",
				shape.nodes,
				shape.routers,
				shape.prefixes,
			),
			func(b *testing.B) {
				nodes := primaryRouteBenchmarkNodes(
					shape.nodes,
					shape.routers,
					shape.prefixes,
				)
				for id, node := range nodes {
					node.IsOnline = new(true)
					// Pairs share their routes so HANodes has actual HA candidates.
					if id%2 == 0 && id <= types.NodeID(shape.routers) { //nolint:gosec // Fixture router counts are positive and bounded to 10000.
						node.ApprovedRoutes = slices.Clone(nodes[id-1].ApprovedRoutes)
						node.Hostinfo = &tailcfg.Hostinfo{
							RoutableIPs: node.ApprovedRoutes,
						}
					}

					nodes[id] = node
				}

				noPeers := func([]types.NodeView) map[types.NodeID][]types.NodeID { return nil }

				for _, operation := range []string{"HANodes", "election", "online-transition"} {
					for _, impl := range []struct {
						name  string
						ha    func(*NodeStore) map[netip.Prefix][]types.NodeID
						elect func(map[types.NodeID]types.Node, map[netip.Prefix]types.NodeID) (map[netip.Prefix]types.NodeID, map[types.NodeID]bool)
						build func(map[types.NodeID]types.Node, PeersFunc, *Snapshot, bool, bool) Snapshot
						apply func(*NodeStore, []work)
					}{
						{"original", (*NodeStore).routeAdvertiserOriginalHANodes, routeAdvertiserOriginalElection, routeAdvertiserOriginalSnapshot, (*NodeStore).routeAdvertiserOriginalApplyBatch},
						{"current", (*NodeStore).HANodes, electPrimaryRoutes, snapshotFromNodes, (*NodeStore).applyBatch},
					} {
						b.Run(operation+"/"+impl.name, func(b *testing.B) {
							initial := impl.build(nodes, noPeers, nil, false, false)
							store := &NodeStore{peersFunc: noPeers}
							store.data.Store(&initial)
							b.ReportAllocs()

							switch operation {
							case "HANodes":
								for b.Loop() {
									runtime.KeepAlive(impl.ha(store))
								}
							case "election":
								for b.Loop() {
									routes, primary := impl.elect(nodes, initial.routes)
									runtime.KeepAlive(routes)
									runtime.KeepAlive(primary)
								}
							case "online-transition":
								for b.Loop() {
									impl.apply(store, []work{{
										op: updateMulti, result: make(chan struct{}),
										multiUpdates: map[types.NodeID]UpdateNodeFunc{
											1: func(n *types.Node) { n.IsOnline = new(!n.Online()) },
										},
									}})
								}
							}
						})
					}
				}
			},
		)
	}
}

// Frozen from 1096abfc8 before advertiser optimization; only identifiers are renamed.
func routeAdvertiserOriginalOnlineAdvertisers(
	nodes map[types.NodeID]types.Node,
	ids []types.NodeID,
) map[netip.Prefix][]types.NodeID {
	advertisers := make(map[netip.Prefix][]types.NodeID)

	for _, id := range ids {
		n := nodes[id]
		if n.IsOnline == nil || !*n.IsOnline {
			continue
		}

		for _, p := range n.AllApprovedRoutes() {
			if tsaddr.IsExitRoute(p) {
				continue
			}

			advertisers[p] = append(advertisers[p], id)
		}
	}

	return advertisers
}

func routeAdvertiserOriginalElection(
	nodes map[types.NodeID]types.Node,
	prev map[netip.Prefix]types.NodeID,
) (map[netip.Prefix]types.NodeID, map[types.NodeID]bool) {
	advertisers := routeAdvertiserOriginalOnlineAdvertisers(nodes, slices.Sorted(maps.Keys(nodes)))

	routes := make(map[netip.Prefix]types.NodeID, len(advertisers))
	for prefix, candidates := range advertisers {
		if cur, ok := prev[prefix]; ok &&
			slices.Contains(candidates, cur) &&
			!nodes[cur].Unhealthy {
			routes[prefix] = cur
			continue
		}

		var (
			selected types.NodeID
			found    bool
		)

		for _, c := range candidates {
			if !nodes[c].Unhealthy {
				selected = c
				found = true

				break
			}
		}

		// All-unhealthy fallback: preserve the previous primary only
		// when it is still a candidate. Falling back to any candidate
		// would point peers at a node the prober has already declared
		// unreachable; leaving the prefix unmapped is honest until a
		// probe cycle picks one that responds.
		if !found {
			if cur, ok := prev[prefix]; ok && slices.Contains(candidates, cur) {
				selected = cur
				found = true
			}
		}

		if found {
			routes[prefix] = selected
		}
	}

	isPrimaryRoute := make(map[types.NodeID]bool, len(routes))
	for _, id := range routes {
		isPrimaryRoute[id] = true
	}

	return routes, isPrimaryRoute
}

func (s *NodeStore) routeAdvertiserOriginalHANodes() map[netip.Prefix][]types.NodeID {
	snap := s.data.Load()

	advertisers := routeAdvertiserOriginalOnlineAdvertisers(
		snap.nodesByID,
		slices.Sorted(maps.Keys(snap.nodesByID)),
	)

	out := make(map[netip.Prefix][]types.NodeID)

	for p, ids := range advertisers {
		if len(ids) < 2 {
			continue
		}

		out[p] = ids
	}

	return out
}

func routeAdvertiserOriginalSnapshot(
	nodes map[types.NodeID]types.Node,
	peersFunc PeersFunc,
	prev *Snapshot,
	reusePeers, reuseRoutes bool,
) Snapshot {
	timer := prometheus.NewTimer(nodeStoreSnapshotBuildDuration)
	defer timer.ObserveDuration()

	allNodes := make([]types.NodeView, 0, len(nodes))
	nodeViewsByID := make(map[types.NodeID]types.NodeView, len(nodes))

	for _, n := range nodes {
		nv := n.View()
		allNodes = append(allNodes, nv)
		nodeViewsByID[n.ID] = nv
	}

	var (
		routes              map[netip.Prefix]types.NodeID
		isPrimaryRoute      map[types.NodeID]bool
		primaryRoutesByNode map[types.NodeID][]netip.Prefix
	)

	if reuseRoutes {
		routes, isPrimaryRoute = prev.routes, prev.isPrimaryRoute
		primaryRoutesByNode = prev.primaryRoutesByNode
	} else {
		// Carrying the previous assignment forward lets a still-valid
		// primary survive unrelated batches.
		var prevRoutes map[netip.Prefix]types.NodeID
		if prev != nil {
			prevRoutes = prev.routes
		}

		routes, isPrimaryRoute = routeAdvertiserOriginalElection(nodes, prevRoutes)
		if len(routes) > 0 {
			primaryRoutesByNode = make(map[types.NodeID][]netip.Prefix, len(isPrimaryRoute))
			for prefix, id := range routes {
				primaryRoutesByNode[id] = append(primaryRoutesByNode[id], prefix)
			}

			for _, prefixes := range primaryRoutesByNode {
				slices.SortFunc(prefixes, netip.Prefix.Compare)
			}
		}
	}

	var (
		peerIDsByNode  map[types.NodeID][]types.NodeID
		peerMembership *sync.Map
	)

	if reusePeers {
		peerIDsByNode = prev.peersByNode
		peerMembership = prev.peerMembership
	} else {
		peersTimer := prometheus.NewTimer(nodeStorePeersCalculationDuration)
		peerIDsByNode = peersFunc(allNodes)

		peersTimer.ObserveDuration()
	}

	if peerMembership == nil {
		peerMembership = &sync.Map{}
	}

	newSnap := Snapshot{
		nodesByID:           nodes,
		nodeViewsByID:       nodeViewsByID,
		allNodes:            allNodes,
		nodesByNodeKey:      make(map[key.NodePublic]types.NodeView),
		nodesByMachineKey:   make(map[key.MachinePublic]map[types.UserID]types.NodeView),
		peersByNode:         peerIDsByNode,
		peerMembership:      peerMembership,
		nodesByUser:         make(map[types.UserID][]types.NodeView),
		routes:              routes,
		isPrimaryRoute:      isPrimaryRoute,
		primaryRoutesByNode: primaryRoutesByNode,
	}

	for _, n := range nodes {
		nodeView := nodeViewsByID[n.ID]
		userID := n.TypedUserID()

		// Tagged nodes are owned by their tags, not a user,
		// so they are not indexed by user.
		if !n.IsTagged() {
			newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		}

		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}

		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	return newSnap
}

func (s *NodeStore) routeAdvertiserOriginalApplyBatch(batch []work) {
	timer := prometheus.NewTimer(nodeStoreBatchDuration)
	defer timer.ObserveDuration()

	nodeStoreBatchSize.Observe(float64(len(batch)))

	nodes := make(map[types.NodeID]types.Node)
	maps.Copy(nodes, s.data.Load().nodesByID)

	// Track which work items need node results
	nodeResultRequests := make(map[types.NodeID][]*work)

	// Track rebuildPeerMaps operations
	var rebuildOps []*work

	// setErrResults collects per-work errors from the setName path so
	// they can be delivered after the snapshot swap, together with the
	// NodeView for that work.
	setErrResults := make(map[*work]error)

	// relationChanged forces a peersFunc run; electionChanged forces a
	// route re-election. put/del/setName/rebuildPeerMaps are treated as
	// relation-changing; updateMulti compares the node before and after.
	relationChanged := false
	electionChanged := false

	for i := range batch {
		w := &batch[i]
		switch w.op {
		case put:
			n := w.node
			n.GivenName = resolveGivenName(nodes, n.ID, n.GivenName)

			nodes[w.nodeID] = n
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}

			relationChanged = true
			electionChanged = true
		case updateMulti:
			for id, fn := range w.multiUpdates {
				n, exists := nodes[id]
				if !exists {
					continue
				}

				oldGivenName := n.GivenName
				pre := n.Clone()
				fn(&n)

				if n.GivenName != oldGivenName {
					n.GivenName = resolveGivenName(nodes, n.ID, n.GivenName)
				}

				nodes[id] = n

				if w.pre != nil {
					w.pre[id] = pre.View()
				}

				relation, election := updateChanges(pre, &n)
				relationChanged = relationChanged || relation
				electionChanged = electionChanged || election
			}
		case del:
			delete(nodes, w.nodeID)
			// For delete operations, send an invalid NodeView if requested
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}

			relationChanged = true
			electionChanged = true
		case setName:
			n, exists := nodes[w.nodeID]
			if !exists {
				setErrResults[w] = ErrNodeNotFound
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)

				continue
			}

			if dnsname.ValidLabel(w.name) != nil {
				setErrResults[w] = ErrGivenNameInvalid
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)

				continue
			}

			taken := false

			for id, other := range nodes {
				if id != w.nodeID && other.GivenName == w.name {
					taken = true
					break
				}
			}

			if taken {
				setErrResults[w] = ErrGivenNameTaken
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)

				continue
			}

			n.GivenName = w.name
			nodes[w.nodeID] = n
			nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			relationChanged = true
			electionChanged = true
		case rebuildPeerMaps:
			// rebuildPeerMaps doesn't modify nodes, it just forces the snapshot rebuild
			// below to recalculate peer relationships using the current peersFunc
			rebuildOps = append(rebuildOps, w)
			relationChanged = true
			electionChanged = true
		}
	}

	prev := s.data.Load()

	// A relation change recomputes adjacency; anything else reuses the
	// previous peer IDs and re-elects routes only if an election input moved.
	if relationChanged {
		nodeStoreSnapshotBuilds.WithLabelValues("recomputed").Inc()
	} else {
		nodeStoreSnapshotBuilds.WithLabelValues("reused").Inc()
	}

	newSnap := routeAdvertiserOriginalSnapshot(nodes, s.peersFunc, prev, !relationChanged, !electionChanged)
	s.data.Store(&newSnap)

	// Update node count gauge
	nodeStoreNodesCount.Set(float64(len(nodes)))

	// Send the resulting nodes to all work items that requested them.
	// A zero-value NodeView{} reports Valid()==false, matching node.View()
	// for a node that was deleted or never existed.
	for nodeID, workItems := range nodeResultRequests {
		var nodeView types.NodeView
		if node, exists := nodes[nodeID]; exists {
			nodeView = node.View()
		}

		for _, w := range workItems {
			w.nodeResult <- nodeView

			close(w.nodeResult)

			if w.errResult != nil {
				w.errResult <- setErrResults[w]

				close(w.errResult)
			}
		}
	}

	// Signal completion for rebuildPeerMaps operations
	for _, w := range rebuildOps {
		close(w.rebuildResult)
	}

	// Signal completion for all other work items
	for _, w := range batch {
		if w.op != rebuildPeerMaps {
			close(w.result)
		}
	}
}
