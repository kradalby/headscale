package state

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// Frozen before lazy peer membership: includes the sibling's route projection,
// so snapshot benchmarks isolate membership overhead from route changes.
func snapshotFromNodesPeerScanReference(
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

		routes, isPrimaryRoute = electPrimaryRoutes(nodes, prevRoutes)
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

	var peerIDsByNode map[types.NodeID][]types.NodeID

	if reusePeers {
		peerIDsByNode = prev.peersByNode
	} else {
		peersTimer := prometheus.NewTimer(nodeStorePeersCalculationDuration)
		peerIDsByNode = peersFunc(allNodes)

		peersTimer.ObserveDuration()
	}

	newSnap := Snapshot{
		nodesByID:           nodes,
		nodeViewsByID:       nodeViewsByID,
		allNodes:            allNodes,
		nodesByNodeKey:      make(map[key.NodePublic]types.NodeView),
		nodesByMachineKey:   make(map[key.MachinePublic]map[types.UserID]types.NodeView),
		peersByNode:         peerIDsByNode,
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

func TestPeerMembershipMatchesListPeers(t *testing.T) {
	const (
		high types.NodeID = 1 << 63
		last types.NodeID = 1<<64 - 1
	)

	nodes := make(types.Nodes, 0, 5)

	for _, id := range []types.NodeID{1, 2, 3, high, last} {
		node := createTestNode(id, 1, "user", "node")
		nodes = append(nodes, &node)
	}

	ordered := []types.NodeID{3, 999, high, 2, 2, last}
	store := NewNodeStore(nodes, func([]types.NodeView) map[types.NodeID][]types.NodeID {
		return map[types.NodeID][]types.NodeID{1: ordered}
	}, TestBatchSize, TestBatchTimeout)
	want := []tailcfg.NodeID{-1 << 63, -1, 2, 2, 3}
	require.Equal(t, want, store.PeerIDsForMembership(1).AsSlice())
	require.Equal(t, []types.NodeID{3, 999, high, 2, 2, last}, ordered,
		"sorting membership must not reorder the peer map")

	var listed []types.NodeID
	for _, peer := range store.ListPeers(1).All() {
		listed = append(listed, peer.ID())
	}

	require.Equal(t, []types.NodeID{3, high, 2, 2, last}, listed)
	require.Zero(t, store.PeerIDsForMembership(999).Len())
}

func TestPeerMembershipLegacySnapshot(t *testing.T) {
	nodes := map[types.NodeID]types.Node{
		1: createTestNode(1, 1, "user", "one"),
		2: createTestNode(2, 1, "user", "two"),
	}
	control := snapshotFromNodesPeerScanReference(nodes, allowAllPeersFunc, nil, false, false)

	var store NodeStore
	store.data.Store(&control)
	old := store.PeerIDsForMembership(1)
	require.Equal(t, []tailcfg.NodeID{2}, old.AsSlice())
	require.Nil(t, control.peerMembership, "published control snapshot must remain unchanged")
	reused := snapshotFromNodes(maps.Clone(nodes), allowAllPeersFunc, &control, true, true)
	require.NotNil(t, reused.peerMembership)
	store.data.Store(&reused)
	require.Equal(t, []tailcfg.NodeID{2}, store.PeerIDsForMembership(1).AsSlice())
	require.Equal(t, []tailcfg.NodeID{2}, old.AsSlice())
}

func TestPeerMembershipSnapshotStable(t *testing.T) {
	node1 := createTestNode(1, 1, "user", "one")
	node2 := createTestNode(2, 1, "user", "two")
	store := NewNodeStore(types.Nodes{&node1, &node2}, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	old := store.PeerIDsForMembership(1)
	require.Equal(t, []tailcfg.NodeID{2}, old.AsSlice())

	first := store.data.Load().peerMembership
	_, ok := store.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
	require.True(t, ok)
	require.Same(t, first, store.data.Load().peerMembership)
	require.Equal(t, []tailcfg.NodeID{2}, store.PeerIDsForMembership(1).AsSlice())

	store.DeleteNode(2)
	require.NotSame(t, first, store.data.Load().peerMembership)
	require.Zero(t, store.PeerIDsForMembership(1).Len())
	require.Equal(t, []tailcfg.NodeID{2}, old.AsSlice())

	store.PutNode(node2)
	require.Equal(t, []tailcfg.NodeID{2}, store.PeerIDsForMembership(1).AsSlice())
	beforePolicy := store.data.Load().peerMembership
	store.RebuildPeerMaps()
	require.NotSame(t, beforePolicy, store.data.Load().peerMembership)
	require.Equal(t, []tailcfg.NodeID{2}, old.AsSlice())
}

func TestPeerMembershipLazySparseRows(t *testing.T) {
	const count = 257

	nodes := make(types.Nodes, 0, count)

	peers := make(map[types.NodeID][]types.NodeID, count)
	for i := range count {
		id := types.NodeID(i + 1) //nolint:gosec // bounded fixture ID
		nodes = append(nodes, &types.Node{ID: id})
		peers[id] = []types.NodeID{types.NodeID((i+1)%count + 1)} //nolint:gosec // bounded fixture ID
	}

	store := NewNodeStore(nodes, func([]types.NodeView) map[types.NodeID][]types.NodeID {
		return peers
	}, TestBatchSize, TestBatchTimeout)
	cache := store.data.Load().peerMembership
	rows := func() (int, int) {
		var count, capacity int

		cache.Range(func(_, value any) bool {
			count++
			row, ok := value.(*peerMembershipRow)
			require.True(t, ok)

			capacity += cap(row.ids)

			return true
		})

		return count, capacity
	}
	gotRows, capacity := rows()
	require.Zero(t, gotRows, "snapshot construction must not build membership rows")
	require.Zero(t, capacity)

	for id := types.NodeID(1000); id < 1100; id++ {
		require.Zero(t, store.PeerIDsForMembership(id).Len())
	}

	gotRows, _ = rows()
	require.Zero(t, gotRows, "unknown recipients must not grow the cache")
	store.PeerIDsForMembership(1)

	gotRows, capacity = rows()
	require.Equal(t, 1, gotRows)
	require.Equal(t, 1, capacity)

	for id := types.NodeID(1); id <= count; id++ {
		store.PeerIDsForMembership(id)
	}

	gotRows, capacity = rows()
	require.Equal(t, count, gotRows)
	require.Equal(t, count, capacity, "storage must follow actual sparse edges")
	require.Zero(t, testing.AllocsPerRun(100, func() { store.PeerIDsForMembership(1) }))
}

func TestPeerMembershipConcurrentColdAndRebuild(t *testing.T) {
	nodes := types.Nodes{{ID: 1}, {ID: 2}, {ID: 3}}
	store := NewNodeStore(nodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 64 {
				assert.Equal(t, []tailcfg.NodeID{2, 3}, store.PeerIDsForMembership(1).AsSlice())
			}
		})
	}

	for range 16 {
		store.RebuildPeerMaps()
	}

	readers.Wait()
}

func peerMembershipBenchmarkPeers(nodeCount, degree int) PeersFunc {
	return func([]types.NodeView) map[types.NodeID][]types.NodeID {
		peers := make(map[types.NodeID][]types.NodeID, nodeCount)
		for i := range nodeCount {
			id := types.NodeID(i + 1) //nolint:gosec // bounded benchmark ID

			row := make([]types.NodeID, degree)
			for j := range row {
				row[j] = types.NodeID((i+degree-j)%nodeCount + 1) //nolint:gosec // bounded benchmark ID
			}

			peers[id] = row
		}

		return peers
	}
}

// Retain the old whole lookup: resolve every peer and rebuild a membership map.
func peerMembershipScanReference(store *NodeStore, id types.NodeID, patches []tailcfg.NodeID) int {
	peers := store.ListPeers(id)

	visible := make(map[tailcfg.NodeID]struct{}, peers.Len())
	for _, peer := range peers.All() {
		visible[peer.ID().NodeID()] = struct{}{}
	}

	var count int

	for _, patch := range patches {
		if _, ok := visible[patch]; ok {
			count++
		}
	}

	return count
}

func peerMembershipIndexedLookup(store *NodeStore, id types.NodeID, patches []tailcfg.NodeID) int {
	visible := store.PeerIDsForMembership(id)

	var count int

	for _, patch := range patches {
		i := sort.Search(visible.Len(), func(i int) bool { return visible.At(i) >= patch })
		if i < visible.Len() && visible.At(i) == patch {
			count++
		}
	}

	return count
}

func reportPeerMembershipCache(b *testing.B, store *NodeStore) {
	b.Helper()

	var rows, capacity int

	if cache := store.data.Load().peerMembership; cache != nil {
		cache.Range(func(_, value any) bool {
			rows++
			row, ok := value.(*peerMembershipRow)
			require.True(b, ok)

			capacity += cap(row.ids)

			return true
		})
	}

	b.ReportMetric(float64(rows), "cached-rows")
	// ID-array storage only; B/op and allocs/op include cache/map overhead.
	b.ReportMetric(float64(8*capacity), "index-ID-bytes")
}

// Cold includes fresh-cache publication plus the first row resolution/sort.
// Warm includes cache lookup and K binary searches; empty/sparse controls stay in.
func BenchmarkPeerMembershipLookup(b *testing.B) {
	for _, n := range []int{128, 1024} {
		for _, p := range []int{0, 8, n - 1} {
			b.Run(fmt.Sprintf("N=%d/P=%d", n, p), func(b *testing.B) {
				nodes := primaryRouteBenchmarkNodes(n, 0, 0)
				peers := peerMembershipBenchmarkPeers(n, p)

				for _, v := range []int{1, 128} {
					for _, k := range []int{1, 8, 64} {
						patches := make([]tailcfg.NodeID, k)
						for i := range patches {
							patches[i] = tailcfg.NodeID((i*17+2)%n + 1) //nolint:gosec // bounded benchmark ID
						}

						b.Run(fmt.Sprintf("V=%d/K=%d", v, k), func(b *testing.B) {
							for _, mode := range []string{"scan", "cold", "warm"} {
								b.Run(mode, func(b *testing.B) {
									snap := snapshotFromNodes(nodes, peers, nil, false, false)

									var store NodeStore
									store.data.Store(&snap)

									lookup := peerMembershipIndexedLookup
									if mode == "scan" {
										lookup = peerMembershipScanReference
									}

									for id := types.NodeID(1); id <= types.NodeID(v); id++ { //nolint:gosec // bounded benchmark ID
										require.Equal(b, peerMembershipScanReference(&store, id, patches), lookup(&store, id, patches))
									}

									var count int

									b.ReportAllocs()

									for b.Loop() {
										if mode == "cold" {
											next := snap
											next.peerMembership = &sync.Map{}
											store.data.Store(&next)
										}

										for id := types.NodeID(1); id <= types.NodeID(v); id++ { //nolint:gosec // bounded benchmark ID
											count += lookup(&store, id, patches)
										}
									}

									runtime.KeepAlive(count)
									reportPeerMembershipCache(b, &store)
								})
							}
						})
					}
				}
			})
		}
	}
}

// Both sides retain the sibling's route projection. Each op copies nodes,
// builds/reuses the snapshot, and optionally fans out K=8 membership checks.
func BenchmarkPeerMembershipSnapshotBatch(b *testing.B) {
	for _, n := range []int{128, 1024} {
		for _, p := range []int{0, 8, n - 1} {
			b.Run(fmt.Sprintf("N=%d/P=%d", n, p), func(b *testing.B) {
				nodes := primaryRouteBenchmarkNodes(n, 0, 0)
				peers := peerMembershipBenchmarkPeers(n, p)
				patches := []tailcfg.NodeID{2, 7, 3, 2, -1, 0, 1<<63 - 1, 17}

				for _, mode := range []struct {
					name                           string
					reusePeers, reuseRoutes, reads bool
				}{
					{"relation", false, false, false},
					{"relation-and-fanout", false, false, true},
					{"payload", true, true, false},
					{"payload-and-fanout", true, true, true},
					{"route-health", true, false, false},
				} {
					for _, indexed := range []bool{false, true} {
						name := "scan"
						build := snapshotFromNodesPeerScanReference
						lookup := peerMembershipScanReference

						if indexed {
							name = "indexed"
							build = snapshotFromNodes
							lookup = peerMembershipIndexedLookup
						}

						b.Run(mode.name+"/"+name, func(b *testing.B) {
							initial := build(nodes, peers, nil, false, false)

							var store NodeStore
							store.data.Store(&initial)

							for id := types.NodeID(1); id <= 128; id++ {
								require.Equal(b, peerMembershipScanReference(&store, id, patches), lookup(&store, id, patches))
							}

							var count int

							b.ReportAllocs()

							for b.Loop() {
								previous := store.data.Load()
								updated := maps.Clone(previous.nodesByID)

								node := updated[1]
								if mode.reuseRoutes {
									node.SessionEpoch++
								} else {
									node.Unhealthy = !node.Unhealthy
								}

								updated[1] = node
								next := build(updated, peers, previous, mode.reusePeers, mode.reuseRoutes)
								store.data.Store(&next)

								if mode.reads {
									for id := types.NodeID(1); id <= 128; id++ {
										count += lookup(&store, id, patches)
									}
								}
							}

							runtime.KeepAlive(count)
							reportPeerMembershipCache(b, &store)
						})
					}
				}
			})
		}
	}
}

func TestSnapshotFromNodes(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() (map[types.NodeID]types.Node, PeersFunc)
		validate  func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot)
	}{
		{
			name: "empty nodes",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := make(map[types.NodeID]types.Node)
				peersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
					return make(map[types.NodeID][]types.NodeID)
				}

				return nodes, peersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) { //nolint:thelper
				assert.Empty(t, snapshot.nodesByID)
				assert.Empty(t, snapshot.allNodes)
				assert.Empty(t, snapshot.peersByNode)
				assert.Empty(t, snapshot.nodesByUser)
			},
		},
		{
			name: "single node",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
				}

				return nodes, allowAllPeersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) { //nolint:thelper
				assert.Len(t, snapshot.nodesByID, 1)
				assert.Len(t, snapshot.allNodes, 1)
				assert.Len(t, snapshot.peersByNode, 1)
				assert.Len(t, snapshot.nodesByUser, 1)

				require.Contains(t, snapshot.nodesByID, types.NodeID(1))
				assert.Equal(t, nodes[1].ID, snapshot.nodesByID[1].ID)
				assert.Empty(t, snapshot.peersByNode[1]) // no other nodes, so no peers
				assert.Len(t, snapshot.nodesByUser[1], 1)
				assert.Equal(t, types.NodeID(1), snapshot.nodesByUser[1][0].ID())
			},
		},
		{
			name: "multiple nodes same user",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
					2: createTestNode(2, 1, "user1", "node2"),
				}

				return nodes, allowAllPeersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) { //nolint:thelper
				assert.Len(t, snapshot.nodesByID, 2)
				assert.Len(t, snapshot.allNodes, 2)
				assert.Len(t, snapshot.peersByNode, 2)
				assert.Len(t, snapshot.nodesByUser, 1)

				// Each node sees the other as peer (but not itself)
				assert.Len(t, snapshot.peersByNode[1], 1)
				assert.Equal(t, types.NodeID(2), snapshot.peersByNode[1][0])
				assert.Len(t, snapshot.peersByNode[2], 1)
				assert.Equal(t, types.NodeID(1), snapshot.peersByNode[2][0])
				assert.Len(t, snapshot.nodesByUser[1], 2)
			},
		},
		{
			name: "multiple nodes different users",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
					2: createTestNode(2, 2, "user2", "node2"),
					3: createTestNode(3, 1, "user1", "node3"),
				}

				return nodes, allowAllPeersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) { //nolint:thelper
				assert.Len(t, snapshot.nodesByID, 3)
				assert.Len(t, snapshot.allNodes, 3)
				assert.Len(t, snapshot.peersByNode, 3)
				assert.Len(t, snapshot.nodesByUser, 2)

				// Each node should have 2 peers (all others, but not itself)
				assert.Len(t, snapshot.peersByNode[1], 2)
				assert.Len(t, snapshot.peersByNode[2], 2)
				assert.Len(t, snapshot.peersByNode[3], 2)

				// User groupings
				assert.Len(t, snapshot.nodesByUser[1], 2) // user1 has nodes 1,3
				assert.Len(t, snapshot.nodesByUser[2], 1) // user2 has node 2
			},
		},
		{
			name: "odd-even peers filtering",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
					2: createTestNode(2, 2, "user2", "node2"),
					3: createTestNode(3, 3, "user3", "node3"),
					4: createTestNode(4, 4, "user4", "node4"),
				}
				peersFunc := oddEvenPeersFunc

				return nodes, peersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) { //nolint:thelper
				assert.Len(t, snapshot.nodesByID, 4)
				assert.Len(t, snapshot.allNodes, 4)
				assert.Len(t, snapshot.peersByNode, 4)
				assert.Len(t, snapshot.nodesByUser, 4)

				// Odd nodes should only see other odd nodes as peers
				require.Len(t, snapshot.peersByNode[1], 1)
				assert.Equal(t, types.NodeID(3), snapshot.peersByNode[1][0])

				require.Len(t, snapshot.peersByNode[3], 1)
				assert.Equal(t, types.NodeID(1), snapshot.peersByNode[3][0])

				// Even nodes should only see other even nodes as peers
				require.Len(t, snapshot.peersByNode[2], 1)
				assert.Equal(t, types.NodeID(4), snapshot.peersByNode[2][0])

				require.Len(t, snapshot.peersByNode[4], 1)
				assert.Equal(t, types.NodeID(2), snapshot.peersByNode[4][0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, peersFunc := tt.setupFunc()
			snapshot := snapshotFromNodes(nodes, peersFunc, nil, false, false)
			tt.validate(t, nodes, snapshot)
		})
	}
}

// Helper functions

func createTestNode(nodeID types.NodeID, userID uint, username, hostname string) types.Node {
	now := time.Now()
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	discoKey := key.NewDisco()

	ipv4 := netip.MustParseAddr("100.64.0.1")
	ipv6 := netip.MustParseAddr("fd7a:115c:a1e0::1")

	return types.Node{
		ID:         nodeID,
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey.Public(),
		DiscoKey:   discoKey.Public(),
		Hostname:   hostname,
		GivenName:  hostname,
		UserID:     new(userID),
		User: &types.User{
			Name:        username,
			DisplayName: username,
		},
		RegisterMethod: "test",
		IPv4:           &ipv4,
		IPv6:           &ipv6,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// Peer functions

func allowAllPeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
	ret := make(map[types.NodeID][]types.NodeID, len(nodes))
	for _, node := range nodes {
		var peers []types.NodeID

		for _, n := range nodes {
			if n.ID() != node.ID() {
				peers = append(peers, n.ID())
			}
		}

		ret[node.ID()] = peers
	}

	return ret
}

func oddEvenPeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
	ret := make(map[types.NodeID][]types.NodeID, len(nodes))
	for _, node := range nodes {
		var peers []types.NodeID

		nodeIsOdd := node.ID()%2 == 1

		for _, n := range nodes {
			if n.ID() == node.ID() {
				continue
			}

			peerIsOdd := n.ID()%2 == 1

			// Only add peer if both are odd or both are even
			if nodeIsOdd == peerIsOdd {
				peers = append(peers, n.ID())
			}
		}

		ret[node.ID()] = peers
	}

	return ret
}

func TestNodeStoreOperations(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) *NodeStore
		steps     []testStep
	}{
		{
			name: "create empty store and add single node",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				return NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "verify empty store",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Empty(t, snapshot.nodesByID)
						assert.Empty(t, snapshot.allNodes)
						assert.Empty(t, snapshot.peersByNode)
						assert.Empty(t, snapshot.nodesByUser)
					},
				},
				{
					name: "add first node",
					action: func(store *NodeStore) {
						node := createTestNode(1, 1, "user1", "node1")
						resultNode := store.PutNode(node)
						assert.True(t, resultNode.Valid(), "PutNode should return valid node")
						assert.Equal(t, node.ID, resultNode.ID())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 1)
						assert.Len(t, snapshot.allNodes, 1)
						assert.Len(t, snapshot.peersByNode, 1)
						assert.Len(t, snapshot.nodesByUser, 1)

						require.Contains(t, snapshot.nodesByID, types.NodeID(1))
						assert.Equal(t, node.ID, snapshot.nodesByID[1].ID)
						assert.Empty(t, snapshot.peersByNode[1]) // no peers yet
						assert.Len(t, snapshot.nodesByUser[1], 1)
					},
				},
			},
		},
		{
			name: "create store with initial node and add more",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				node1 := createTestNode(1, 1, "user1", "node1")
				initialNodes := types.Nodes{&node1}

				return NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "verify initial state",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 1)
						assert.Len(t, snapshot.allNodes, 1)
						assert.Len(t, snapshot.peersByNode, 1)
						assert.Len(t, snapshot.nodesByUser, 1)
						assert.Empty(t, snapshot.peersByNode[1])
					},
				},
				{
					name: "add second node same user",
					action: func(store *NodeStore) {
						node2 := createTestNode(2, 1, "user1", "node2")
						resultNode := store.PutNode(node2)
						assert.True(t, resultNode.Valid(), "PutNode should return valid node")
						assert.Equal(t, types.NodeID(2), resultNode.ID())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 2)
						assert.Len(t, snapshot.allNodes, 2)
						assert.Len(t, snapshot.peersByNode, 2)
						assert.Len(t, snapshot.nodesByUser, 1)

						// Now both nodes should see each other as peers
						assert.Len(t, snapshot.peersByNode[1], 1)
						assert.Equal(t, types.NodeID(2), snapshot.peersByNode[1][0])
						assert.Len(t, snapshot.peersByNode[2], 1)
						assert.Equal(t, types.NodeID(1), snapshot.peersByNode[2][0])
						assert.Len(t, snapshot.nodesByUser[1], 2)
					},
				},
				{
					name: "add third node different user",
					action: func(store *NodeStore) {
						node3 := createTestNode(3, 2, "user2", "node3")
						resultNode := store.PutNode(node3)
						assert.True(t, resultNode.Valid(), "PutNode should return valid node")
						assert.Equal(t, types.NodeID(3), resultNode.ID())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)
						assert.Len(t, snapshot.allNodes, 3)
						assert.Len(t, snapshot.peersByNode, 3)
						assert.Len(t, snapshot.nodesByUser, 2)

						// All nodes should see the other 2 as peers
						assert.Len(t, snapshot.peersByNode[1], 2)
						assert.Len(t, snapshot.peersByNode[2], 2)
						assert.Len(t, snapshot.peersByNode[3], 2)

						// User groupings
						assert.Len(t, snapshot.nodesByUser[1], 2) // user1 has nodes 1,2
						assert.Len(t, snapshot.nodesByUser[2], 1) // user2 has node 3
					},
				},
			},
		},
		{
			name: "test node deletion",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				node3 := createTestNode(3, 2, "user2", "node3")
				initialNodes := types.Nodes{&node1, &node2, &node3}

				return NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "verify initial 3 nodes",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)
						assert.Len(t, snapshot.allNodes, 3)
						assert.Len(t, snapshot.peersByNode, 3)
						assert.Len(t, snapshot.nodesByUser, 2)
					},
				},
				{
					name: "delete middle node",
					action: func(store *NodeStore) {
						store.DeleteNode(2)

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 2)
						assert.Len(t, snapshot.allNodes, 2)
						assert.Len(t, snapshot.peersByNode, 2)
						assert.Len(t, snapshot.nodesByUser, 2)

						// Node 2 should be gone
						assert.NotContains(t, snapshot.nodesByID, types.NodeID(2))

						// Remaining nodes should see each other as peers
						assert.Len(t, snapshot.peersByNode[1], 1)
						assert.Equal(t, types.NodeID(3), snapshot.peersByNode[1][0])
						assert.Len(t, snapshot.peersByNode[3], 1)
						assert.Equal(t, types.NodeID(1), snapshot.peersByNode[3][0])

						// User groupings updated
						assert.Len(t, snapshot.nodesByUser[1], 1) // user1 now has only node 1
						assert.Len(t, snapshot.nodesByUser[2], 1) // user2 still has node 3
					},
				},
				{
					name: "delete all remaining nodes",
					action: func(store *NodeStore) {
						store.DeleteNode(1)
						store.DeleteNode(3)

						snapshot := store.data.Load()
						assert.Empty(t, snapshot.nodesByID)
						assert.Empty(t, snapshot.allNodes)
						assert.Empty(t, snapshot.peersByNode)
						assert.Empty(t, snapshot.nodesByUser)
					},
				},
			},
		},
		{
			name: "test node updates",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				initialNodes := types.Nodes{&node1, &node2}

				return NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "verify initial hostnames",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Equal(t, "node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "node2", snapshot.nodesByID[2].Hostname)
					},
				},
				{
					name: "update node hostname",
					action: func(store *NodeStore) {
						resultNode, ok := store.UpdateNode(1, func(n *types.Node) {
							n.Hostname = "updated-node1"
							n.GivenName = "updated-node1"
						})
						assert.True(t, ok, "UpdateNode should return true for existing node")
						assert.True(t, resultNode.Valid(), "Result node should be valid")
						assert.Equal(t, "updated-node1", resultNode.Hostname())
						assert.Equal(t, "updated-node1", resultNode.GivenName())

						snapshot := store.data.Load()
						assert.Equal(t, "updated-node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "updated-node1", snapshot.nodesByID[1].GivenName)
						assert.Equal(t, "node2", snapshot.nodesByID[2].Hostname) // unchanged

						// Peers should still work correctly
						assert.Len(t, snapshot.peersByNode[1], 1)
						assert.Len(t, snapshot.peersByNode[2], 1)
					},
				},
			},
		},
		{
			name: "test with odd-even peers filtering",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				return NewNodeStore(nil, oddEvenPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "add nodes with odd-even filtering",
					action: func(store *NodeStore) {
						// Add nodes in sequence
						n1 := store.PutNode(createTestNode(1, 1, "user1", "node1"))
						assert.True(t, n1.Valid())

						n2 := store.PutNode(createTestNode(2, 2, "user2", "node2"))
						assert.True(t, n2.Valid())

						n3 := store.PutNode(createTestNode(3, 3, "user3", "node3"))
						assert.True(t, n3.Valid())

						n4 := store.PutNode(createTestNode(4, 4, "user4", "node4"))
						assert.True(t, n4.Valid())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 4)

						// Verify odd-even peer relationships
						require.Len(t, snapshot.peersByNode[1], 1)
						assert.Equal(t, types.NodeID(3), snapshot.peersByNode[1][0])

						require.Len(t, snapshot.peersByNode[2], 1)
						assert.Equal(t, types.NodeID(4), snapshot.peersByNode[2][0])

						require.Len(t, snapshot.peersByNode[3], 1)
						assert.Equal(t, types.NodeID(1), snapshot.peersByNode[3][0])

						require.Len(t, snapshot.peersByNode[4], 1)
						assert.Equal(t, types.NodeID(2), snapshot.peersByNode[4][0])
					},
				},
				{
					name: "delete odd node and verify even nodes unaffected",
					action: func(store *NodeStore) {
						store.DeleteNode(1)

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)

						// Node 3 (odd) should now have no peers
						assert.Empty(t, snapshot.peersByNode[3])

						// Even nodes should still see each other
						require.Len(t, snapshot.peersByNode[2], 1)
						assert.Equal(t, types.NodeID(4), snapshot.peersByNode[2][0])
						require.Len(t, snapshot.peersByNode[4], 1)
						assert.Equal(t, types.NodeID(2), snapshot.peersByNode[4][0])
					},
				},
			},
		},
		{
			name: "test batch modifications return correct node state",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				initialNodes := types.Nodes{&node1, &node2}

				return NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "verify initial state",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 2)
						assert.Equal(t, "node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "node2", snapshot.nodesByID[2].Hostname)
					},
				},
				{
					name: "concurrent updates should reflect all batch changes",
					action: func(store *NodeStore) {
						// Start multiple updates that will be batched together
						done1 := make(chan struct{})
						done2 := make(chan struct{})
						done3 := make(chan struct{})

						var (
							resultNode1, resultNode2 types.NodeView
							newNode3                 types.NodeView
							ok1, ok2                 bool
						)

						// These should all be processed in the same batch

						go func() {
							resultNode1, ok1 = store.UpdateNode(1, func(n *types.Node) {
								n.Hostname = "batch-updated-node1"
								n.GivenName = "batch-given-1"
							})

							close(done1)
						}()

						go func() {
							resultNode2, ok2 = store.UpdateNode(2, func(n *types.Node) {
								n.Hostname = "batch-updated-node2"
								n.GivenName = "batch-given-2"
							})

							close(done2)
						}()

						go func() {
							node3 := createTestNode(3, 1, "user1", "node3")
							newNode3 = store.PutNode(node3)

							close(done3)
						}()

						// Wait for all operations to complete
						<-done1
						<-done2
						<-done3

						// Verify the returned nodes reflect the batch state
						assert.True(t, ok1, "UpdateNode should succeed for node 1")
						assert.True(t, ok2, "UpdateNode should succeed for node 2")
						assert.True(t, resultNode1.Valid())
						assert.True(t, resultNode2.Valid())
						assert.True(t, newNode3.Valid())

						// Check that returned nodes have the updated values
						assert.Equal(t, "batch-updated-node1", resultNode1.Hostname())
						assert.Equal(t, "batch-given-1", resultNode1.GivenName())
						assert.Equal(t, "batch-updated-node2", resultNode2.Hostname())
						assert.Equal(t, "batch-given-2", resultNode2.GivenName())
						assert.Equal(t, "node3", newNode3.Hostname())

						// Verify the snapshot also reflects all changes
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)
						assert.Equal(t, "batch-updated-node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "batch-updated-node2", snapshot.nodesByID[2].Hostname)
						assert.Equal(t, "node3", snapshot.nodesByID[3].Hostname)

						// Verify peer relationships are updated correctly with new node
						assert.Len(t, snapshot.peersByNode[1], 2) // sees nodes 2 and 3
						assert.Len(t, snapshot.peersByNode[2], 2) // sees nodes 1 and 3
						assert.Len(t, snapshot.peersByNode[3], 2) // sees nodes 1 and 2
					},
				},
				{
					name: "update non-existent node returns invalid view",
					action: func(store *NodeStore) {
						resultNode, ok := store.UpdateNode(999, func(n *types.Node) {
							n.Hostname = "should-not-exist"
						})

						assert.False(t, ok, "UpdateNode should return false for non-existent node")
						assert.False(t, resultNode.Valid(), "Result should be invalid NodeView")
					},
				},
				{
					name: "multiple updates to same node in batch all see final state",
					action: func(store *NodeStore) {
						// This test verifies that when multiple updates to the same node
						// are batched together, each returned node reflects ALL changes
						// in the batch, not just the individual update's changes.
						done1 := make(chan struct{})
						done2 := make(chan struct{})
						done3 := make(chan struct{})

						var (
							resultNode1, resultNode2, resultNode3 types.NodeView
							ok1, ok2, ok3                         bool
						)

						// These updates all modify node 1 and should be batched together
						// The final state should have all three modifications applied

						go func() {
							resultNode1, ok1 = store.UpdateNode(1, func(n *types.Node) {
								n.Hostname = "multi-update-hostname"
							})

							close(done1)
						}()

						go func() {
							resultNode2, ok2 = store.UpdateNode(1, func(n *types.Node) {
								n.GivenName = "multi-update-givenname"
							})

							close(done2)
						}()

						go func() {
							resultNode3, ok3 = store.UpdateNode(1, func(n *types.Node) {
								n.Tags = []string{"tag1", "tag2"}
							})

							close(done3)
						}()

						// Wait for all operations to complete
						<-done1
						<-done2
						<-done3

						// All updates should succeed
						assert.True(t, ok1, "First update should succeed")
						assert.True(t, ok2, "Second update should succeed")
						assert.True(t, ok3, "Third update should succeed")

						// CRITICAL: Each returned node should reflect ALL changes from the batch
						// not just the change from its specific update call

						// resultNode1 (from hostname update) should also have the givenname and tags changes
						assert.Equal(t, "multi-update-hostname", resultNode1.Hostname())
						assert.Equal(t, "multi-update-givenname", resultNode1.GivenName())
						assert.Equal(t, []string{"tag1", "tag2"}, resultNode1.Tags().AsSlice())

						// resultNode2 (from givenname update) should also have the hostname and tags changes
						assert.Equal(t, "multi-update-hostname", resultNode2.Hostname())
						assert.Equal(t, "multi-update-givenname", resultNode2.GivenName())
						assert.Equal(t, []string{"tag1", "tag2"}, resultNode2.Tags().AsSlice())

						// resultNode3 (from tags update) should also have the hostname and givenname changes
						assert.Equal(t, "multi-update-hostname", resultNode3.Hostname())
						assert.Equal(t, "multi-update-givenname", resultNode3.GivenName())
						assert.Equal(t, []string{"tag1", "tag2"}, resultNode3.Tags().AsSlice())

						// Verify the snapshot also has all changes
						snapshot := store.data.Load()
						finalNode := snapshot.nodesByID[1]
						assert.Equal(t, "multi-update-hostname", finalNode.Hostname)
						assert.Equal(t, "multi-update-givenname", finalNode.GivenName)
						assert.Equal(t, []string{"tag1", "tag2"}, finalNode.Tags.List())
					},
				},
			},
		},
		{
			name: "test UpdateNode result is immutable for database save",
			setupFunc: func(t *testing.T) *NodeStore { //nolint:thelper
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				initialNodes := types.Nodes{&node1, &node2}

				return NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
			},
			steps: []testStep{
				{
					name: "verify returned node is complete and consistent",
					action: func(store *NodeStore) {
						// Update a node and verify the returned view is complete
						resultNode, ok := store.UpdateNode(1, func(n *types.Node) {
							n.Hostname = "db-save-hostname"
							n.GivenName = "db-save-given"
							n.Tags = []string{"db-tag1", "db-tag2"}
						})

						assert.True(t, ok, "UpdateNode should succeed")
						assert.True(t, resultNode.Valid(), "Result should be valid")

						// Verify the returned node has all expected values
						assert.Equal(t, "db-save-hostname", resultNode.Hostname())
						assert.Equal(t, "db-save-given", resultNode.GivenName())
						assert.Equal(t, []string{"db-tag1", "db-tag2"}, resultNode.Tags().AsSlice())

						// Convert to struct as would be done for database save
						nodePtr := resultNode.AsStruct()
						assert.NotNil(t, nodePtr)
						assert.Equal(t, "db-save-hostname", nodePtr.Hostname)
						assert.Equal(t, "db-save-given", nodePtr.GivenName)
						assert.Equal(t, []string{"db-tag1", "db-tag2"}, nodePtr.Tags.List())

						// Verify the snapshot also reflects the same state
						snapshot := store.data.Load()
						storedNode := snapshot.nodesByID[1]
						assert.Equal(t, "db-save-hostname", storedNode.Hostname)
						assert.Equal(t, "db-save-given", storedNode.GivenName)
						assert.Equal(t, []string{"db-tag1", "db-tag2"}, storedNode.Tags.List())
					},
				},
				{
					name: "concurrent updates all return consistent final state for DB save",
					action: func(store *NodeStore) {
						// Multiple goroutines updating the same node
						// All should receive the final batch state suitable for DB save
						done1 := make(chan struct{})
						done2 := make(chan struct{})
						done3 := make(chan struct{})

						var (
							result1, result2, result3 types.NodeView
							ok1, ok2, ok3             bool
						)

						// Start concurrent updates

						go func() {
							result1, ok1 = store.UpdateNode(1, func(n *types.Node) {
								n.Hostname = "concurrent-db-hostname"
							})

							close(done1)
						}()

						go func() {
							result2, ok2 = store.UpdateNode(1, func(n *types.Node) {
								n.GivenName = "concurrent-db-given"
							})

							close(done2)
						}()

						go func() {
							result3, ok3 = store.UpdateNode(1, func(n *types.Node) {
								n.Tags = []string{"concurrent-tag"}
							})

							close(done3)
						}()

						// Wait for all to complete
						<-done1
						<-done2
						<-done3

						assert.True(t, ok1 && ok2 && ok3, "All updates should succeed")

						// All results should be valid and suitable for database save
						assert.True(t, result1.Valid())
						assert.True(t, result2.Valid())
						assert.True(t, result3.Valid())

						// Convert each to struct as would be done for DB save
						nodePtr1 := result1.AsStruct()
						nodePtr2 := result2.AsStruct()
						nodePtr3 := result3.AsStruct()

						// All should have the complete final state
						assert.Equal(t, "concurrent-db-hostname", nodePtr1.Hostname)
						assert.Equal(t, "concurrent-db-given", nodePtr1.GivenName)
						assert.Equal(t, []string{"concurrent-tag"}, nodePtr1.Tags.List())

						assert.Equal(t, "concurrent-db-hostname", nodePtr2.Hostname)
						assert.Equal(t, "concurrent-db-given", nodePtr2.GivenName)
						assert.Equal(t, []string{"concurrent-tag"}, nodePtr2.Tags.List())

						assert.Equal(t, "concurrent-db-hostname", nodePtr3.Hostname)
						assert.Equal(t, "concurrent-db-given", nodePtr3.GivenName)
						assert.Equal(t, []string{"concurrent-tag"}, nodePtr3.Tags.List())

						// Verify consistency with stored state
						snapshot := store.data.Load()
						storedNode := snapshot.nodesByID[1]
						assert.Equal(t, nodePtr1.Hostname, storedNode.Hostname)
						assert.Equal(t, nodePtr1.GivenName, storedNode.GivenName)
						assert.Equal(t, nodePtr1.Tags, storedNode.Tags)
					},
				},
				{
					name: "verify returned node preserves all fields for DB save",
					action: func(store *NodeStore) {
						// Get initial state
						snapshot := store.data.Load()
						originalNode := snapshot.nodesByID[2]
						originalIPv4 := originalNode.IPv4
						originalIPv6 := originalNode.IPv6
						originalCreatedAt := originalNode.CreatedAt
						originalUser := originalNode.User

						// Update only hostname
						resultNode, ok := store.UpdateNode(2, func(n *types.Node) {
							n.Hostname = "preserve-test-hostname"
						})

						assert.True(t, ok, "Update should succeed")

						// Convert to struct for DB save
						nodeForDB := resultNode.AsStruct()

						// Verify all fields are preserved
						assert.Equal(t, "preserve-test-hostname", nodeForDB.Hostname)
						assert.Equal(t, originalIPv4, nodeForDB.IPv4)
						assert.Equal(t, originalIPv6, nodeForDB.IPv6)
						assert.Equal(t, originalCreatedAt, nodeForDB.CreatedAt)
						assert.Equal(t, originalUser.Name, nodeForDB.User.Name)
						assert.Equal(t, types.NodeID(2), nodeForDB.ID)

						// These fields should be suitable for direct database save
						assert.NotNil(t, nodeForDB.IPv4)
						assert.NotNil(t, nodeForDB.IPv6)
						assert.False(t, nodeForDB.CreatedAt.IsZero())
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.setupFunc(t)

			store.Start()
			defer store.Stop()

			for _, step := range tt.steps {
				t.Run(step.name, func(t *testing.T) {
					step.action(store)
				})
			}
		})
	}
}

type testStep struct {
	name   string
	action func(store *NodeStore)
}

// --- Additional NodeStore concurrency, batching, race, resource, timeout, and allocation tests ---

// Helper for concurrent test nodes.
func createConcurrentTestNode(id types.NodeID, hostname string) types.Node {
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	return types.Node{
		ID:         id,
		Hostname:   hostname,
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey.Public(),
		UserID:     new(uint(1)),
		User: &types.User{
			Name: "concurrent-test-user",
		},
	}
}

// --- Concurrency: concurrent PutNode operations ---.
func TestNodeStoreConcurrentPutNode(t *testing.T) {
	const concurrentOps = 20

	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	var wg sync.WaitGroup

	results := make(chan bool, concurrentOps)
	for nodeID := 1; nodeID <= concurrentOps; nodeID++ {
		wg.Go(func() {
			node := createConcurrentTestNode(types.NodeID(nodeID), "concurrent-node") //nolint:gosec // safe conversion in test

			resultNode := store.PutNode(node)
			results <- resultNode.Valid()
		})
	}

	wg.Wait()
	close(results)

	successCount := 0

	for success := range results {
		if success {
			successCount++
		}
	}

	require.Equal(t, concurrentOps, successCount, "All concurrent PutNode operations should succeed")
}

// --- Batching: concurrent ops fit in one batch ---.
func TestNodeStoreBatchingEfficiency(t *testing.T) {
	const ops = 15 // more than batchSize

	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	var wg sync.WaitGroup

	results := make(chan bool, ops)
	for nodeID := 1; nodeID <= ops; nodeID++ {
		wg.Go(func() {
			node := createConcurrentTestNode(types.NodeID(nodeID), "batch-node") //nolint:gosec // test code with small integers

			resultNode := store.PutNode(node)
			results <- resultNode.Valid()
		})
	}

	wg.Wait()
	close(results)

	successCount := 0

	for success := range results {
		if success {
			successCount++
		}
	}

	require.Equal(t, ops, successCount, "All batch PutNode operations should succeed")
}

// --- Race conditions: many goroutines on same node ---.
func TestNodeStoreRaceConditions(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	nodeID := types.NodeID(1)
	node := createConcurrentTestNode(nodeID, "race-node")
	resultNode := store.PutNode(node)
	require.True(t, resultNode.Valid())

	const (
		numGoroutines   = 30
		opsPerGoroutine = 10
	)

	var wg sync.WaitGroup

	errors := make(chan error, numGoroutines*opsPerGoroutine)

	for gid := range numGoroutines {
		wg.Go(func() {
			for j := range opsPerGoroutine {
				switch j % 3 {
				case 0:
					resultNode, _ := store.UpdateNode(nodeID, func(n *types.Node) {
						n.Hostname = "race-updated"
					})
					if !resultNode.Valid() {
						errors <- fmt.Errorf("UpdateNode failed in goroutine %d, op %d", gid, j) //nolint:err113
					}
				case 1:
					retrieved, found := store.GetNode(nodeID)
					if !found || !retrieved.Valid() {
						errors <- fmt.Errorf("GetNode failed in goroutine %d, op %d", gid, j) //nolint:err113
					}
				case 2:
					newNode := createConcurrentTestNode(nodeID, "race-put")

					resultNode := store.PutNode(newNode)
					if !resultNode.Valid() {
						errors <- fmt.Errorf("PutNode failed in goroutine %d, op %d", gid, j) //nolint:err113
					}
				}
			}
		})
	}

	wg.Wait()
	close(errors)

	errorCount := 0

	for err := range errors {
		t.Error(err)

		errorCount++
	}

	if errorCount > 0 {
		t.Fatalf("Race condition test failed with %d errors", errorCount)
	}
}

// --- Resource cleanup: goroutine leak detection ---.
func TestNodeStoreResourceCleanup(t *testing.T) {
	// initialGoroutines := runtime.NumGoroutine()
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	// Wait for store to be ready
	var afterStartGoroutines int

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		afterStartGoroutines = runtime.NumGoroutine()
		assert.Positive(c, afterStartGoroutines) // Just ensure we have a valid count
	}, time.Second, 10*time.Millisecond, "store should be running")

	const ops = 100
	for i := range ops {
		nodeID := types.NodeID(i + 1) //nolint:gosec // test code with small integers
		node := createConcurrentTestNode(nodeID, "cleanup-node")
		resultNode := store.PutNode(node)
		assert.True(t, resultNode.Valid())
		store.UpdateNode(nodeID, func(n *types.Node) {
			n.Hostname = "cleanup-updated"
		})
		retrieved, found := store.GetNode(nodeID)
		assert.True(t, found && retrieved.Valid())

		if i%10 == 9 {
			store.DeleteNode(nodeID)
		}
	}

	runtime.GC()

	// Wait for goroutines to settle and check for leaks
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		finalGoroutines := runtime.NumGoroutine()
		assert.LessOrEqual(c, finalGoroutines, afterStartGoroutines+2,
			"Potential goroutine leak: started with %d, ended with %d", afterStartGoroutines, finalGoroutines)
	}, time.Second, 10*time.Millisecond, "goroutines should not leak")
}

// --- Timeout/deadlock: operations complete within reasonable time ---.
func TestNodeStoreOperationTimeout(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	const ops = 30

	var wg sync.WaitGroup

	putResults := make([]error, ops)
	updateResults := make([]error, ops)

	// Launch all PutNode operations concurrently
	for idx := 1; idx <= ops; idx++ {
		id := types.NodeID(idx) //nolint:gosec // test code with small integers

		wg.Go(func() {
			startPut := time.Now()
			fmt.Printf("[TestNodeStoreOperationTimeout] %s: PutNode(%d) starting\n", startPut.Format("15:04:05.000"), id)
			node := createConcurrentTestNode(id, "timeout-node")
			resultNode := store.PutNode(node)
			endPut := time.Now()
			fmt.Printf("[TestNodeStoreOperationTimeout] %s: PutNode(%d) finished, valid=%v, duration=%v\n", endPut.Format("15:04:05.000"), id, resultNode.Valid(), endPut.Sub(startPut))

			if !resultNode.Valid() {
				putResults[idx-1] = fmt.Errorf("PutNode failed for node %d", id) //nolint:err113
			}
		})
	}

	wg.Wait()

	// Launch all UpdateNode operations concurrently
	wg = sync.WaitGroup{}

	for idx := 1; idx <= ops; idx++ {
		id := types.NodeID(idx) //nolint:gosec // test code with small integers

		wg.Go(func() {
			startUpdate := time.Now()
			fmt.Printf("[TestNodeStoreOperationTimeout] %s: UpdateNode(%d) starting\n", startUpdate.Format("15:04:05.000"), id)
			resultNode, ok := store.UpdateNode(id, func(n *types.Node) {
				n.Hostname = "timeout-updated"
			})
			endUpdate := time.Now()
			fmt.Printf("[TestNodeStoreOperationTimeout] %s: UpdateNode(%d) finished, valid=%v, ok=%v, duration=%v\n", endUpdate.Format("15:04:05.000"), id, resultNode.Valid(), ok, endUpdate.Sub(startUpdate))

			if !ok || !resultNode.Valid() {
				updateResults[idx-1] = fmt.Errorf("UpdateNode failed for node %d", id) //nolint:err113
			}
		})
	}

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		errorCount := 0

		for _, err := range putResults {
			if err != nil {
				t.Error(err)

				errorCount++
			}
		}

		for _, err := range updateResults {
			if err != nil {
				t.Error(err)

				errorCount++
			}
		}

		if errorCount == 0 {
			t.Log("All concurrent operations completed successfully within timeout")
		} else {
			t.Fatalf("Some concurrent operations failed: %d errors", errorCount)
		}
	case <-ctx.Done():
		fmt.Println("[TestNodeStoreOperationTimeout] Timeout reached, test failed")
		t.Fatal("Operations timed out - potential deadlock or resource issue")
	}
}

// --- Edge case: update non-existent node ---.
func TestNodeStoreUpdateNonExistentNode(t *testing.T) {
	for i := range 10 {
		store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
		store.Start()

		nonExistentID := types.NodeID(999 + i) //nolint:gosec // test code with small integers
		updateCallCount := 0

		fmt.Printf("[TestNodeStoreUpdateNonExistentNode] UpdateNode(%d) starting\n", nonExistentID)
		resultNode, ok := store.UpdateNode(nonExistentID, func(n *types.Node) {
			updateCallCount++
			n.Hostname = "should-never-be-called"
		})
		fmt.Printf("[TestNodeStoreUpdateNonExistentNode] UpdateNode(%d) finished, valid=%v, ok=%v, updateCallCount=%d\n", nonExistentID, resultNode.Valid(), ok, updateCallCount)
		assert.False(t, ok, "UpdateNode should return false for non-existent node")
		assert.False(t, resultNode.Valid(), "UpdateNode should return invalid node for non-existent node")
		assert.Equal(t, 0, updateCallCount, "UpdateFn should not be called for non-existent node")
		store.Stop()
	}
}

// --- Allocation benchmark ---.
func BenchmarkNodeStoreAllocations(b *testing.B) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	for i := 0; b.Loop(); i++ {
		nodeID := types.NodeID(i + 1) //nolint:gosec // benchmark code with small integers
		node := createConcurrentTestNode(nodeID, "bench-node")
		store.PutNode(node)
		store.UpdateNode(nodeID, func(n *types.Node) {
			n.Hostname = "bench-updated"
		})
		store.GetNode(nodeID)

		if i%10 == 9 {
			store.DeleteNode(nodeID)
		}
	}
}

func TestNodeStoreAllocationStats(t *testing.T) {
	res := testing.Benchmark(BenchmarkNodeStoreAllocations)
	allocs := res.AllocsPerOp()
	t.Logf("NodeStore allocations per op: %.2f", float64(allocs))
}

// TestRebuildPeerMapsWithChangedPeersFunc tests that RebuildPeerMaps correctly
// rebuilds the peer map when the peersFunc behavior changes.
// This simulates what happens when SetNodeTags changes node tags and the
// PolicyManager's matchers are updated, requiring the peer map to be rebuilt.
func TestRebuildPeerMapsWithChangedPeersFunc(t *testing.T) {
	// Create a peersFunc that can be controlled via a channel
	// Initially it returns all nodes as peers, then we change it to return no peers
	allowPeers := true

	// This simulates how PolicyManager.BuildPeerMap works - it reads state
	// that can change between calls
	dynamicPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
		ret := make(map[types.NodeID][]types.NodeID, len(nodes))
		if allowPeers {
			// Allow all peers
			for _, node := range nodes {
				var peers []types.NodeID

				for _, n := range nodes {
					if n.ID() != node.ID() {
						peers = append(peers, n.ID())
					}
				}

				ret[node.ID()] = peers
			}
		} else {
			// Allow no peers
			for _, node := range nodes {
				ret[node.ID()] = []types.NodeID{}
			}
		}

		return ret
	}

	// Create nodes
	node1 := createTestNode(1, 1, "user1", "node1")
	node2 := createTestNode(2, 2, "user2", "node2")
	initialNodes := types.Nodes{&node1, &node2}

	// Create store with dynamic peersFunc
	store := NewNodeStore(initialNodes, dynamicPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	// Initially, nodes should see each other as peers
	snapshot := store.data.Load()
	require.Len(t, snapshot.peersByNode[1], 1, "node1 should have 1 peer initially")
	require.Len(t, snapshot.peersByNode[2], 1, "node2 should have 1 peer initially")
	require.Equal(t, types.NodeID(2), snapshot.peersByNode[1][0])
	require.Equal(t, types.NodeID(1), snapshot.peersByNode[2][0])

	// Now "change the policy" by disabling peers
	allowPeers = false

	// Call RebuildPeerMaps to rebuild with the new behavior
	store.RebuildPeerMaps()

	// After rebuild, nodes should have no peers
	snapshot = store.data.Load()
	assert.Empty(t, snapshot.peersByNode[1], "node1 should have no peers after rebuild")
	assert.Empty(t, snapshot.peersByNode[2], "node2 should have no peers after rebuild")

	// Verify that ListPeers returns the correct result
	peers1 := store.ListPeers(1)
	peers2 := store.ListPeers(2)

	assert.Equal(t, 0, peers1.Len(), "ListPeers for node1 should return empty")
	assert.Equal(t, 0, peers2.Len(), "ListPeers for node2 should return empty")

	// Now re-enable peers and rebuild again
	allowPeers = true

	store.RebuildPeerMaps()

	// Nodes should see each other again
	snapshot = store.data.Load()
	require.Len(t, snapshot.peersByNode[1], 1, "node1 should have 1 peer after re-enabling")
	require.Len(t, snapshot.peersByNode[2], 1, "node2 should have 1 peer after re-enabling")

	peers1 = store.ListPeers(1)
	peers2 = store.ListPeers(2)

	assert.Equal(t, 1, peers1.Len(), "ListPeers for node1 should return 1")
	assert.Equal(t, 1, peers2.Len(), "ListPeers for node2 should return 1")
}

// TestGetNodesByMachineKeyAllUsers ensures the lookup returns every node sharing
// a machine key keyed by owning UserID (tagged nodes under UserID(0)), so callers
// see the full set instead of a single arbitrary pick.
func TestGetNodesByMachineKeyAllUsers(t *testing.T) {
	mk := key.NewMachine().Public()

	t.Run("empty when absent", func(t *testing.T) {
		store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

		store.Start()
		defer store.Stop()

		require.Empty(t, store.GetNodesByMachineKeyAllUsers(mk))
	})

	t.Run("returns all user-owned nodes keyed by user", func(t *testing.T) {
		store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

		store.Start()
		defer store.Stop()

		n1 := createTestNode(1, 1, "user1", "node1")
		n1.MachineKey = mk
		n2 := createTestNode(2, 2, "user2", "node2")
		n2.MachineKey = mk

		store.PutNode(n1)
		store.PutNode(n2)

		all := store.GetNodesByMachineKeyAllUsers(mk)
		require.Len(t, all, 2)
		require.Equal(t, types.NodeID(1), all[types.UserID(1)].ID())
		require.Equal(t, types.NodeID(2), all[types.UserID(2)].ID())
	})

	t.Run("tagged node indexed under UserID(0)", func(t *testing.T) {
		store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

		store.Start()
		defer store.Stop()

		owned := createTestNode(1, 1, "user1", "node1")
		owned.MachineKey = mk
		tagged := createTestNode(3, 3, "user3", "node3")
		tagged.MachineKey = mk
		tagged.UserID = nil
		tagged.User = nil
		tagged.Tags = []string{"tag:foo"}

		store.PutNode(owned)
		store.PutNode(tagged)

		all := store.GetNodesByMachineKeyAllUsers(mk)
		require.Len(t, all, 2)
		require.Equal(t, types.NodeID(1), all[types.UserID(1)].ID())
		require.True(t, all[types.UserID(0)].IsTagged())
		require.Equal(t, types.NodeID(3), all[types.UserID(0)].ID())
	})
}

// TestPeerIrrelevantWriteReusesPeerMap ensures writes that cannot alter peer
// visibility neither run peersFunc nor copy the immutable adjacency map.
//
// peersByNode is derived from addresses, ownership, routes, tags, and exit-node
// status. LastSeen and node keys are payload/index data, so neither can change
// adjacency.
func TestPeerIrrelevantWriteReusesPeerMap(t *testing.T) {
	var peersCalls atomic.Int64

	countingPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
		peersCalls.Add(1)

		return allowAllPeersFunc(nodes)
	}

	node1 := createTestNode(1, 1, "user1", "node1")
	node2 := createTestNode(2, 2, "user2", "node2")

	store := NewNodeStore(types.Nodes{&node1, &node2}, countingPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()

	defer store.Stop()

	// Ignore the initial snapshot build.
	peersCalls.Store(0)

	before := store.data.Load()
	require.NotEmpty(t, before.peersByNode[1])

	now := time.Now()
	_, ok := store.UpdateNode(1, func(n *types.Node) {
		n.LastSeen = &now
	})
	require.True(t, ok, "update should apply")

	newNodeKey := key.NewNode().Public()
	_, ok = store.UpdateNode(1, func(n *types.Node) {
		n.NodeKey = newNodeKey
	})
	require.True(t, ok, "key rotation should apply")

	indexed, ok := store.GetNodeByNodeKey(newNodeKey)
	require.True(t, ok, "rotated key must be present in the rebuilt key index")
	require.Equal(t, types.NodeID(1), indexed.ID())

	peersOf2 := store.ListPeers(2)
	require.Equal(t, 1, peersOf2.Len())
	require.Equal(t, newNodeKey, peersOf2.At(0).NodeKey(),
		"reused adjacency must resolve to the fresh view")

	require.Equalf(t, int64(0), peersCalls.Load(),
		"payload/index-only writes must not recompute the peer map, got %d recomputations",
		peersCalls.Load())

	_, ok = store.UpdateNode(1, func(n *types.Node) {
		n.User = nil
	})
	require.True(t, ok, "user association update should apply")
	require.Equal(t, int64(1), peersCalls.Load(),
		"a BuildPeerMap input must recompute peer adjacency")
}

// TestHealthOnlyWriteReusesPeerMap ensures a health flip re-elects routes
// without recomputing peer adjacency.
func TestHealthOnlyWriteReusesPeerMap(t *testing.T) {
	var peersCalls atomic.Int64

	countingPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
		peersCalls.Add(1)

		return allowAllPeersFunc(nodes)
	}

	// Set up two HA candidates for the same prefix.
	node1 := createTestNode(1, 1, "user1", "router1")
	node2 := createTestNode(2, 1, "user1", "router2")

	pfx := netip.MustParsePrefix("10.99.0.0/24")
	node1.Hostinfo = &tailcfg.Hostinfo{Hostname: "router1", RoutableIPs: []netip.Prefix{pfx}}
	node2.Hostinfo = &tailcfg.Hostinfo{Hostname: "router2", RoutableIPs: []netip.Prefix{pfx}}
	node1.ApprovedRoutes = append(node1.ApprovedRoutes, pfx)
	node2.ApprovedRoutes = append(node2.ApprovedRoutes, pfx)

	online := true
	node1.IsOnline = &online
	node2.IsOnline = &online

	store := NewNodeStore(types.Nodes{&node1, &node2}, countingPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()

	defer store.Stop()

	primary, ok := store.PrimaryRouteFor(pfx)
	require.True(t, ok)
	require.Equal(t, types.NodeID(1), primary)

	peersCalls.Store(0) // ignore initial snapshot build

	// Healthy -> healthy (no-op): no election, no relation rebuild.
	_, ok = store.UpdateNode(1, func(n *types.Node) {
		// Simulate BatchSetNodeHealth setter semantics with the same
		// stored value. healthSetter(healthy=true) sets Unhealthy=false;
		// node already has Unhealthy=false.
		healthSetter(true)(n)
	})
	require.True(t, ok)

	// Healthy -> unhealthy (real transition): election must run, but
	// relation must NOT be recomputed (Unhealthy is election-relevant,
	// not relation-relevant).
	_, ok = store.UpdateNode(1, healthSetter(false))
	require.True(t, ok)
	primary, ok = store.PrimaryRouteFor(pfx)
	require.True(t, ok)
	require.Equal(t, types.NodeID(2), primary)

	// Unhealthy -> unhealthy (no-op): no relation rebuild.
	_, ok = store.UpdateNode(1, healthSetter(false))
	require.True(t, ok)

	require.Equal(t, int64(0), peersCalls.Load(),
		"no health-only write may recompute the peer map; got %d recomputations",
		peersCalls.Load())
}

// TestPrimaryRoutesForNodeSorted checks a router's primaries come back in
// a stable order: they render into its self node, which the mapper resends
// whenever it differs from what the node holds (issue #3502).
func TestPrimaryRoutesForNodeSorted(t *testing.T) {
	node := createTestNode(1, 1, "user1", "router")

	prefixes := make([]netip.Prefix, 0, 8)
	for i := range 8 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
	}

	node.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: prefixes}
	node.ApprovedRoutes = prefixes
	node.IsOnline = new(true)

	store := NewNodeStore(types.Nodes{&node}, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	for range 20 {
		require.Equal(t, prefixes, store.PrimaryRoutesForNode(1))
	}
}

func BenchmarkSnapshotPayloadDense(b *testing.B) {
	const nodeCount = 500

	nodes := make(map[types.NodeID]types.Node, nodeCount)
	for i := 1; i <= nodeCount; i++ {
		id := types.NodeID(i)                                   //nolint:gosec // bounded benchmark node count
		nodes[id] = createTestNode(id, uint(i), "user", "node") //nolint:gosec // bounded benchmark node count
	}

	initial := snapshotFromNodes(nodes, allowAllPeersFunc, nil, false, false)
	n := nodes[1]
	n.LastSeen = new(time.Now())
	nodes[1] = n

	b.Run("reuse-peer-adjacency", func(b *testing.B) {
		previous := initial

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			next := snapshotFromNodes(nodes, allowAllPeersFunc, &previous, true, true)
			previous = next
		}
	})

	b.Run("rebuild-peer-adjacency", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			snapshotFromNodes(nodes, allowAllPeersFunc, nil, false, false)
		}
	})
}

// TestRebuildPeerMapsAfterStopReturns ensures a rebuild requested after the
// writer has exited does not block the caller forever.
func TestRebuildPeerMapsAfterStopReturns(t *testing.T) {
	node := createTestNode(1, 1, "user1", "node1")
	store := NewNodeStore(types.Nodes{&node}, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()
	store.Stop()

	done := make(chan struct{})

	go func() {
		store.RebuildPeerMaps()
		close(done)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "RebuildPeerMaps hung after Stop")
}

// TestUpdateNodeRecomputesPeersOnlyForRelationInputs pins which fields make a
// write recompute peer adjacency: the inputs that force a peer-map rebuild
// (an announced but unapproved route is included on purpose).
func TestUpdateNodeRecomputesPeersOnlyForRelationInputs(t *testing.T) {
	subnet := netip.MustParsePrefix("10.77.0.0/24")

	tests := []struct {
		name          string
		mutate        func(*types.Node)
		wantRecompute bool
	}{
		{name: "last seen", mutate: func(n *types.Node) { n.LastSeen = new(time.Now()) }},
		{name: "node key", mutate: func(n *types.Node) { n.NodeKey = key.NewNode().Public() }},
		{name: "expiry", mutate: func(n *types.Node) { n.Expiry = new(time.Now()) }},
		{name: "online", mutate: func(n *types.Node) { n.IsOnline = new(true) }},
		{name: "unhealthy", mutate: func(n *types.Node) { n.Unhealthy = true }},
		{
			name: "endpoints",
			mutate: func(n *types.Node) {
				n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:41641")}
			},
		},
		{name: "tags", mutate: func(n *types.Node) { n.Tags = []string{"tag:x"} }, wantRecompute: true},
		{
			name: "ipv4",
			mutate: func(n *types.Node) {
				ip := netip.MustParseAddr("100.64.9.9")
				n.IPv4 = &ip
			},
			wantRecompute: true,
		},
		{
			name: "announced route",
			mutate: func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
			},
			wantRecompute: true,
		},
		{name: "user association", mutate: func(n *types.Node) { n.User = nil }, wantRecompute: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var peersCalls atomic.Int64

			countingPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
				peersCalls.Add(1)

				return allowAllPeersFunc(nodes)
			}

			node1 := createTestNode(1, 1, "user1", "node1")
			node2 := createTestNode(2, 2, "user2", "node2")

			store := NewNodeStore(types.Nodes{&node1, &node2}, countingPeersFunc, TestBatchSize, TestBatchTimeout)
			store.Start()

			defer store.Stop()

			store.PeerIDsForMembership(1)
			membership := store.data.Load().peerMembership
			peersCalls.Store(0)

			_, ok := store.UpdateNode(1, tt.mutate)
			require.True(t, ok)

			var want int64
			if tt.wantRecompute {
				want = 1
			}

			require.Equal(t, want, peersCalls.Load())

			if tt.wantRecompute {
				require.NotSame(t, membership, store.data.Load().peerMembership)
			} else {
				require.Same(t, membership, store.data.Load().peerMembership)
			}
		})
	}
}

// TestUpdateNodeDiff proves the update returns the node the writer replaced
// alongside the result, and an invalid before for a missing node.
func TestUpdateNodeDiff(t *testing.T) {
	node := createTestNode(1, 1, "user1", "node1")
	oldKey := node.NodeKey

	store := NewNodeStore(types.Nodes{&node}, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()

	defer store.Stop()

	newKey := key.NewNode().Public()
	before, after, ok := store.UpdateNodeDiff(1, func(n *types.Node) { n.NodeKey = newKey })
	require.True(t, ok)
	assert.Equal(t, oldKey, before.NodeKey())
	assert.Equal(t, newKey, after.NodeKey())

	before, _, ok = store.UpdateNodeDiff(99, func(*types.Node) {})
	assert.False(t, ok)
	assert.False(t, before.Valid())
}

// TestListPeersExcludesSelf proves a node is never returned among its own
// peers, on both the snapshot path and the explicit peer-ID path.
//
// The explicit path is reached for incremental updates, where the caller
// passes the IDs named by a change batch — a batch that may include the
// recipient. Without the exclusion the recipient reaches the mapper as one of
// its own peers, is emitted in [tailcfg.MapResponse.PeersChanged], and the
// Tailscale client merges it into its peer map next to the self node.
func TestListPeersExcludesSelf(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("peer-user")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "peer-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	allIDs := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		allIDs = append(allIDs, n.ID)
	}

	for _, self := range allIDs {
		t.Run(self.String(), func(t *testing.T) {
			snapshot := s.ListPeers(self)
			for _, peer := range snapshot.All() {
				require.NotEqual(t, self, peer.ID(), "node listed in its own snapshot peers")
			}

			// Every node named, the recipient included.
			named := s.ListPeers(self, allIDs...)
			require.Equal(t, len(allIDs)-1, named.Len(), "self must be dropped, every other named node kept")

			for _, peer := range named.All() {
				require.NotEqual(t, self, peer.ID(), "node listed in its own named peers")
			}

			// Naming only the recipient yields nothing.
			require.Zero(t, s.ListPeers(self, self).Len(), "naming only self must yield no peers")
		})
	}
}

// fatalfer is the subset of *testing.T / *testing.B / *rapid.T that the
// NodeStore-against-policy helpers need, so property tests and
// benchmarks can share them.
type fatalfer interface {
	Fatalf(format string, args ...any)
}

// nodeStoreWithPolicy builds a [NodeStore] whose [PeersFunc] runs a real
// [policyv2.PolicyManager], mirroring how [State] wires the two together.
func nodeStoreWithPolicy(t fatalfer, pol string, users []types.User, nodes types.Nodes) (*NodeStore, *policyv2.PolicyManager) {
	pm, err := policyv2.NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	store := NewNodeStore(nodes, policyPeersFunc(pm), TestBatchSize, TestBatchTimeout)
	store.Start()

	return store, pm
}

// syncPolicy does what [State.updatePolicyManagerNodes] does after a
// NodeStore write: feed the policy manager the current nodes, and rebuild
// the peer maps only if it reports a policy-affecting change.
func syncPolicy(t fatalfer, store *NodeStore, pm *policyv2.PolicyManager) {
	changed, err := pm.SetNodes(store.ListNodes())
	if err != nil {
		t.Fatalf("SetNodes: %v", err)
	}

	if changed {
		store.RebuildPeerMaps()
	}
}

// checkAdjacencyMatchesFullBuild compares the NodeStore's current
// adjacency — however it got there, including the reused-from-previous-
// snapshot path taken for payload-only writes — against
// [policyv2.PolicyManager.BuildPeerMap] from a fresh policy manager over
// the same nodes. The fresh manager keeps the oracle independent of the
// one the NodeStore writer updates. Divergence means the store served
// stale adjacency.
func checkAdjacencyMatchesFullBuild(t fatalfer, store *NodeStore, pol string, users []types.User) {
	snap := store.data.Load()
	nodes := views.SliceOf(snap.allNodes)

	fresh, err := policyv2.NewPolicyManager([]byte(pol), users, nodes)
	if err != nil {
		t.Fatalf("fresh policy: %v", err)
	}

	want := fresh.BuildPeerMap(nodes)

	for id := range snap.nodesByID {
		got := slices.Sorted(slices.Values(snap.peersByNode[id]))

		exp := slices.Sorted(slices.Values(want[id]))
		if !slices.Equal(got, exp) {
			t.Fatalf("node %d: adjacency %v, full build %v", id, got, exp)
		}
	}
}

// Policy shapes shared by TestNodeStoreAdjacencyMatchesFullBuild and the
// NodeStore write benchmarks below: a global ACL, autogroup:self, and a
// via grant. hscontrol/policy/v2/policy_test.go keeps its own copy since
// test packages can't share one.
const (
	policyGlobal = `{
		"groups": {"group:a": ["u1@"]},
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [
			{"action": "accept", "src": ["group:a"], "dst": ["tag:srv:*"]},
			{"action": "accept", "src": ["u2@"], "dst": ["10.33.0.0/24:*"]}
		]}`

	policyAutogroupSelf = `{
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`

	policyVia = `{
		"tagOwners": {"tag:router": ["u1@"]},
		"grants": [{"src": ["u2@"], "dst": ["10.33.0.0/24"], "ip": ["*"], "via": ["tag:router"]}]}`
)

// TestNodeStoreAdjacencyMatchesFullBuild drives random node mutations
// through a real [NodeStore] wired to a real [policyv2.PolicyManager] and
// checks, after every step, that the resulting adjacency — including
// whatever [NodeStore] served from its reused-peers path — matches a
// fresh [policyv2.PolicyManager.BuildPeerMap] over the same nodes. This is
// the safety net for later NodeStore/policy changes: divergence here is a
// real bug in the shipped reuse path.
func TestNodeStoreAdjacencyMatchesFullBuild(t *testing.T) {
	users := []types.User{
		{ID: 1, Name: "u1"},
		{ID: 2, Name: "u2"},
	}
	subnet := netip.MustParsePrefix("10.33.0.0/24")

	for _, tc := range []struct {
		name string
		pol  string
	}{
		{name: "global", pol: policyGlobal},
		{name: "autogroup-self", pol: policyAutogroupSelf},
		{name: "via", pol: policyVia},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				nodes := make(types.Nodes, 0, 6)

				for i := 1; i <= 6; i++ {
					n := createTestNode(types.NodeID(i), uint(1+i%2), fmt.Sprintf("u%d", 1+i%2), fmt.Sprintf("n%d", i))
					ip4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i)})
					n.IPv4 = &ip4
					n.IPv6 = nil
					n.User = &users[i%2]
					nodes = append(nodes, &n)
				}

				store, pm := nodeStoreWithPolicy(rt, tc.pol, users, nodes)
				defer store.Stop()

				steps := rapid.IntRange(1, 20).Draw(rt, "steps")
				for range steps {
					id := types.NodeID(rapid.IntRange(1, 6).Draw(rt, "id")) //nolint:gosec // safe conversion in test
					switch rapid.IntRange(0, 5).Draw(rt, "op") {
					case 0: // payload only
						store.UpdateNode(id, func(n *types.Node) { n.LastSeen = new(time.Now()) })
					case 1: // tag
						tag := rapid.SampledFrom([]string{"tag:srv", "tag:router"}).Draw(rt, "tag")

						store.UpdateNode(id, func(n *types.Node) {
							n.Tags = []string{tag}
							n.UserID, n.User = nil, nil
						})
					case 2: // announce + approve subnet
						store.UpdateNode(id, func(n *types.Node) {
							n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
							n.ApprovedRoutes = []netip.Prefix{subnet}
						})
					case 3: // drop routes
						store.UpdateNode(id, func(n *types.Node) { n.ApprovedRoutes = nil })
					case 4: // online flip
						store.UpdateNode(id, func(n *types.Node) { n.IsOnline = new(!n.Online()) })
					case 5: // endpoint
						store.UpdateNode(id, func(n *types.Node) {
							n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
						})
					}

					// Check before syncPolicy: the write's own snapshot must
					// already be right, both on the reuse path (updateChanges
					// said payload-only) and on the recompute path (the
					// peersFunc refreshed pm before building). Checking only
					// after syncPolicy would let either mistake hide behind a
					// RebuildPeerMaps.
					checkAdjacencyMatchesFullBuild(rt, store, tc.pol, users)

					syncPolicy(rt, store, pm)
					checkAdjacencyMatchesFullBuild(rt, store, tc.pol, users)
				}
			})
		})
	}
}

// nodeFieldImpact classifies what NodeStore work a change to each
// exported types.Node field requires:
//   - "relation": policy (hscontrol/policy/v2) or BuildPeerMap reads it,
//     so a write must recompute peer adjacency.
//   - "election": affects route election (online/health) but not who
//     sees whom.
//   - "payload": neither; a write can reuse the previous peer adjacency.
//
// A field missing here fails TestUpdateChangesCoversEveryNodeField:
// classify it, and if it is a relation input, teach HasPolicyChange or
// HasNetworkChanges about it before updateChanges can let NodeStore
// reuse peer adjacency across the write.
var nodeFieldImpact = map[string]string{
	"ID": "relation", "IPv4": "relation", "IPv6": "relation",
	"UserID": "relation", "User": "relation", "Tags": "relation",
	"ApprovedRoutes": "relation", "Hostinfo": "relation",
	"IsOnline": "election", "Unhealthy": "election",
	"MachineKey": "payload", "NodeKey": "payload", "DiscoKey": "payload",
	"Endpoints": "payload", "Hostname": "payload", "GivenName": "payload",
	"RegisterMethod": "payload", "AuthKeyID": "payload", "AuthKey": "payload",
	"Expiry": "payload", "LastSeen": "payload", "CreatedAt": "payload",
	"UpdatedAt": "payload", "DeletedAt": "payload",
	"ActiveSessions": "payload", "SessionEpoch": "payload",
}

// TestUpdateChangesCoversEveryNodeField guards against a new types.Node
// field going unclassified in nodeFieldImpact. An unclassified field
// means nobody has decided whether updateChanges needs to know about
// it, which is exactly how a relation input goes silently unrebuilt.
func TestUpdateChangesCoversEveryNodeField(t *testing.T) {
	typ := reflect.TypeFor[types.Node]()
	for f := range typ.Fields() {
		if !f.IsExported() {
			continue
		}

		if _, ok := nodeFieldImpact[f.Name]; !ok {
			t.Errorf("types.Node.%s is not classified in nodeFieldImpact", f.Name)
		}
	}
}

// TestUpdateChangesReportsRelationFields pins what updateChanges reports
// for a mutation to each relation/election field in nodeFieldImpact,
// against a real pre/post pair rather than the classification map alone.
func TestUpdateChangesReportsRelationFields(t *testing.T) {
	pfx := netip.MustParsePrefix("10.44.0.0/24")
	ip := netip.MustParseAddr("100.64.9.9")

	tests := []struct {
		name         string
		mutate       func(*types.Node)
		wantRelation bool
		wantElection bool
	}{
		{name: "ipv4", mutate: func(n *types.Node) { n.IPv4 = &ip }, wantRelation: true, wantElection: true},
		{name: "tags", mutate: func(n *types.Node) { n.Tags = []string{"tag:x"}; n.UserID, n.User = nil, nil }, wantRelation: true, wantElection: true},
		{name: "user", mutate: func(n *types.Node) { n.UserID = new(uint(99)) }, wantRelation: true, wantElection: true},
		{name: "approved route", mutate: func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{pfx}}
			n.ApprovedRoutes = []netip.Prefix{pfx}
		}, wantRelation: true, wantElection: true},
		{
			// Announcing a route the policy has not approved does not
			// change who can access it (SubnetRoutes/ExitRoutes, which
			// gate HasPolicyChange, stay empty), but HasNetworkChanges
			// tracks the raw announcement so a later approval sees a
			// fresh Hostinfo rather than one NodeStore decided to reuse.
			name: "announced but not approved route",
			mutate: func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{pfx}}
			},
			wantRelation: true, wantElection: true,
		},
		{name: "online", mutate: func(n *types.Node) { n.IsOnline = new(true) }, wantElection: true},
		{name: "unhealthy", mutate: func(n *types.Node) { n.Unhealthy = true }, wantElection: true},
		{name: "endpoint", mutate: func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")} }},
		{name: "lastseen", mutate: func(n *types.Node) { n.LastSeen = new(time.Now()) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pre := createTestNode(1, 1, "u", "n")
			post := *pre.Clone()
			tt.mutate(&post)

			relation, election := updateChanges(&pre, &post)
			require.Equal(t, tt.wantRelation, relation, "relation")
			require.Equal(t, tt.wantElection, election, "election")
		})
	}
}

// benchNodes builds n nodes spread across 10 users for
// BenchmarkNodeStoreWrite: ~10% tagged tag:srv, ~5% carrying an
// approved and announced 10.x.0.0/24 route, each with a unique IPv4.
// hscontrol/policy/v2/policy_test.go keeps its own copy since test
// packages can't share one.
func benchNodes(n int) ([]types.User, types.Nodes) {
	users := make([]types.User, 10)
	for i := range users {
		users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i+1)}
	}

	nodes := make(types.Nodes, 0, n)
	for i := range n {
		u := users[i%len(users)]
		nd := createTestNode(types.NodeID(i+1), u.ID, u.Name, fmt.Sprintf("n%d", i+1))

		ip := netip.AddrFrom4([4]byte{100, 64, byte(i / 256), byte(i % 256)}) //nolint:gosec
		nd.IPv4, nd.IPv6 = &ip, nil

		if i%10 == 0 {
			nd.Tags = []string{"tag:srv"}
		} else {
			nd.User = &u
		}

		if i%20 == 0 {
			subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte((i / 20) % 256), 0, 0}), 24) //nolint:gosec
			nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
			nd.ApprovedRoutes = []netip.Prefix{subnet}
		}

		nodes = append(nodes, &nd)
	}

	return users, nodes
}

// BenchmarkNodeStoreWrite drives one UpdateNode of the named kind
// followed by syncPolicy against a started NodeStore wired to a real
// PolicyManager, over a realistic node count. peer-builds/op counts
// calls into the wrapped peersFunc, the baseline later NodeStore
// write-path changes are compared against: a payload-only write
// (lastseen) should cost far fewer builds than a relation-changing one
// (route, tag).
func BenchmarkNodeStoreWrite(b *testing.B) {
	users, nodes := benchNodes(617)

	for _, kind := range []struct {
		name   string
		mutate func(i int, n *types.Node)
	}{
		{name: "lastseen", mutate: func(_ int, n *types.Node) {
			n.LastSeen = new(time.Now())
		}},
		{name: "route", mutate: func(i int, n *types.Node) {
			subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(200 + i%50), 0, 0}), 24) //nolint:gosec
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
			n.ApprovedRoutes = []netip.Prefix{subnet}
		}},
		{name: "tag", mutate: func(i int, n *types.Node) {
			tag := "tag:srv"
			if i%2 == 0 {
				tag = "tag:web"
			}

			n.Tags = []string{tag}
			n.UserID, n.User = nil, nil
		}},
	} {
		b.Run(fmt.Sprintf("%s/n=%d", kind.name, len(nodes)), func(b *testing.B) {
			var calls atomic.Int64

			pm, err := policyv2.NewPolicyManager([]byte(policyGlobal), users, nodes.ViewSlice())
			require.NoError(b, err)

			inner := policyPeersFunc(pm)
			peersFunc := func(ns []types.NodeView) map[types.NodeID][]types.NodeID {
				calls.Add(1)

				return inner(ns)
			}

			store := NewNodeStore(nodes, peersFunc, TestBatchSize, TestBatchTimeout)

			store.Start()
			defer store.Stop()

			targetID := nodes[0].ID

			// NewNodeStore's own initial build is setup, not a per-write cost.
			calls.Store(0)

			b.ReportAllocs()

			i := 0
			for b.Loop() {
				i++

				store.UpdateNode(targetID, func(n *types.Node) { kind.mutate(i, n) })
				syncPolicy(b, store, pm)
			}

			b.ReportMetric(float64(calls.Load())/float64(b.N), "peer-builds/op")
		})
	}
}

// countStatePeerBuilds swaps s's NodeStore for one wired the same way
// but counting peersFunc runs, so a test can see how many O(n^2) peer
// builds a State write costs. Call before anything else uses s.
func countStatePeerBuilds(t *testing.T, s *State) *atomic.Int64 {
	t.Helper()

	nodes := make(types.Nodes, 0, s.nodeStore.ListNodes().Len())
	for _, nv := range s.nodeStore.ListNodes().All() {
		nodes = append(nodes, nv.AsStruct())
	}

	s.nodeStore.Stop()

	var calls atomic.Int64

	inner := policyPeersFunc(s.polMan)
	s.nodeStore = NewNodeStore(nodes, func(ns []types.NodeView) map[types.NodeID][]types.NodeID {
		calls.Add(1)

		return inner(ns)
	}, TestBatchSize, TestBatchTimeout)
	s.nodeStore.Start()

	calls.Store(0)

	return &calls
}

// peerBuildTestPolicy is the policy newPeerBuildTestState installs.
const peerBuildTestPolicy = `{
	"tagOwners": {"tag:a": ["pb-user@"], "tag:b": ["pb-user@"]},
	"acls": [
		{"action": "accept", "src": ["tag:a"], "dst": ["tag:b:*"]},
		{"action": "accept", "src": ["pb-user@"], "dst": ["10.55.0.0/24:*"]}
	]}`

// checkStateAdjacencyMatchesFullBuild is checkAdjacencyMatchesFullBuild
// for a State from newPeerBuildTestState.
func checkStateAdjacencyMatchesFullBuild(t *testing.T, s *State) {
	t.Helper()

	users, err := s.ListAllUsers()
	require.NoError(t, err)

	checkAdjacencyMatchesFullBuild(t, s.nodeStore, peerBuildTestPolicy, users)
}

// newPeerBuildTestState returns a State over three user-owned nodes, the
// first announcing a subnet, under a policy where both a tag and that
// subnet decide who sees whom.
func newPeerBuildTestState(t *testing.T) (*State, []types.NodeID, *atomic.Int64) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("pb-user")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "pb-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(peerBuildTestPolicy))
	require.NoError(t, err)

	ids := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}

	_, ok := s.nodeStore.UpdateNode(ids[0], func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.55.0.0/24")}}
	})
	require.True(t, ok)

	return s, ids, countStatePeerBuilds(t, s)
}

// TestStatePolicyWriteBuildsPeersOnce pins that a policy-relevant State
// write costs one peer build: the NodeStore writer's own build must
// already use the matchers the written node implies, not the old ones
// followed by a second rebuild once the policy manager catches up.
func TestStatePolicyWriteBuildsPeersOnce(t *testing.T) {
	tests := []struct {
		name  string
		write func(t *testing.T, s *State, id types.NodeID) change.Change
	}{
		{name: "tag", write: func(t *testing.T, s *State, id types.NodeID) change.Change {
			t.Helper()

			_, c, err := s.SetNodeTags(id, []string{"tag:a"})
			require.NoError(t, err)

			return c
		}},
		{name: "route", write: func(t *testing.T, s *State, id types.NodeID) change.Change {
			t.Helper()

			_, c, err := s.SetApprovedRoutes(id, []netip.Prefix{netip.MustParsePrefix("10.55.0.0/24")})
			require.NoError(t, err)

			return c
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ids, builds := newPeerBuildTestState(t)

			c := tt.write(t, s, ids[0])

			assert.Equal(t, "policy", c.Type(), "a policy-relevant write must still report a policy change")
			assert.Equal(t, int64(1), builds.Load(), "peer builds for one policy-relevant write")

			checkStateAdjacencyMatchesFullBuild(t, s)
		})
	}
}

// TestStateConcurrentTagWritesEachReportPolicyChange runs two SetNodeTags
// on different nodes at once. The NodeStore may apply both in one batch,
// so the policy manager sees both tags in a single SetNodes; each caller
// must still report a policy change for its own write, and adjacency
// must end up matching a full build. A report from only one of them could
// be sent before the other's snapshot is published.
func TestStateConcurrentTagWritesEachReportPolicyChange(t *testing.T) {
	s, ids, _ := newPeerBuildTestState(t)

	tags := [2]string{"tag:a", "tag:b"}

	for round := range 20 {
		var (
			wg      sync.WaitGroup
			changes [2]change.Change
			errs    [2]error
		)

		for i := range 2 {
			wg.Go(func() {
				tag := tags[(i+round)%2]
				_, changes[i], errs[i] = s.SetNodeTags(ids[1+i], []string{tag})
			})
		}

		wg.Wait()

		for i := range 2 {
			require.NoError(t, errs[i])
			require.True(t, changes[i].RequiresRuntimePeerComputation,
				"round %d writer %d: %s must report a policy change", round, i, changes[i].Type())
			require.Equal(t, ids[1+i], changes[i].OriginNode, "round %d writer %d", round, i)
		}

		checkStateAdjacencyMatchesFullBuild(t, s)
	}
}

// TestPolicyWriteReportsAfterPublish holds the NodeStore writer between the
// policy manager's SetNodes and the snapshot swap, and lets another caller
// report in that window. The writer's own caller must still report a policy
// change: one reported in the window is computed against the old snapshot,
// so peers would keep the adjacency the write replaced.
func TestPolicyWriteReportsAfterPublish(t *testing.T) {
	s, ids, _ := newPeerBuildTestState(t)

	nodes := make(types.Nodes, 0, s.nodeStore.ListNodes().Len())
	for _, nv := range s.nodeStore.ListNodes().All() {
		nodes = append(nodes, nv.AsStruct())
	}

	s.nodeStore.Stop()

	var (
		armed   atomic.Bool
		reached = make(chan struct{})
		release = make(chan struct{})
	)

	inner := policyPeersFunc(s.polMan)
	s.nodeStore = NewNodeStore(nodes, func(ns []types.NodeView) map[types.NodeID][]types.NodeID {
		if armed.CompareAndSwap(true, false) {
			_, err := s.polMan.SetNodes(views.SliceOf(ns))
			assert.NoError(t, err)
			close(reached)
			<-release
		}

		return inner(ns)
	}, TestBatchSize, TestBatchTimeout)
	s.nodeStore.Start()

	other := s.polMan.NodesGeneration()

	armed.Store(true)

	var (
		wg   sync.WaitGroup
		tagC change.Change
		err  error
	)

	wg.Go(func() {
		_, tagC, err = s.SetNodeTags(ids[1], []string{"tag:a"})
	})

	<-reached

	published, ok := s.GetNodeByID(ids[1])
	require.True(t, ok)
	require.False(t, published.IsTagged(), "the tag must not be published yet")

	otherC := s.policyChangeSince(other)

	close(release)
	wg.Wait()

	require.NoError(t, err)
	assert.True(t, otherC.IncludePolicy, "a caller whose window saw the move may report it early")
	assert.True(t, tagC.IncludePolicy,
		"the writer must report the policy change once its snapshot is published")
	assert.Equal(t, ids[1], tagC.OriginNode)
}

// TestBackfillNodeIPsReportsPolicyChange pins that assigning a missing
// address reports a policy change: the address is a policy input, and
// without the change clients only learned it from whichever unrelated
// write next refreshed the policy.
func TestBackfillNodeIPsReportsPolicyChange(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("bf-user")
	nodes := database.CreateRegisteredNodesForTest(user, 2, "bf-node")
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", nodes[0].ID).Update("ipv4", nil).Error)
	// Backfill copies the stored Hostinfo, which a registered client always has.
	require.NoError(t, database.DB.Model(&types.Node{}).Where("1 = 1").Update("host_info", "{}").Error)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	backfilled, cs, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, backfilled)
	assert.True(t, slices.ContainsFunc(cs, change.Change.IsBroadcastPolicyChange),
		"backfill must report a policy change: %v", cs)
}

// TestPolicyCachesSurviveOldViewDuringBuild covers the window between the
// writer's SetNodes and the snapshot swap: a mapper still holding the
// written node's old view can ask for its filter or SSH policy then. The
// answer for that old view must not be cached under the node's ID, or
// the node keeps it after the swap, since nothing invalidates it again.
func TestPolicyCachesSurviveOldViewDuringBuild(t *testing.T) {
	users := []types.User{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}
	subnet := netip.MustParsePrefix("10.33.0.0/24")

	pol := `{
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [{"action": "accept", "src": ["u2@"], "dst": ["10.33.0.0/24:*"]}],
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}]
	}`

	tests := []struct {
		name   string
		mutate func(n *types.Node)
		// probe reports a property of node 1's cached artefact that the
		// write flips from !want to want. It takes no *testing.T because it
		// also runs on the NodeStore writer, where FailNow would hang.
		probe func(pm *policyv2.PolicyManager, view types.NodeView) (bool, error)
		want  bool
	}{
		{
			name: "filter after route approval",
			mutate: func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
				n.ApprovedRoutes = []netip.Prefix{subnet}
			},
			probe: func(pm *policyv2.PolicyManager, view types.NodeView) (bool, error) {
				rules, err := pm.FilterForNode(view)
				if err != nil {
					return false, err
				}

				for _, r := range rules {
					for _, d := range r.DstPorts {
						if d.IP == subnet.String() {
							return true, nil
						}
					}
				}

				return false, nil
			},
			want: true,
		},
		{
			// A tagged node is outside autogroup:self, so tagging it must
			// drop its SSH rules.
			name: "ssh after tagging",
			mutate: func(n *types.Node) {
				n.Tags = []string{"tag:srv"}
				n.UserID, n.User = nil, nil
			},
			probe: func(pm *policyv2.PolicyManager, view types.NodeView) (bool, error) {
				sshPol, err := pm.SSHPolicy("", view)
				if err != nil {
					return false, err
				}

				return sshPol != nil && len(sshPol.Rules) > 0, nil
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Node 3 shares node 1's user so autogroup:self has a source
			// for node 1 once node 1 itself is tagged away.
			owners := []int{0, 1, 0}
			nodes := make(types.Nodes, 0, len(owners))

			for i, o := range owners {
				id := i + 1
				n := createTestNode(types.NodeID(id), users[o].ID, users[o].Name, fmt.Sprintf("n%d", id)) //nolint:gosec
				ip4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(id)})                                     //nolint:gosec
				n.IPv4, n.IPv6 = &ip4, nil
				n.User = &users[o]
				nodes = append(nodes, &n)
			}

			pm, err := policyv2.NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
			require.NoError(t, err)

			var (
				oldView  atomic.Pointer[types.NodeView]
				buildErr atomic.Pointer[error]
			)

			inner := policyPeersFunc(pm)
			store := NewNodeStore(nodes, func(ns []types.NodeView) map[types.NodeID][]types.NodeID {
				// Stand in for a mapper that read the snapshot just before
				// this write and asks between SetNodes and the swap.
				if v := oldView.Load(); v != nil {
					_, err := pm.SetNodes(views.SliceOf(ns))
					if err == nil {
						_, err = tt.probe(pm, *v)
					}

					if err != nil {
						buildErr.CompareAndSwap(nil, &err)
					}
				}

				return inner(ns)
			}, TestBatchSize, TestBatchTimeout)
			store.Start()

			defer store.Stop()

			before, ok := store.GetNode(1)
			require.True(t, ok)

			got, err := tt.probe(pm, before)
			require.NoError(t, err)
			require.NotEqual(t, tt.want, got, "precondition: the write must flip the probed artefact")

			oldView.Store(&before)

			after, ok := store.UpdateNode(1, tt.mutate)
			require.True(t, ok)
			oldView.Store(nil)

			if e := buildErr.Load(); e != nil {
				require.NoError(t, *e, "probe during peer map build")
			}

			got, err = tt.probe(pm, after)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "cached artefact must reflect the written node")
		})
	}
}

// nodeKeyIndexMismatch describes where snap's NodeKey index disagrees with its
// node list, or returns "" when every listed node, and nothing else, is indexed.
func nodeKeyIndexMismatch(snap *Snapshot) string {
	if len(snap.nodesByNodeKey) != len(snap.allNodes) {
		return fmt.Sprintf("index holds %d keys, list holds %d nodes",
			len(snap.nodesByNodeKey), len(snap.allNodes))
	}

	for _, nv := range snap.allNodes {
		// A missing key yields the zero view, whose ID() panics.
		got, ok := snap.nodesByNodeKey[nv.NodeKey()]
		if !ok {
			return fmt.Sprintf("node %d: key not indexed", nv.ID())
		}

		if got.ID() != nv.ID() {
			return fmt.Sprintf("node %d: key indexed to node %d", nv.ID(), got.ID())
		}
	}

	return ""
}

// TestNodeStoreNodeKeyIndexMatchesNodes pins the index DERP admission reads:
// every published snapshot indexes exactly its listed nodes' keys, and a key
// rotated away or deleted stops resolving, also on writes that reuse the
// previous peer map.
func TestNodeStoreNodeKeyIndexMatchesNodes(t *testing.T) {
	var peersCalls atomic.Int64

	countingPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
		peersCalls.Add(1)

		return allowAllPeersFunc(nodes)
	}

	store := NewNodeStore(nil, countingPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()

	defer store.Stop()

	// Readers load snapshots while the writes below publish them, so a torn
	// or stale index surfaces here and under -race.
	var (
		firstMismatch atomic.Pointer[string]
		stop          atomic.Bool
		readers       sync.WaitGroup
	)

	for range 4 {
		readers.Go(func() {
			for !stop.Load() {
				msg := nodeKeyIndexMismatch(store.data.Load())
				if msg != "" {
					firstMismatch.CompareAndSwap(nil, &msg)
				}
			}
		})
	}

	stopReaders := func() {
		stop.Store(true)
		readers.Wait()
	}
	t.Cleanup(stopReaders)

	requireResolves := func(t *testing.T, k key.NodePublic, want types.NodeID) {
		t.Helper()

		nv, ok := store.GetNodeByNodeKey(k)
		require.True(t, ok, "key of node %d must resolve", want)
		require.True(t, nv.Valid())
		require.Equal(t, want, nv.ID())
	}

	requireRefused := func(t *testing.T, k key.NodePublic) {
		t.Helper()

		_, ok := store.GetNodeByNodeKey(k)
		require.False(t, ok, "key must not resolve")
	}

	n1 := createTestNode(1, 1, "user1", "node1")
	n2 := createTestNode(2, 1, "user1", "node2")
	n3 := createTestNode(3, 2, "user2", "node3")

	for _, n := range []types.Node{n1, n2, n3} {
		store.PutNode(n)
	}

	requireResolves(t, n1.NodeKey, 1)
	requireResolves(t, n2.NodeKey, 2)
	requireResolves(t, n3.NodeKey, 3)

	peersCalls.Store(0)

	// Rotation is not a peer-map input, so it takes the reuse path; repeat it
	// so the readers overlap many publishes.
	current := n1.NodeKey
	for range 50 {
		prev := current
		current = key.NewNode().Public()

		_, ok := store.UpdateNode(1, func(n *types.Node) { n.NodeKey = current })
		require.True(t, ok)

		requireRefused(t, prev)
		requireResolves(t, current, 1)
	}

	store.UpdateNode(2, func(n *types.Node) { n.Hostname = "node2-renamed" })

	nv, ok := store.GetNodeByNodeKey(n2.NodeKey)
	require.True(t, ok)
	require.Equal(t, "node2-renamed", nv.Hostname(),
		"payload-only write must republish the indexed view")

	require.Zero(t, peersCalls.Load(),
		"rotation and payload writes must take the peer-map reuse path")

	store.DeleteNode(3)
	requireRefused(t, n3.NodeKey)
	requireResolves(t, current, 1)
	requireResolves(t, n2.NodeKey, 2)

	stopReaders()

	msg := firstMismatch.Load()
	if msg != nil {
		t.Fatalf("snapshot index disagreed with node list: %s", *msg)
	}

	require.Empty(t, nodeKeyIndexMismatch(store.data.Load()))
}

// Frozen before the primary-route projection change: keep the original snapshot
// construction and complete scan lookup for differential tests and benchmarks.
func snapshotFromNodesRouteScanReference(
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
		routes         map[netip.Prefix]types.NodeID
		isPrimaryRoute map[types.NodeID]bool
	)

	if reuseRoutes {
		routes, isPrimaryRoute = prev.routes, prev.isPrimaryRoute
	} else {
		// Carrying the previous assignment forward lets a still-valid
		// primary survive unrelated batches.
		var prevRoutes map[netip.Prefix]types.NodeID
		if prev != nil {
			prevRoutes = prev.routes
		}

		routes, isPrimaryRoute = electPrimaryRoutes(nodes, prevRoutes)
	}

	var peerIDsByNode map[types.NodeID][]types.NodeID

	if reusePeers {
		peerIDsByNode = prev.peersByNode
	} else {
		peersTimer := prometheus.NewTimer(nodeStorePeersCalculationDuration)
		peerIDsByNode = peersFunc(allNodes)

		peersTimer.ObserveDuration()
	}

	newSnap := Snapshot{
		nodesByID:         nodes,
		nodeViewsByID:     nodeViewsByID,
		allNodes:          allNodes,
		nodesByNodeKey:    make(map[key.NodePublic]types.NodeView),
		nodesByMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView),
		peersByNode:       peerIDsByNode,
		nodesByUser:       make(map[types.UserID][]types.NodeView),
		routes:            routes,
		isPrimaryRoute:    isPrimaryRoute,
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

func (s *NodeStore) primaryRoutesForNodeScanReference(id types.NodeID) []netip.Prefix {
	snap := s.data.Load()
	if !snap.isPrimaryRoute[id] {
		return nil
	}

	out := make([]netip.Prefix, 0)

	for prefix, nodeID := range snap.routes {
		if nodeID == id {
			out = append(out, prefix)
		}
	}

	slices.SortFunc(out, netip.Prefix.Compare)

	return out
}

func TestPrimaryRoutesForNodeWithoutProjection(t *testing.T) {
	nodes := primaryRouteBenchmarkNodes(3, 1, 2)
	initial := snapshotFromNodesRouteScanReference(nodes, allowAllPeersFunc, nil, false, false)
	reused := snapshotFromNodes(maps.Clone(nodes), allowAllPeersFunc, &initial, true, true)

	var store NodeStore
	for _, snap := range []*Snapshot{&initial, &reused} {
		store.data.Store(snap)

		for _, id := range []types.NodeID{1, 2, 99} {
			require.Equal(t, store.primaryRoutesForNodeScanReference(id), store.PrimaryRoutesForNode(id))
		}

		got := store.PrimaryRoutesForNode(1)
		require.NotEmpty(t, got)
		got[0] = netip.MustParsePrefix("::/0")

		require.Equal(t, store.primaryRoutesForNodeScanReference(1), store.PrimaryRoutesForNode(1))
	}
}

func TestPrimaryRoutesForNodeAllocations(t *testing.T) {
	node := createTestNode(1, 1, "user", "router")

	for i := range 64 {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)
		node.ApprovedRoutes = append(node.ApprovedRoutes, prefix)
	}

	node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: node.ApprovedRoutes}
	node.IsOnline = new(true)
	ordinary := createTestNode(2, 1, "user", "ordinary")
	store := NewNodeStore(
		types.Nodes{&node, &ordinary},
		allowAllPeersFunc,
		TestBatchSize,
		TestBatchTimeout,
	)
	empty := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	for _, tc := range []struct {
		name  string
		store *NodeStore
		id    types.NodeID
		count int
	}{
		{name: "primary", store: store, id: 1, count: 64},
		{name: "ordinary", store: store, id: 2},
		{name: "unknown", store: store, id: 99},
		{name: "empty", store: empty, id: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []netip.Prefix

			allocs := testing.AllocsPerRun(100, func() {
				got = tc.store.PrimaryRoutesForNode(tc.id)
			})

			require.Len(t, got, tc.count)

			if tc.count == 0 {
				require.Nil(t, got)
				require.Zero(t, allocs)
			} else {
				require.LessOrEqual(
					t,
					allocs,
					float64(1),
					"only the caller's route copy should allocate",
				)
			}
		})
	}
}

func TestPrimaryRoutesForNodeOwnsReturnedSlice(t *testing.T) {
	prefix := netip.MustParsePrefix("10.77.0.0/24")
	node := createTestNode(1, 1, "user", "router")
	node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{prefix}}
	node.ApprovedRoutes = []netip.Prefix{prefix}
	node.IsOnline = new(true)
	store := NewNodeStore(
		types.Nodes{&node},
		allowAllPeersFunc,
		TestBatchSize,
		TestBatchTimeout,
	)
	first := store.data.Load()

	got := store.PrimaryRoutesForNode(1)
	got[0] = netip.MustParsePrefix("::/0")

	require.Equal(t, []netip.Prefix{prefix}, store.PrimaryRoutesForNode(1))

	reused := snapshotFromNodes(
		maps.Clone(first.nodesByID),
		allowAllPeersFunc,
		first,
		true,
		true,
	)
	require.Same(t, &first.primaryRoutesByNode[1][0], &reused.primaryRoutesByNode[1][0],
		"payload snapshots must reuse the immutable route projection")
	store.data.Store(&reused)
	kept := store.PrimaryRoutesForNode(1)
	require.Equal(t, []netip.Prefix{prefix}, kept)

	nodes := maps.Clone(reused.nodesByID)
	node = nodes[1]
	node.IsOnline = new(false)
	nodes[1] = node
	withdrawn := snapshotFromNodes(nodes, allowAllPeersFunc, &reused, true, false)
	store.data.Store(&withdrawn)
	require.Nil(t, store.PrimaryRoutesForNode(1))
	require.Equal(t, []netip.Prefix{prefix}, kept)

	for _, old := range []*Snapshot{first, &reused} {
		store.data.Store(old)
		require.Equal(t, []netip.Prefix{prefix}, store.PrimaryRoutesForNode(1))
	}
}

func TestPrimaryRoutesForNodeMatchesElectionChanges(t *testing.T) {
	subnets := []netip.Prefix{
		netip.MustParsePrefix("10.77.0.0/24"),
		netip.MustParsePrefix("fd00::/64"),
	}
	advertised := append(
		slices.Clone(subnets),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	)
	nodes := make(types.Nodes, 0, 2)

	for id := types.NodeID(1); id <= 2; id++ {
		n := createTestNode(id, 1, "user", fmt.Sprintf("router-%d", id))
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: advertised}
		n.ApprovedRoutes = advertised
		n.IsOnline = new(true)
		nodes = append(nodes, &n)
	}

	store := NewNodeStore(nodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	for _, step := range []struct {
		name    string
		updates map[types.NodeID]UpdateNodeFunc
		primary types.NodeID
	}{
		{name: "initial", primary: 1},
		{name: "failover", updates: map[types.NodeID]UpdateNodeFunc{1: func(n *types.Node) { n.Unhealthy = true }}, primary: 2},
		{name: "recovery does not flap", updates: map[types.NodeID]UpdateNodeFunc{1: func(n *types.Node) { n.Unhealthy = false }}, primary: 2},
		{name: "all unhealthy keeps previous", updates: map[types.NodeID]UpdateNodeFunc{
			1: func(n *types.Node) { n.Unhealthy = true },
			2: func(n *types.Node) { n.Unhealthy = true },
		}, primary: 2},
		{name: "unhealthy without previous stays unmapped", updates: map[types.NodeID]UpdateNodeFunc{
			2: func(n *types.Node) { n.ApprovedRoutes = nil },
		}},
		{name: "healthy candidate returns", updates: map[types.NodeID]UpdateNodeFunc{1: func(n *types.Node) { n.Unhealthy = false }}, primary: 1},
		{name: "offline withdraws routes", updates: map[types.NodeID]UpdateNodeFunc{1: func(n *types.Node) { n.IsOnline = new(false) }}},
	} {
		t.Run(step.name, func(t *testing.T) {
			store.UpdateNodes(step.updates)

			for id := types.NodeID(1); id <= 3; id++ {
				var want []netip.Prefix
				if id == step.primary {
					want = subnets
				}

				require.Equal(t, want, store.primaryRoutesForNodeScanReference(id))
				require.Equal(t, want, store.PrimaryRoutesForNode(id))
			}
		})
	}
}

//nolint:gosec // Drawn node IDs are bounded to the fixture's positive IDs.
func TestPrimaryRoutesForNodeMatchesScanHistory(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("fd00::/64"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	rapid.Check(t, func(rt *rapid.T) {
		nodes := make(map[types.NodeID]types.Node, 6)

		for id := types.NodeID(1); id <= 6; id++ {
			n := createTestNode(id, 1, "user", "router")
			if id <= 2 {
				n.ApprovedRoutes = slices.Clone(prefixes)
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(prefixes)}
				n.IsOnline = new(true)
			} else if id == 3 {
				n.ApprovedRoutes = slices.Clone(prefixes[3:])
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(prefixes[3:])}
				n.IsOnline = new(true)
			}

			nodes[id] = n
		}

		type snapshots struct{ actual, reference *Snapshot }

		initial := snapshotFromNodes(nodes, allowAllPeersFunc, nil, false, false)
		original := snapshotFromNodesRouteScanReference(
			nodes,
			allowAllPeersFunc,
			nil,
			false,
			false,
		)
		steps := rapid.IntRange(10, 60).Draw(rt, "steps")
		history := make([]snapshots, 1, 1+steps)
		history[0] = snapshots{&initial, &original}
		check := func(pair snapshots) {
			if !reflect.DeepEqual(pair.reference.routes, pair.actual.routes) {
				rt.Fatalf(
					"primary assignments changed: scan %v, projection %v",
					pair.reference.routes,
					pair.actual.routes,
				)
			}

			var actual, reference NodeStore
			actual.data.Store(pair.actual)
			reference.data.Store(pair.reference)

			for id := types.NodeID(0); id <= 7; id++ {
				want := reference.primaryRoutesForNodeScanReference(id)

				got := actual.PrimaryRoutesForNode(id)
				if !reflect.DeepEqual(want, got) ||
					!reflect.DeepEqual(
						actual.primaryRoutesForNodeScanReference(id),
						got,
					) {
					rt.Fatalf(
						"node %d: scan %v, projection %v (nil: %v/%v)",
						id,
						want,
						got,
						want == nil,
						got == nil,
					)
				}
			}
		}
		check(history[0])

		for step := range steps {
			previous := history[len(history)-1]
			nodes = maps.Clone(previous.actual.nodesByID)
			id := types.NodeID(
				rapid.IntRange(1, 6).Draw(rt, "node"),
			) //nolint:gosec // bounded test ID

			n, exists := nodes[id]
			if !exists {
				n = createTestNode(id, 1, "user", "router")
			}

			op := rapid.IntRange(0, 9).Draw(rt, "operation")
			drawRoutes := func() []netip.Prefix {
				return rapid.SliceOfN(rapid.SampledFrom(prefixes), 0, 6).
					Draw(rt, "routes")
			}

			switch op {
			case 0:
				n.IsOnline = rapid.SampledFrom([]*bool{nil, new(false), new(true)}).
					Draw(rt, "online")
			case 1:
				n.Unhealthy = !n.Unhealthy
			case 2:
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: drawRoutes()}
			case 3:
				n.ApprovedRoutes = drawRoutes()
			case 4:
				n.ApprovedRoutes = drawRoutes()
				n.Hostinfo = &tailcfg.Hostinfo{
					RoutableIPs: slices.Clone(n.ApprovedRoutes),
				}
			case 5:
				n.Hostinfo = nil
			case 6:
				n.ApprovedRoutes = []netip.Prefix{}
			case 7:
				n.SessionEpoch++
			case 8:
				delete(nodes, id)
			case 9:
				for otherID, other := range nodes {
					other.Unhealthy = !other.Unhealthy
					other.IsOnline = new(!other.Online())
					nodes[otherID] = other
				}
			}

			if op != 8 && op != 9 {
				nodes[id] = n
			}

			reuseRoutes := op == 7 && exists
			next := snapshotFromNodes(
				nodes,
				allowAllPeersFunc,
				previous.actual,
				true,
				reuseRoutes,
			)
			baseline := snapshotFromNodesRouteScanReference(
				nodes,
				allowAllPeersFunc,
				previous.reference,
				true,
				reuseRoutes,
			)
			pair := snapshots{&next, &baseline}
			history = append(history, pair)
			check(pair)
			check(history[step/2])
		}

		for _, pair := range history {
			check(pair)
		}
	})
}

// primaryRouteBenchmarkNodes separates the ordinary tailnet size from the
// number of primary routers and prefixes, which determine projection overhead.
//
//nolint:gosec // Benchmark prefix octets come from small bounded fixture counts.
func primaryRouteBenchmarkNodes(
	nodeCount, routers, prefixesPerRouter int,
) map[types.NodeID]types.Node {
	nodes := make(map[types.NodeID]types.Node, nodeCount)
	for i := range nodeCount {
		n := createTestNode(
			types.NodeID(i+1),
			1,
			"user",
			fmt.Sprintf("node-%d", i+1),
		) //nolint:gosec // bounded benchmark ID
		if i < routers {
			for j := range prefixesPerRouter {
				index := i*prefixesPerRouter + j
				prefix := netip.PrefixFrom(
					netip.AddrFrom4([4]byte{10, byte(index / 256), byte(index), 0}),
					24,
				) //nolint:gosec // bounded benchmark prefix
				n.ApprovedRoutes = append(n.ApprovedRoutes, prefix)
			}

			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: n.ApprovedRoutes}
			n.IsOnline = new(true)
		}

		nodes[n.ID] = n
	}

	return nodes
}

func BenchmarkPrimaryRoutesForNode(b *testing.B) {
	for _, shape := range []struct{ routers, prefixes int }{{0, 0}, {1, 1}, {32, 8}, {128, 16}} {
		b.Run(
			fmt.Sprintf("routers=%d/prefixes=%d", shape.routers, shape.prefixes),
			func(b *testing.B) {
				nodes := primaryRouteBenchmarkNodes(617, shape.routers, shape.prefixes)
				snap := snapshotFromNodes(
					nodes,
					func([]types.NodeView) map[types.NodeID][]types.NodeID { return nil },
					nil,
					false,
					false,
				)

				var store NodeStore
				store.data.Store(&snap)

				for _, target := range []struct {
					name string
					id   types.NodeID
				}{{"router", 1}, {"ordinary", 617}, {"unknown", 999}} {
					require.Equal(
						b,
						store.primaryRoutesForNodeScanReference(target.id),
						store.PrimaryRoutesForNode(target.id),
					)

					for _, impl := range []struct {
						name   string
						lookup func(*NodeStore, types.NodeID) []netip.Prefix
					}{
						{"scan", (*NodeStore).primaryRoutesForNodeScanReference},
						{"projection", (*NodeStore).PrimaryRoutesForNode},
					} {
						b.Run(target.name+"/"+impl.name, func(b *testing.B) {
							var routes []netip.Prefix

							b.ReportAllocs()

							for b.Loop() {
								routes = impl.lookup(&store, target.id)
							}

							runtime.KeepAlive(routes)
						})
					}
				}
			},
		)
	}
}

// BenchmarkPrimaryRouteSnapshotBatch includes the full node-map copy and
// snapshot construction; the read variant also visits every node's routes.
// Queue delays and policy work are excluded so projection write costs stay visible.
func BenchmarkPrimaryRouteSnapshotBatch(b *testing.B) {
	for _, routers := range []int{0, 32, 128} {
		b.Run(fmt.Sprintf("routers=%d/prefixes=8", routers), func(b *testing.B) {
			nodes := primaryRouteBenchmarkNodes(617, routers, 8)
			noPeers := func([]types.NodeView) map[types.NodeID][]types.NodeID { return nil }

			for _, mode := range []struct {
				name               string
				reuseRoutes, reads bool
			}{
				{name: "payload", reuseRoutes: true},
				{name: "reelect"},
				{name: "reelect-and-lookups", reads: true},
			} {
				for _, impl := range []struct {
					name   string
					build  func(map[types.NodeID]types.Node, PeersFunc, *Snapshot, bool, bool) Snapshot
					lookup func(*NodeStore, types.NodeID) []netip.Prefix
				}{
					{"scan", snapshotFromNodesRouteScanReference, (*NodeStore).primaryRoutesForNodeScanReference},
					{"projection", snapshotFromNodes, (*NodeStore).PrimaryRoutesForNode},
				} {
					b.Run(mode.name+"/"+impl.name, func(b *testing.B) {
						initial := impl.build(nodes, noPeers, nil, false, false)

						var store NodeStore
						store.data.Store(&initial)

						var routeCount int

						b.ReportAllocs()

						for b.Loop() {
							previous := store.data.Load()
							updated := maps.Clone(previous.nodesByID)

							n := updated[1]
							if mode.reuseRoutes {
								n.SessionEpoch++
							} else {
								n.IsOnline = new(!n.Online())
							}

							updated[1] = n
							next := impl.build(
								updated,
								noPeers,
								previous,
								true,
								mode.reuseRoutes,
							)
							store.data.Store(&next)

							if mode.reads {
								for id := types.NodeID(1); id <= 617; id++ {
									routeCount += len(impl.lookup(&store, id))
								}
							}
						}

						runtime.KeepAlive(routeCount)
					})
				}
			}
		})
	}
}
