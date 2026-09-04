package state

// Tests that BatchSetNodeHealth does not trigger peer-relation work when
// the requested health value matches what is already stored. The HA
// prober runs every few seconds against every HA candidate; without this
// prefilter, every cycle causes a NodeStore write and (pre-fix) a full
// peer-map rebuild.
//
// See https://github.com/juanfont/headscale/issues/3417.

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestBatchSetNodeHealthUnchangedDoesNotPublish ensures that asking for
// the same health value that is already stored produces no work — no
// snapshot publish, no peersFunc invocation, no peer-map rebuild.
func TestBatchSetNodeHealthUnchangedDoesNotPublish(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	// Use the State's nodeStore directly to confirm the node exists.
	_, exists := s.nodeStore.GetNode(nodeID)
	require.True(t, exists)

	initialSnapshot := s.nodeStore.data.Load()

	// The node starts with Unhealthy=false. Asking for "healthy=true"
	// means Unhealthy stays false — no change.
	for range 20 {
		changed := s.BatchSetNodeHealth(map[types.NodeID]bool{nodeID: true})
		require.False(t, changed,
			"unchanged health write must not report a route-primary change")
		require.Same(t, initialSnapshot, s.nodeStore.data.Load(),
			"unchanged health write must not publish a new snapshot")
	}
}

// TestBatchSetNodeHealthTransitionElection verifies the real transition
// case still triggers election evaluation. Uses a node that has approved
// routes so it is an HA candidate.
func TestBatchSetNodeHealthTransitionElection(t *testing.T) {
	var peersCalls atomic.Int64

	countingPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
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
