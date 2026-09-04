package mapper

// Tests that empty changes are dropped at batcher ingress and never reach
// recipient fan-out. The MapRequest classifier can legitimately produce
// empty changes (no-op request, STUN-only churn, DERPLatency-only update);
// those must not create any pending entries, in-flight work, or recipient
// processing.
//
// See https://github.com/juanfont/headscale/issues/3417.

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
)

// TestAddToBatchDropsEmptyChanges ensures an empty-only batch produces no
// pending entries on any recipient node.
func TestAddToBatchDropsEmptyChanges(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 16)
	defer lb.cleanup()

	// A zero-value change.Change is empty: no peers changed, no patches,
	// no full update, no removal.
	empty := change.Change{}
	require.True(t, empty.IsEmpty(), "zero change must be empty")

	lb.b.AddWork(empty)

	require.Equal(t, 0, countTotalPending(lb.b),
		"empty change must not create pending entries on any node")
	require.Equal(t, 0, countNodesPending(lb.b),
		"empty change must not mark any node as having pending work")
}

// TestAddToBatchEmptyMixedWithReal ensures empty changes dropped from a batch
// do not affect delivery of the real changes alongside them.
func TestAddToBatchEmptyMixedWithReal(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 16)
	defer lb.cleanup()

	added := change.NodeAdded(types.NodeID(42))
	empty := change.Change{}

	lb.b.AddWork(empty, added, empty)

	// The real change must land for every connected node; empties must not
	// add anything.
	require.Equal(t, 3, countNodesPending(lb.b),
		"all 3 nodes should have the real change pending")

	for id := range lb.channels {
		pending := getPendingForNode(lb.b, id)
		require.Len(t, pending, 1,
			"node %d must have exactly the one real change pending, no empties", id)
	}
}

// TestAddToBatchFullUpdateUnaffectedByEmpty ensures that a full update in
// the batch still takes precedence and replaces pending state, regardless
// of any empty changes in the same batch.
func TestAddToBatchFullUpdateUnaffectedByEmpty(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 16)
	defer lb.cleanup()

	lb.b.AddWork(change.Change{}, change.FullUpdate(), change.Change{})

	for id := range lb.channels {
		pending := getPendingForNode(lb.b, id)
		require.Len(t, pending, 1,
			"node %d pending should be the single full update", id)
		require.True(t, pending[0].IsFull(),
			"node %d pending entry must be the full update", id)
	}
}

// TestAddToBatchPeersRemovedNotTreatedAsEmpty ensures the empty filter does
// not swallow a PeersRemoved change — deletion cleanup must still run, and
// surviving recipients must still see the removal.
func TestAddToBatchPeersRemovedNotTreatedAsEmpty(t *testing.T) {
	lb := setupLightweightBatcher(t, 4, 16)
	defer lb.cleanup()

	// Remove node 4.
	removal := change.NodeRemoved(types.NodeID(4))
	require.False(t, removal.IsEmpty(), "PeersRemoved change is not empty")

	lb.b.AddWork(removal)

	// Node 4 must be evicted from the batcher.
	_, exists := lb.b.nodes.Load(types.NodeID(4))
	require.False(t, exists, "removed node must be evicted from batcher")

	// Surviving nodes must see the removal pending.
	require.Equal(t, 3, countNodesPending(lb.b),
		"surviving 3 nodes must have the removal pending")
}
