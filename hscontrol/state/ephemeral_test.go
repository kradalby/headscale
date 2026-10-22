package state

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestEphemeralNodeDeleteWithConcurrentUpdate races UpdateNode against
// DeleteNode, as UpdateNodeFromMapRequest races an ephemeral node's logout.
// Whichever commits first, the node ends deleted: an update never re-inserts
// a node, and one that runs after the delete reports the node gone.
func TestEphemeralNodeDeleteWithConcurrentUpdate(t *testing.T) {
	for i := range 20 {
		id := types.NodeID(i + 1) //nolint:gosec // small test ids
		w := newTestWorld(t, createTestNode(id, 1, "test-user", "test-node"))

		var (
			wg      sync.WaitGroup
			updated types.NodeView
			ok      bool
		)

		start := make(chan struct{})

		wg.Go(func() {
			<-start

			updated, ok = w.UpdateNode(id, func(n *types.Node) { n.LastSeen = new(time.Now()) })
		})
		wg.Go(func() {
			<-start

			w.DeleteNode(id)
		})
		close(start)
		wg.Wait()

		_, found := w.snapshot().GetNode(id)
		require.False(t, found, "node must stay deleted")
		require.Equal(t, ok, updated.Valid(), "UpdateNode must report the node it wrote, or none")
	}
}

// registerEphemeralNode registers a node with an ephemeral pre-auth key, as
// a container joining with one does.
func registerEphemeralNode(t *testing.T, s *State, hostname string) types.NodeView {
	t.Helper()

	user, err := s.GetUserByName("persist-user")
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)

	node, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}, key.NewMachine().Public())
	require.NoError(t, err)
	require.True(t, node.IsEphemeral(), "precondition: node is ephemeral")

	return node
}

// requireNodeGone asserts the node is absent from memory and the database.
func requireNodeGone(t *testing.T, s *State, id types.NodeID) {
	t.Helper()

	_, ok := s.GetNodeByID(id)
	require.False(t, ok, "node must be gone from memory")

	_, err := s.db.GetNodeByID(id)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound, "node must be gone from the database")
}

// TestPersistNodeToDBPreventsRaceCondition persists a view taken before the
// node left memory. persistNode re-reads memory and must refuse, so a stale
// caller cannot write a node memory no longer holds.
func TestPersistNodeToDBPreventsRaceCondition(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	updated, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostname = "renamed-before-delete"
	})
	require.True(t, ok)

	s.world.DeleteNode(nodeID)

	_, err := s.persistNode(updated)
	require.ErrorIs(t, err, ErrNodeNotInNodeStore)

	row, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.NotEqual(t, "renamed-before-delete", row.Hostname, "the stale view must not be written")
}

// TestPersistNodeToDBChecksMemoryBeforePersist persists a view of an
// ephemeral node taken before its logout deleted it. The deleted row must
// not come back.
func TestPersistNodeToDBChecksMemoryBeforePersist(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node := registerEphemeralNode(t, s, "ephemeral-node")

	stale, ok := s.world.UpdateNode(node.ID(), func(n *types.Node) { n.LastSeen = new(time.Now()) })
	require.True(t, ok)

	require.NoError(t, s.DeleteNode(stale))

	_, err := s.persistNode(stale)
	require.ErrorIs(t, err, ErrNodeNotInNodeStore)
	requireNodeGone(t, s, node.ID())
}

// TestEphemeralNodeLogoutRaceCondition races a map request against the
// logout of an ephemeral node. Persisting the map request after the logout
// would re-insert the node the logout deleted.
func TestEphemeralNodeLogoutRaceCondition(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	for range 10 {
		node := registerEphemeralNode(t, s, "ephemeral-node")

		req := tailcfg.MapRequest{
			NodeKey:   node.NodeKey(),
			Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:41641")},
			Hostinfo:  &tailcfg.Hostinfo{Hostname: "ephemeral-node"},
		}

		var (
			wg        sync.WaitGroup
			deleteErr error
		)

		start := make(chan struct{})

		wg.Go(func() {
			<-start

			// Fails when the logout won; either order is fine.
			_ = s.UpdateNodeFromMapRequest(node.ID(), req)
		})
		wg.Go(func() {
			<-start

			deleteErr = s.DeleteNode(node)
		})
		close(start)
		wg.Wait()

		require.NoError(t, deleteErr)
		requireNodeGone(t, s, node.ID())
	}
}

// TestUpdateNodeFromMapRequestEphemeralLogoutSequence delivers a map request
// that was in flight when its ephemeral node logged out. It must fail and
// leave the node deleted.
func TestUpdateNodeFromMapRequestEphemeralLogoutSequence(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node := registerEphemeralNode(t, s, "ephemeral-node")

	require.NoError(t, s.DeleteNode(node))

	err := s.UpdateNodeFromMapRequest(node.ID(), tailcfg.MapRequest{
		NodeKey:   node.NodeKey(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:41641")},
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "ephemeral-node"},
	})
	require.ErrorIs(t, err, ErrNodeNotInNodeStore)
	requireNodeGone(t, s, node.ID())
}
