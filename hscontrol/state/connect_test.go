package state

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// requireOnline asserts the node's online state in the latest snapshot.
func requireOnline(t *testing.T, s *State, id types.NodeID, want bool) {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	online, known := nv.IsOnline().GetOk()
	require.True(t, known)
	require.Equal(t, want, online, "node %d online", id)
}

// TestConnectDisconnectOrdinaryNodeKeepsPolicy asserts that an ordinary node
// coming online or going offline recompiles neither the policy nor the peer
// map. Online state is not a policy input; recompiling on it would make
// each reconnect an O(N) rebuild for every peer, and a reconnect storm
// O(N^2).
func TestConnectDisconnectOrdinaryNodeKeepsPolicy(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	before := s.Snapshot()

	epoch := s.Connect(nodeID)
	require.NotZero(t, epoch, "Connect should return a session epoch")
	requireOnline(t, s, nodeID, true)

	drainSessions(t, s, nodeID, epoch)

	after := s.Snapshot()
	require.Greater(t, after.Rev(), before.Rev(), "connect and disconnect must commit")
	assert.Equal(t, before.PolicyRev(), after.PolicyRev(), "online state must not recompile the policy")
	assert.Equal(t, before.PeersRev(), after.PeersRev(), "online state must not rebuild the peer map")
}

// TestConnectDisconnectSubnetRouterMovesPrimary guards the sole announced and
// approved router's fallback across connect/disconnect. Availability changes
// must not remove its route when no alternative is available.
func TestConnectDisconnectSubnetRouterMovesPrimary(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
	})
	require.True(t, ok)

	primary, ok := s.Snapshot().PrimaryRouteFor(route)
	require.True(t, ok, "the sole offline announced and approved router is the fallback")
	assert.Equal(t, nodeID, primary)

	epoch := s.Connect(nodeID)
	require.NotZero(t, epoch)

	primary, ok = s.Snapshot().PrimaryRouteFor(route)
	require.True(t, ok, "subnet router connect keeps it primary")
	assert.Equal(t, nodeID, primary)

	drainSessions(t, s, nodeID, epoch)

	primary, ok = s.Snapshot().PrimaryRouteFor(route)
	require.True(t, ok, "subnet router disconnect retains the sole approved fallback")
	assert.Equal(t, nodeID, primary)
}

// drainSessions releases poll sessions on nodeID until the node goes
// offline. Fails the test if the node is still online after releasing as
// many sessions as Connect calls could plausibly have acquired.
func drainSessions(t *testing.T, s *State, nodeID types.NodeID, epoch uint64) {
	t.Helper()

	// Arbitrary upper bound: comfortably above the number of Connect
	// calls any test here makes. It only guards against looping
	// forever when the node never goes offline.
	const maxSessions = 16

	for range maxSessions {
		err := s.Disconnect(nodeID, epoch)
		require.NoError(t, err)

		nv, ok := s.GetNodeByID(nodeID)
		require.True(t, ok)

		if !nv.IsOnline().Get() {
			return
		}
	}

	t.Fatalf("node %d still online after releasing %d sessions", nodeID, maxSessions)
}

// TestDisconnectOutOfOrderSessionsCannotStrandNodeOnline reproduces the
// server side of the relogin flake at the state level: a cancelled map
// request whose handler runs late acquires a session (and the newest
// epoch) after the real session's Connect, then releases without taking
// the node offline because the real session is still live. The real
// session's release — carrying the older epoch — must still take the
// node offline. Under the old epoch-equality gate it was rejected as
// stale and the node stayed online forever.
func TestDisconnectOutOfOrderSessionsCannotStrandNodeOnline(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	liveGen := s.Connect(nodeID)
	zombieGen := s.Connect(nodeID)
	require.Greater(t, zombieGen, liveGen, "late session must hold the newer epoch")

	// The zombie session dies first; another session is live, so the node
	// must stay online.
	err := s.Disconnect(nodeID, zombieGen)
	require.NoError(t, err)
	requireOnline(t, s, nodeID, true)

	// The real session releases last, with the older epoch. This must take
	// the node offline.
	err = s.Disconnect(nodeID, liveGen)
	require.NoError(t, err)
	requireOnline(t, s, nodeID, false)
}

func TestExpiredNodeSessionAccounting(t *testing.T) {
	for _, expiry := range []*time.Time{nil, new(time.Time{}), new(time.Now().Add(time.Hour))} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			first := s.Connect(id)
			past := time.Now()
			node, err := s.SetNodeExpiry(id, &past)
			require.NoError(t, err)
			require.False(t, node.IsOnline().Get())
			require.Equal(t, 1, node.ActiveSessions())

			// An expired key can poll control but must not come online.
			second := s.Connect(id)
			require.Greater(t, second, first)

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)
			require.False(t, node.IsOnline().Get())
			require.Equal(t, 2, node.ActiveSessions())

			err = s.Disconnect(id, second)
			require.NoError(t, err)

			node, err = s.SetNodeExpiry(id, expiry)
			require.NoError(t, err)
			require.True(t, node.IsOnline().Get(), "restoring a key with a live session restores online state")
			require.Equal(t, 1, node.ActiveSessions())

			err = s.Disconnect(id, first)
			require.NoError(t, err)
			node, err = s.SetNodeExpiry(id, expiry)
			require.NoError(t, err)
			require.False(t, node.IsOnline().Get(), "restoring expiry cannot connect a disconnected node")
			require.Zero(t, node.ActiveSessions())
		})
	}
}

// TestBackfillNodeIPsKeepsLiveSessions guards the IP backfill against
// replacing in-memory nodes with their database rows, which drops the
// runtime-only session count and strands a connected node offline.
func TestBackfillNodeIPsKeepsLiveSessions(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	require.NoError(t, s.Close())

	// Dropping the IPv6 prefix gives the backfill work to do.
	cfg := persistTestConfig(dbPath)
	cfg.Prefixes.V6 = nil

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	firstGen := s.Connect(nodeID)
	s.Connect(nodeID)

	// Connected nodes carry the Hostinfo of their first MapRequest.
	s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{Hostname: "persist-node"}
	})

	changes, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, changes, "precondition: backfill must change the node")

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Len(t, nv.IPs(), 1, "backfill must drop the IPv6 address")

	err = s.Disconnect(nodeID, firstGen)
	require.NoError(t, err)

	nv, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)

	online, known := nv.IsOnline().GetOk()
	require.True(t, known)
	assert.True(t, online, "node must stay online while its second session lives")
}

// Delivery assertions are exercised by mapper.TestReconnectWhileOnlineAnnouncesNothing.
// These additional checks pin the coherent state each stream renders.
func TestReconnectWhileOnlineAnnouncesNothing(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	_, ok := s.world.UpdateNode(id, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
	})
	require.True(t, ok)

	first := s.Connect(id)
	online := s.Snapshot()
	firstNode, _ := online.GetNode(id)
	require.True(t, firstNode.Online())
	require.Equal(t, 1, firstNode.ActiveSessions())
	require.Equal(t, id, online.PrimaryRoutes()[route])
	second := s.Connect(id)
	reconnected := s.Snapshot()
	secondNode, _ := reconnected.GetNode(id)
	assert.True(t, firstNode.SameRender(secondNode), "an overlapping reconnect changes nothing peers read")
	assert.Equal(t, firstNode.SessionStart(), secondNode.SessionStart())
	assert.Equal(t, 2, secondNode.ActiveSessions())
	require.NoError(t, s.Disconnect(id, first))
	during, _ := s.GetNodeByID(id)
	assert.True(t, secondNode.SameRender(during))
	assert.Equal(t, 1, during.ActiveSessions())
	require.NoError(t, s.Disconnect(id, second))
	offline, _ := s.GetNodeByID(id)
	assert.False(t, offline.Online())
	assert.Zero(t, offline.ActiveSessions())
	assert.False(t, during.SameRender(offline))
	require.True(t, offline.LastSeen().Valid())
	s.Connect(id)
	restored, _ := s.GetNodeByID(id)
	assert.True(t, restored.Online())
	assert.Equal(t, 1, restored.ActiveSessions())
	assert.False(t, offline.SameRender(restored))
	assert.True(t, restored.SessionStart().After(firstNode.SessionStart()))
}

func TestConnectForMapRequestRejectsRotatedKey(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	original, ok := s.GetNodeByID(id)
	require.True(t, ok)

	rotated := key.NewNode().Public()
	_, ok = s.world.UpdateNode(id, func(n *types.Node) { n.NodeKey = rotated })
	require.True(t, ok)

	before := s.Snapshot()
	assert.Zero(t, s.ConnectForMapRequest(id, original.NodeKey()))
	assert.Zero(t, s.ConnectForMapRequest(id, key.NodePublic{}))
	after := s.Snapshot()
	assert.Equal(t, before.Rev(), after.Rev(), "refused admission publishes nothing")
	current, ok := after.GetNode(id)
	require.True(t, ok)
	assert.Equal(t, original.ActiveSessions(), current.ActiveSessions())

	epoch := s.ConnectForMapRequest(id, rotated)
	require.NotZero(t, epoch)

	current, ok = s.GetNodeByID(id)
	require.True(t, ok)
	assert.Equal(t, original.ActiveSessions()+1, current.ActiveSessions())
	require.NoError(t, s.Disconnect(id, epoch))
}
