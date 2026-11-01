package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestAutoApproveBatchApprovesRoutes verifies the batched autoApproveNodes still
// approves a node's advertised route when policy auto-approvers permit it. The
// batching collapses the per-node SetApprovedRoutes calls into one commit
// and one policy rebuild; this guards that correctness is preserved.
func TestAutoApproveBatchApprovesRoutes(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")

	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	})
	require.True(t, ok)

	pol := `{
		"autoApprovers": {"routes": {"10.0.0.0/24": ["persist-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err := s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	err = s.ReloadPolicy()
	require.NoError(t, err)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Contains(t, nv.ApprovedRoutes().AsSlice(), route,
		"auto-approver should have approved the advertised route")
}

// TestAutoApproveSurvivesVanishedRow pins that a policy reload's persist
// sweep skips a node whose row a lifetime delete already dropped instead of
// failing the whole reload: the policy is already published when the sweep
// runs, and the remaining nodes' durable route approvals must not be held
// hostage to a node that is on its way out.
func TestAutoApproveSurvivesVanishedRow(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	routeA := netip.MustParsePrefix("10.0.0.0/24")
	routeB := netip.MustParsePrefix("10.1.0.0/24")

	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{routeA}}
	})
	require.True(t, ok)

	survivor := registerPersistedNode(t, s, "autoapprove-survivor")

	_, ok = s.world.UpdateNode(survivor.ID(), func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{routeB}}
	})
	require.True(t, ok)

	pol := `{
		"autoApprovers": {"routes": {
			"10.0.0.0/24": ["persist-user@"],
			"10.1.0.0/24": ["persist-user@"]
		}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err := s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	// A lifetime delete's window: the victim's row is gone while the world
	// still knows it, so the reload's persist sweep matches zero rows.
	victim, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.NoError(t, s.db.DeleteNode(victim.AsStruct()))

	err = s.ReloadPolicy()
	require.NoError(t, err, "a vanished node must not fail the reload")

	live, ok := s.GetNodeByID(survivor.ID())
	require.True(t, ok)
	assert.Contains(t, live.ApprovedRoutes().AsSlice(), routeB,
		"the surviving node's approval must publish")

	durable, err := s.db.GetNodeByID(survivor.ID())
	require.NoError(t, err)
	assert.Contains(t, durable.ApprovedRoutes, routeB,
		"the surviving node's approval must reach its row")
}
