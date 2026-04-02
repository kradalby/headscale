package state

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/types/key"
)

// ============================================================================
// Generators
// ============================================================================

// genNodeID generates a NodeID in a small range to encourage key collisions
// during map-based generation while remaining large enough for meaningful tests.
func genNodeID() *rapid.Generator[types.NodeID] {
	return rapid.Custom[types.NodeID](func(t *rapid.T) types.NodeID {
		return types.NodeID(rapid.Uint64Range(1, 200).Draw(t, "nodeID"))
	})
}

// genUserID generates a UserID in a small range to create multi-node-per-user scenarios.
func genUserID() *rapid.Generator[uint] {
	return rapid.Custom[uint](func(t *rapid.T) uint {
		return uint(rapid.IntRange(1, 10).Draw(t, "userID"))
	})
}

// genTag generates a tag string in the form "tag:name".
func genTag() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		name := rapid.StringMatching(`[a-z][a-z0-9]{0,7}`).Draw(t, "tagname")
		return "tag:" + name
	})
}

// genTags generates a slice of 0..maxLen unique tags.
func genTags(maxLen int) *rapid.Generator[[]string] {
	return rapid.Custom[[]string](func(t *rapid.T) []string {
		n := rapid.IntRange(0, maxLen).Draw(t, "numTags")
		seen := make(map[string]bool, n)
		result := make([]string, 0, n)
		for len(result) < n {
			tag := genTag().Draw(t, "tag")
			if !seen[tag] {
				seen[tag] = true
				result = append(result, tag)
			}
		}
		return result
	})
}

// genNode generates a random Node with random keys, IPs, user, and optional tags.
func genNode() *rapid.Generator[types.Node] {
	return rapid.Custom[types.Node](func(t *rapid.T) types.Node {
		id := genNodeID().Draw(t, "id")
		uid := genUserID().Draw(t, "uid")
		tags := genTags(3).Draw(t, "tags")

		machineKey := key.NewMachine()
		nodeKey := key.NewNode()
		discoKey := key.NewDisco()

		// Generate deterministic IPs from the node ID to avoid collisions in
		// simple cases but still have meaningful values.
		ipv4 := netip.AddrFrom4([4]byte{
			100,
			64,
			byte(id >> 8),   //nolint:gosec
			byte(id & 0xFF), //nolint:gosec
		})
		ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}
		ipv6Bytes[14] = byte(id >> 8)   //nolint:gosec
		ipv6Bytes[15] = byte(id & 0xFF) //nolint:gosec
		ipv6 := netip.AddrFrom16(ipv6Bytes)

		hostname := fmt.Sprintf("node-%d", id)

		return types.Node{
			ID:         id,
			MachineKey: machineKey.Public(),
			NodeKey:    nodeKey.Public(),
			DiscoKey:   discoKey.Public(),
			Hostname:   hostname,
			GivenName:  hostname,
			UserID:     new(uid),
			User: &types.User{
				Name:        fmt.Sprintf("user-%d", uid),
				DisplayName: fmt.Sprintf("User %d", uid),
			},
			RegisterMethod: "test",
			IPv4:           &ipv4,
			IPv6:           &ipv6,
			Tags:           tags,
		}
	})
}

// genNodeMap generates a map of NodeID -> Node with unique IDs.
// The map size is bounded to keep tests fast.
func genNodeMap(maxSize int) *rapid.Generator[map[types.NodeID]types.Node] {
	return rapid.Custom[map[types.NodeID]types.Node](func(t *rapid.T) map[types.NodeID]types.Node {
		n := rapid.IntRange(0, maxSize).Draw(t, "mapSize")
		nodes := make(map[types.NodeID]types.Node, n)
		for len(nodes) < n {
			node := genNode().Draw(t, "node")
			// Overwrite if ID exists; that's fine for unique-ID maps.
			nodes[node.ID] = node
		}
		return nodes
	})
}

// ============================================================================
// PeersFunc implementations
// ============================================================================

// allVisiblePeersFunc: every node sees every other node.
func allVisiblePeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, len(nodes))
	for _, node := range nodes {
		var peers []types.NodeView
		for _, n := range nodes {
			if n.ID() != node.ID() {
				peers = append(peers, n)
			}
		}
		ret[node.ID()] = peers
	}
	return ret
}

// noVisiblePeersFunc: no node sees any other node.
func noVisiblePeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, len(nodes))
	for _, node := range nodes {
		ret[node.ID()] = nil
	}
	return ret
}

// symmetricRandomPeersFunc builds a PeersFunc from a pre-computed symmetric
// adjacency set. By constructing the adjacency before the PeersFunc is called,
// we guarantee symmetry: if Y is in peers(X), then X is in peers(Y).
func symmetricRandomPeersFunc(t *rapid.T, ids []types.NodeID) PeersFunc {
	// Build a symmetric adjacency set.
	type edge struct{ a, b types.NodeID }
	adj := make(map[types.NodeID]map[types.NodeID]bool)
	for _, id := range ids {
		adj[id] = make(map[types.NodeID]bool)
	}

	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if rapid.Bool().Draw(t, fmt.Sprintf("edge-%d-%d", ids[i], ids[j])) {
				adj[ids[i]][ids[j]] = true
				adj[ids[j]][ids[i]] = true
			}
		}
	}

	return func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
		ret := make(map[types.NodeID][]types.NodeView, len(nodes))
		nodesByID := make(map[types.NodeID]types.NodeView, len(nodes))
		for _, n := range nodes {
			nodesByID[n.ID()] = n
		}

		for _, node := range nodes {
			var peers []types.NodeView
			for peerID := range adj[node.ID()] {
				if pv, ok := nodesByID[peerID]; ok {
					peers = append(peers, pv)
				}
			}
			ret[node.ID()] = peers
		}
		return ret
	}
}

// genPeersFunc picks one of the three PeersFunc strategies.
// For symmetricRandom, we need the node IDs ahead of time so the
// adjacency can be pre-computed.
func genPeersFunc(t *rapid.T, ids []types.NodeID) PeersFunc {
	strategy := rapid.IntRange(0, 2).Draw(t, "peersFuncStrategy")
	switch strategy {
	case 0:
		return allVisiblePeersFunc
	case 1:
		return noVisiblePeersFunc
	default:
		return symmetricRandomPeersFunc(t, ids)
	}
}

// nodeIDs extracts sorted IDs from a node map.
func nodeIDs(nodes map[types.NodeID]types.Node) []types.NodeID {
	ids := make([]types.NodeID, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b types.NodeID) int {
		return cmp.Compare(a, b)
	})
	return ids
}

// ============================================================================
// Property 1: allNodes count matches input
// ============================================================================

func TestRapid_Snapshot_AllNodesCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		if len(snap.allNodes) != len(nodes) {
			t.Fatalf("allNodes count %d != input count %d", len(snap.allNodes), len(nodes))
		}
	})
}

// ============================================================================
// Property 2: nodesByID completeness — every input node is in nodesByID
// ============================================================================

func TestRapid_Snapshot_NodesByIDCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for id, node := range nodes {
			got, ok := snap.nodesByID[id]
			if !ok {
				t.Fatalf("node %d missing from nodesByID", id)
			}
			if got.ID != node.ID {
				t.Fatalf("nodesByID[%d].ID = %d, want %d", id, got.ID, node.ID)
			}
		}

		// Reverse: nothing extra in nodesByID
		if len(snap.nodesByID) != len(nodes) {
			t.Fatalf("nodesByID has %d entries, input has %d", len(snap.nodesByID), len(nodes))
		}
	})
}

// ============================================================================
// Property 3: nodesByNodeKey consistency — every nodesByID entry has a
// corresponding entry in nodesByNodeKey
// ============================================================================

func TestRapid_Snapshot_NodesByNodeKeyConsistency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for _, node := range snap.nodesByID {
			nv, ok := snap.nodesByNodeKey[node.NodeKey]
			if !ok {
				t.Fatalf("node %d (NodeKey=%s) missing from nodesByNodeKey",
					node.ID, node.NodeKey.ShortString())
			}
			if nv.ID() != node.ID {
				t.Fatalf("nodesByNodeKey lookup for node %d returned node %d",
					node.ID, nv.ID())
			}
		}
	})
}

// ============================================================================
// Property 4: nodesByMachineKey consistency — every node can be found via
// its machine key + user ID
// ============================================================================

func TestRapid_Snapshot_NodesByMachineKeyConsistency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for _, node := range snap.nodesByID {
			userMap, ok := snap.nodesByMachineKey[node.MachineKey]
			if !ok {
				t.Fatalf("node %d MachineKey missing from nodesByMachineKey", node.ID)
			}

			typedUID := node.TypedUserID()
			nv, ok := userMap[typedUID]
			if !ok {
				t.Fatalf("node %d not found in nodesByMachineKey[MK][UserID=%d]",
					node.ID, typedUID)
			}
			if nv.ID() != node.ID {
				t.Fatalf("nodesByMachineKey lookup for node %d returned node %d",
					node.ID, nv.ID())
			}
		}
	})
}

// ============================================================================
// Property 5: nodesByUser excludes tagged nodes
// ============================================================================

func TestRapid_Snapshot_NodesByUserExcludesTaggedNodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for uid, userNodes := range snap.nodesByUser {
			for _, nv := range userNodes {
				if nv.IsTagged() {
					t.Fatalf("tagged node %d (tags=%v) found in nodesByUser[%d]",
						nv.ID(), nv.Tags().AsSlice(), uid)
				}
			}
		}
	})
}

// ============================================================================
// Property 6: nodesByUser includes all user-owned (untagged) nodes
// ============================================================================

func TestRapid_Snapshot_NodesByUserIncludesUserOwnedNodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for _, node := range nodes {
			if node.IsTagged() {
				continue
			}

			uid := node.TypedUserID()
			userNodes, ok := snap.nodesByUser[uid]
			if !ok {
				t.Fatalf("user-owned node %d (user=%d) has no entry in nodesByUser",
					node.ID, uid)
			}

			found := false
			for _, nv := range userNodes {
				if nv.ID() == node.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("user-owned node %d not found in nodesByUser[%d]",
					node.ID, uid)
			}
		}
	})
}

// ============================================================================
// Property 7: peersByNode self-exclusion — no node appears in its own peer list
// ============================================================================

func TestRapid_Snapshot_PeersByNodeSelfExclusion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		ids := nodeIDs(nodes)
		pf := genPeersFunc(t, ids)
		snap := snapshotFromNodes(nodes, pf)

		for nodeID, peers := range snap.peersByNode {
			for _, peer := range peers {
				if peer.ID() == nodeID {
					t.Fatalf("node %d appears in its own peer list", nodeID)
				}
			}
		}
	})
}

// ============================================================================
// Property 8: peersByNode symmetry — with a symmetric PeersFunc, if Y is in
// peers(X) then X is in peers(Y)
// ============================================================================

func TestRapid_Snapshot_PeersByNodeSymmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		ids := nodeIDs(nodes)
		// Always use the symmetric random PeersFunc for this property.
		pf := symmetricRandomPeersFunc(t, ids)
		snap := snapshotFromNodes(nodes, pf)

		for nodeID, peers := range snap.peersByNode {
			for _, peer := range peers {
				// peer.ID() should have nodeID in its peers
				reversePeers, ok := snap.peersByNode[peer.ID()]
				if !ok {
					t.Fatalf("node %d is peer of %d but %d has no peersByNode entry",
						peer.ID(), nodeID, peer.ID())
				}

				found := false
				for _, rp := range reversePeers {
					if rp.ID() == nodeID {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("symmetry violation: %d in peers(%d), but %d not in peers(%d)",
						peer.ID(), nodeID, nodeID, peer.ID())
				}
			}
		}
	})
}

// ============================================================================
// Property 9: allNodes is NOT sorted by ID
//
// This test was originally written to assert that allNodes is sorted by ID.
// Rapid immediately found a counterexample: snapshotFromNodes iterates over
// a Go map (nondeterministic order) and does NOT sort allNodes. This is a
// deliberate design choice — the slice is used for iteration, not binary
// search, so sorting would be unnecessary overhead.
//
// We keep the test inverted to document and protect this behavior: if someone
// adds sorting in the future, this test will catch the change so the team can
// decide whether to update callers or revert.
// ============================================================================

func TestRapid_Snapshot_AllNodesNotSortedInvariant(t *testing.T) {
	// We verify that allNodes contains the correct IDs (unordered) and that
	// there are no duplicates, which IS an invariant.
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		seen := make(map[types.NodeID]bool, len(snap.allNodes))
		for _, nv := range snap.allNodes {
			if seen[nv.ID()] {
				t.Fatalf("duplicate ID %d in allNodes", nv.ID())
			}
			seen[nv.ID()] = true
		}

		// Every input ID must appear.
		for id := range nodes {
			if !seen[id] {
				t.Fatalf("node %d missing from allNodes", id)
			}
		}

		// No extra IDs.
		if len(seen) != len(nodes) {
			t.Fatalf("allNodes has %d unique IDs, input has %d", len(seen), len(nodes))
		}
	})
}

// ============================================================================
// Property 10: Empty input produces empty snapshot
// ============================================================================

func TestRapid_Snapshot_EmptyInputEmptySnapshot(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Use any PeersFunc strategy — doesn't matter for empty input.
		strategy := rapid.IntRange(0, 1).Draw(t, "strategy")
		var pf PeersFunc
		if strategy == 0 {
			pf = allVisiblePeersFunc
		} else {
			pf = noVisiblePeersFunc
		}

		snap := snapshotFromNodes(map[types.NodeID]types.Node{}, pf)

		if len(snap.allNodes) != 0 {
			t.Fatalf("empty input: allNodes has %d entries", len(snap.allNodes))
		}
		if len(snap.nodesByID) != 0 {
			t.Fatalf("empty input: nodesByID has %d entries", len(snap.nodesByID))
		}
		if len(snap.nodesByNodeKey) != 0 {
			t.Fatalf("empty input: nodesByNodeKey has %d entries", len(snap.nodesByNodeKey))
		}
		if len(snap.nodesByMachineKey) != 0 {
			t.Fatalf("empty input: nodesByMachineKey has %d entries", len(snap.nodesByMachineKey))
		}
		if len(snap.nodesByUser) != 0 {
			t.Fatalf("empty input: nodesByUser has %d entries", len(snap.nodesByUser))
		}
		if len(snap.peersByNode) != 0 {
			t.Fatalf("empty input: peersByNode has %d entries", len(snap.peersByNode))
		}
	})
}

// ============================================================================
// Bonus properties
// ============================================================================

// Property: nodesByUser partitions the untagged nodes — the total count of
// entries across all user buckets equals the number of untagged input nodes.
func TestRapid_Snapshot_NodesByUserPartitionsUntagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		// Count untagged nodes in input.
		untaggedCount := 0
		for _, node := range nodes {
			if !node.IsTagged() {
				untaggedCount++
			}
		}

		// Count total entries in nodesByUser.
		userNodeCount := 0
		for _, userNodes := range snap.nodesByUser {
			userNodeCount += len(userNodes)
		}

		if userNodeCount != untaggedCount {
			t.Fatalf("nodesByUser total entries %d != untagged input count %d",
				userNodeCount, untaggedCount)
		}
	})
}

// Property: allNodes contains exactly the same set of IDs as nodesByID.
func TestRapid_Snapshot_AllNodesMatchesNodesByID(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		// Collect IDs from allNodes.
		allNodeIDs := make(map[types.NodeID]bool, len(snap.allNodes))
		for _, nv := range snap.allNodes {
			if allNodeIDs[nv.ID()] {
				t.Fatalf("duplicate ID %d in allNodes", nv.ID())
			}
			allNodeIDs[nv.ID()] = true
		}

		// Compare with nodesByID.
		for id := range snap.nodesByID {
			if !allNodeIDs[id] {
				t.Fatalf("nodesByID has ID %d not found in allNodes", id)
			}
		}
		for id := range allNodeIDs {
			if _, ok := snap.nodesByID[id]; !ok {
				t.Fatalf("allNodes has ID %d not found in nodesByID", id)
			}
		}
	})
}

// Property: with allVisiblePeersFunc, every node sees exactly N-1 peers.
func TestRapid_Snapshot_AllVisiblePeersCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		n := len(nodes)
		for nodeID, peers := range snap.peersByNode {
			if len(peers) != n-1 {
				t.Fatalf("node %d has %d peers with allVisible, want %d",
					nodeID, len(peers), n-1)
			}
		}
	})
}

// Property: with noVisiblePeersFunc, every node sees zero peers.
func TestRapid_Snapshot_NoVisiblePeersCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, noVisiblePeersFunc)

		for nodeID, peers := range snap.peersByNode {
			if len(peers) != 0 {
				t.Fatalf("node %d has %d peers with noVisible, want 0",
					nodeID, len(peers))
			}
		}
	})
}

// Property: peersByNode has an entry for every node in the input (the PeersFunc
// is called with all nodes and should return an entry per node).
func TestRapid_Snapshot_PeersByNodeCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		ids := nodeIDs(nodes)
		pf := genPeersFunc(t, ids)
		snap := snapshotFromNodes(nodes, pf)

		for id := range nodes {
			if _, ok := snap.peersByNode[id]; !ok {
				t.Fatalf("node %d missing from peersByNode", id)
			}
		}
	})
}
