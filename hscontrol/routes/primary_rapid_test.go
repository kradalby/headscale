package routes

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
)

// prefixPool is a fixed set of 6 non-exit subnet prefixes used in the PBT.
var prefixPool = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/24"),
	netip.MustParsePrefix("10.0.1.0/24"),
	netip.MustParsePrefix("192.168.1.0/24"),
	netip.MustParsePrefix("192.168.2.0/24"),
	netip.MustParsePrefix("172.16.0.0/16"),
	netip.MustParsePrefix("fd00::/64"),
}

// exitRoutes are the 2 exit route prefixes that should always be filtered out.
var exitRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// allGeneratable includes both normal and exit prefixes for the generator.
var allGeneratable = append(append([]netip.Prefix{}, prefixPool...), exitRoutes...)

// genNodeID draws a small NodeID from [1, 8].
func genNodeID(t *rapid.T) types.NodeID {
	return types.NodeID(rapid.Uint64Range(1, 8).Draw(t, "nodeID"))
}

// genPrefixes draws a distinct subset of allGeneratable (including possible exit routes).
func genPrefixes(t *rapid.T) []netip.Prefix {
	return rapid.SliceOfNDistinct(
		rapid.SampledFrom(allGeneratable),
		0, len(allGeneratable),
		func(p netip.Prefix) string { return p.String() },
	).Draw(t, "prefixes")
}

// referenceModel is a simple model that tracks the same state as PrimaryRoutes
// but with a straightforward implementation for comparison.
type referenceModel struct {
	// routes maps nodeID -> set of non-exit prefixes advertised by that node.
	routes map[types.NodeID]map[netip.Prefix]struct{}

	// primaries maps prefix -> primary nodeID.
	// Mirrors PrimaryRoutes.primaries semantics:
	// - Stability: if old primary still advertises, keep it.
	// - Selection: lowest nodeID among advertisers for new primaries.
	primaries map[netip.Prefix]types.NodeID
}

func newReferenceModel() *referenceModel {
	return &referenceModel{
		routes:    make(map[types.NodeID]map[netip.Prefix]struct{}),
		primaries: make(map[netip.Prefix]types.NodeID),
	}
}

// setRoutes mirrors PrimaryRoutes.SetRoutes logic in the reference model.
// Returns true if primaries changed.
func (m *referenceModel) setRoutes(node types.NodeID, prefixes []netip.Prefix) bool {
	// Filter out exit routes and build the set.
	filtered := make(map[netip.Prefix]struct{})
	for _, p := range prefixes {
		if !tsaddr.IsExitRoute(p) {
			filtered[p] = struct{}{}
		}
	}

	if len(filtered) == 0 {
		delete(m.routes, node)
	} else {
		m.routes[node] = filtered
	}

	return m.recalcPrimaries()
}

// recalcPrimaries mirrors updatePrimaryLocked.
func (m *referenceModel) recalcPrimaries() bool {
	// Build prefix -> sorted list of advertisers.
	advertisers := make(map[netip.Prefix][]types.NodeID)
	for nid, prefixes := range m.routes {
		for p := range prefixes {
			advertisers[p] = append(advertisers[p], nid)
		}
	}
	// Sort each list by NodeID (ascending) for deterministic selection.
	for p := range advertisers {
		sort.Slice(advertisers[p], func(i, j int) bool {
			return advertisers[p][i] < advertisers[p][j]
		})
	}

	changed := false

	// For each prefix with advertisers, determine primary.
	for prefix, nodes := range advertisers {
		if currentPrimary, ok := m.primaries[prefix]; ok {
			if slices.Contains(nodes, currentPrimary) {
				// Stability: current primary still advertises, keep it.
				continue
			}
		}
		// New primary needed: pick lowest NodeID.
		m.primaries[prefix] = nodes[0]
		changed = true
	}

	// Clean up primaries for prefixes no longer advertised.
	for prefix := range m.primaries {
		if _, ok := advertisers[prefix]; !ok {
			delete(m.primaries, prefix)
			changed = true
		}
	}

	return changed
}

// primaryRoutesFor returns sorted primary prefixes for a node
// (mirrors PrimaryRoutes.PrimaryRoutes).
func (m *referenceModel) primaryRoutesFor(id types.NodeID) []netip.Prefix {
	var routes []netip.Prefix
	for prefix, nid := range m.primaries {
		if nid == id {
			routes = append(routes, prefix)
		}
	}
	slices.SortFunc(routes, netip.Prefix.Compare)
	return routes
}

// allNodeIDs returns the set of all nodeIDs that appear in the model routes.
func (m *referenceModel) allNodeIDs() []types.NodeID {
	seen := make(map[types.NodeID]struct{})
	for nid := range m.routes {
		seen[nid] = struct{}{}
	}
	ids := make([]types.NodeID, 0, len(seen))
	for nid := range seen {
		ids = append(ids, nid)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func TestRapid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pr := New()
		model := newReferenceModel()

		t.Repeat(map[string]func(*rapid.T){
			"addRoutes": func(t *rapid.T) {
				node := genNodeID(t)
				prefixes := genPrefixes(t)

				gotChanged := pr.SetRoutes(node, prefixes...)
				modelChanged := model.setRoutes(node, prefixes)

				if gotChanged != modelChanged {
					t.Fatalf("addRoutes(node=%d, prefixes=%v): changed mismatch: got %v, model %v",
						node, prefixes, gotChanged, modelChanged)
				}
			},

			"removeNode": func(t *rapid.T) {
				node := genNodeID(t)

				gotChanged := pr.SetRoutes(node) // empty = remove
				modelChanged := model.setRoutes(node, nil)

				if gotChanged != modelChanged {
					t.Fatalf("removeNode(node=%d): changed mismatch: got %v, model %v",
						node, gotChanged, modelChanged)
				}
			},

			"queryPrimary": func(t *rapid.T) {
				node := genNodeID(t)

				gotRoutes := pr.PrimaryRoutes(node)
				wantRoutes := model.primaryRoutesFor(node)

				// Normalize nil vs empty for comparison.
				if len(gotRoutes) == 0 {
					gotRoutes = nil
				}
				if len(wantRoutes) == 0 {
					wantRoutes = nil
				}

				if !slices.Equal(gotRoutes, wantRoutes) {
					t.Fatalf("queryPrimary(node=%d): got %v, want %v",
						node, gotRoutes, wantRoutes)
				}
			},

			// Invariant checker runs after every operation.
			"": func(t *rapid.T) {
				checkAllInvariants(t, pr, model)
			},
		})
	})
}

// checkAllInvariants verifies all required invariants hold.
// Uses DebugJSON() and PrimaryRoutes() (public API) for verification.
func checkAllInvariants(t *rapid.T, pr *PrimaryRoutes, model *referenceModel) {
	debug := pr.DebugJSON()

	// Collect all advertised prefixes (union across all nodes).
	allAdvertised := make(map[netip.Prefix]bool)
	for _, prefixes := range debug.AvailableRoutes {
		for _, p := range prefixes {
			allAdvertised[p] = true
		}
	}

	// Collect all primary assignments from DebugJSON.
	primaries := make(map[netip.Prefix]types.NodeID, len(debug.PrimaryRoutes))
	for prefixStr, nodeID := range debug.PrimaryRoutes {
		p := netip.MustParsePrefix(prefixStr)
		primaries[p] = nodeID
	}

	// Invariant 1: Every advertised prefix has exactly one primary.
	for p := range allAdvertised {
		if _, ok := primaries[p]; !ok {
			t.Fatalf("invariant 1: prefix %s is advertised but has no primary", p)
		}
	}
	// Count: number of primaries must equal number of advertised prefixes.
	if len(primaries) != len(allAdvertised) {
		t.Fatalf("invariant 1: primaries count (%d) != advertised prefixes count (%d)\nprimaries: %v\nadvertised: %v",
			len(primaries), len(allAdvertised), primaries, allAdvertised)
	}

	// Invariant 2: Primary is a valid advertiser for that prefix.
	for p, nodeID := range primaries {
		nodeRoutes, ok := debug.AvailableRoutes[nodeID]
		if !ok {
			t.Fatalf("invariant 2: primary node %d for prefix %s has no routes at all", nodeID, p)
		}
		if !slices.Contains(nodeRoutes, p) {
			t.Fatalf("invariant 2: primary node %d for prefix %s does not advertise that prefix (routes: %v)",
				nodeID, p, nodeRoutes)
		}
	}

	// Invariant 3: No orphaned primaries (prefix in primaries but nobody advertises).
	for p := range primaries {
		if !allAdvertised[p] {
			t.Fatalf("invariant 3: prefix %s has a primary but no advertisers", p)
		}
	}

	// Invariant 4: No exit routes anywhere in the system.
	for _, prefixes := range debug.AvailableRoutes {
		for _, p := range prefixes {
			if tsaddr.IsExitRoute(p) {
				t.Fatalf("invariant 4: exit route %s found in available routes", p)
			}
		}
	}
	for prefixStr := range debug.PrimaryRoutes {
		p := netip.MustParsePrefix(prefixStr)
		if tsaddr.IsExitRoute(p) {
			t.Fatalf("invariant 4: exit route %s found in primaries", p)
		}
	}

	// Invariant 5: isPrimary index is consistent.
	// A node isPrimary iff it is primary for some prefix.
	// We verify this through the public API: for every node in [1,8],
	// PrimaryRoutes(id) returns non-nil iff the node is a primary for something.
	expectedPrimaryNodes := make(map[types.NodeID]bool)
	for _, nodeID := range primaries {
		expectedPrimaryNodes[nodeID] = true
	}
	for id := types.NodeID(1); id <= 8; id++ {
		routes := pr.PrimaryRoutes(id)
		hasPrimaries := len(routes) > 0
		shouldHave := expectedPrimaryNodes[id]
		if hasPrimaries != shouldHave {
			t.Fatalf("invariant 5: isPrimary inconsistency for node %d: PrimaryRoutes returned %v but expected isPrimary=%v",
				id, routes, shouldHave)
		}
	}

	// Invariant 6: Deterministic selection - lowest remaining ID wins when new primary needed.
	// We verify this by checking the model's primaries match the SUT's primaries exactly.
	// The model implements the same lowest-ID selection rule.
	for p, modelNode := range model.primaries {
		sutNode, ok := primaries[p]
		if !ok {
			t.Fatalf("invariant 6: prefix %s in model primaries but not in SUT", p)
		}
		if sutNode != modelNode {
			t.Fatalf("invariant 6: primary for %s: SUT=%d, model=%d (lowest-ID violation)",
				p, sutNode, modelNode)
		}
	}
	for p, sutNode := range primaries {
		modelNode, ok := model.primaries[p]
		if !ok {
			t.Fatalf("invariant 6: prefix %s in SUT primaries but not in model", p)
		}
		if sutNode != modelNode {
			t.Fatalf("invariant 6: primary for %s: SUT=%d, model=%d", p, sutNode, modelNode)
		}
	}

	// Invariant 7: Stability - if old primary still advertises, it stays.
	// This is enforced by the model comparison above: the model implements stability,
	// so if the SUT matches the model, stability is preserved.
	// Additionally, we can verify per-node that PrimaryRoutes output matches model.
	allNodeIDs := model.allNodeIDs()
	// Also include nodes that might be in the SUT but not in model routes.
	for nodeID := range debug.AvailableRoutes {
		found := false
		for _, id := range allNodeIDs {
			if id == nodeID {
				found = true
				break
			}
		}
		if !found {
			allNodeIDs = append(allNodeIDs, nodeID)
		}
	}
	for _, nodeID := range allNodeIDs {
		gotRoutes := pr.PrimaryRoutes(nodeID)
		wantRoutes := model.primaryRoutesFor(nodeID)
		if len(gotRoutes) == 0 {
			gotRoutes = nil
		}
		if len(wantRoutes) == 0 {
			wantRoutes = nil
		}
		if !slices.Equal(gotRoutes, wantRoutes) {
			t.Fatalf("invariant 7 (stability via model): PrimaryRoutes(%d): got %v, want %v",
				nodeID, gotRoutes, wantRoutes)
		}
	}

	// Cross-check: every primary prefix appears exactly once across all nodes'
	// PrimaryRoutes results.
	seenPrefixes := make(map[netip.Prefix]types.NodeID)
	for id := types.NodeID(1); id <= 8; id++ {
		for _, p := range pr.PrimaryRoutes(id) {
			if prev, ok := seenPrefixes[p]; ok {
				t.Fatalf("invariant cross-check: prefix %s claimed by both node %d and node %d",
					p, prev, id)
			}
			seenPrefixes[p] = id
		}
	}
	if len(seenPrefixes) != len(primaries) {
		t.Fatalf("invariant cross-check: PrimaryRoutes across all nodes yields %d prefixes, but DebugJSON has %d",
			len(seenPrefixes), len(primaries))
	}
	for p, nodeID := range seenPrefixes {
		if primaries[p] != nodeID {
			t.Fatalf("invariant cross-check: prefix %s: PrimaryRoutes says node %d, DebugJSON says node %d",
				p, nodeID, primaries[p])
		}
	}

	// Verify DebugJSON available routes match model routes.
	if len(debug.AvailableRoutes) != len(model.routes) {
		t.Fatalf("available routes count mismatch: SUT=%d, model=%d",
			len(debug.AvailableRoutes), len(model.routes))
	}
	for nodeID, modelPrefixes := range model.routes {
		sutPrefixes, ok := debug.AvailableRoutes[nodeID]
		if !ok {
			t.Fatalf("node %d in model routes but not in SUT AvailableRoutes", nodeID)
		}
		modelSorted := make([]netip.Prefix, 0, len(modelPrefixes))
		for p := range modelPrefixes {
			modelSorted = append(modelSorted, p)
		}
		slices.SortFunc(modelSorted, netip.Prefix.Compare)
		// sutPrefixes are already sorted by DebugJSON.
		if !slices.Equal(sutPrefixes, modelSorted) {
			t.Fatalf("node %d routes mismatch:\n  SUT:   %v\n  model: %v",
				nodeID, sutPrefixes, modelSorted)
		}
	}

	_ = fmt.Sprintf("invariants checked: %d primaries, %d nodes", len(primaries), len(debug.AvailableRoutes))
}
