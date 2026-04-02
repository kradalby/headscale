package change

import (
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// --- Generators ---

// genNodeID generates a small NodeID in [1, 20].
// Zero is excluded because it serves as the "unset" sentinel for
// OriginNode and TargetNode.
func genNodeID(t *rapid.T) types.NodeID {
	return types.NodeID(rapid.Uint64Range(1, 20).Draw(t, "nodeID"))
}

// genNodeIDSlice generates a slice of 0..8 non-zero NodeIDs.
// May contain duplicates, which exercises uniqueNodeIDs deduplication.
func genNodeIDSlice(t *rapid.T) []types.NodeID {
	return rapid.SliceOfN(rapid.Map(rapid.Uint64Range(1, 20), func(v uint64) types.NodeID {
		return types.NodeID(v)
	}), 0, 8).Draw(t, "nodeIDs")
}

// genPeerPatch generates a *tailcfg.PeerChange with a random NodeID.
func genPeerPatch(t *rapid.T) *tailcfg.PeerChange {
	return &tailcfg.PeerChange{
		NodeID: tailcfg.NodeID(rapid.Uint64Range(1, 20).Draw(t, "patchNodeID")),
	}
}

// genPeerPatches generates 0..4 PeerChange pointers.
func genPeerPatches(t *rapid.T) []*tailcfg.PeerChange {
	n := rapid.IntRange(0, 4).Draw(t, "numPatches")
	patches := make([]*tailcfg.PeerChange, n)
	for i := range patches {
		patches[i] = genPeerPatch(t)
	}
	return patches
}

// genReason generates a short reason string (possibly empty).
func genReason(t *rapid.T) string {
	return rapid.SampledFrom([]string{
		"", "policy", "route change", "tag change", "DERP update", "node added",
	}).Draw(t, "reason")
}

// genChange generates a fully random Change.
func genChange(t *rapid.T) Change {
	return Change{
		Reason:                         genReason(t),
		TargetNode:                     types.NodeID(rapid.Uint64Range(0, 10).Draw(t, "targetNode")),
		OriginNode:                     types.NodeID(rapid.Uint64Range(0, 10).Draw(t, "originNode")),
		IncludeSelf:                    rapid.Bool().Draw(t, "includeSelf"),
		IncludeDERPMap:                 rapid.Bool().Draw(t, "includeDERPMap"),
		IncludeDNS:                     rapid.Bool().Draw(t, "includeDNS"),
		IncludeDomain:                  rapid.Bool().Draw(t, "includeDomain"),
		IncludePolicy:                  rapid.Bool().Draw(t, "includePolicy"),
		SendAllPeers:                   rapid.Bool().Draw(t, "sendAllPeers"),
		RequiresRuntimePeerComputation: rapid.Bool().Draw(t, "requiresRuntimePeerComputation"),
		PeersChanged:                   genNodeIDSlice(t),
		PeersRemoved:                   genNodeIDSlice(t),
		PeerPatches:                    genPeerPatches(t),
	}
}

// genBoolOnlyChange generates a Change with only boolean fields set.
// Isolates boolean algebra properties from peer/reason complications.
func genBoolOnlyChange(t *rapid.T) Change {
	return Change{
		IncludeSelf:                    rapid.Bool().Draw(t, "includeSelf"),
		IncludeDERPMap:                 rapid.Bool().Draw(t, "includeDERPMap"),
		IncludeDNS:                     rapid.Bool().Draw(t, "includeDNS"),
		IncludeDomain:                  rapid.Bool().Draw(t, "includeDomain"),
		IncludePolicy:                  rapid.Bool().Draw(t, "includePolicy"),
		SendAllPeers:                   rapid.Bool().Draw(t, "sendAllPeers"),
		RequiresRuntimePeerComputation: rapid.Bool().Draw(t, "requiresRuntimePeerComputation"),
	}
}

// --- Helpers ---

// cloneChange creates a deep copy of a Change so that Merge's append
// aliasing bug cannot corrupt subsequent uses of the original.
func cloneChange(c Change) Change {
	out := c
	if c.PeersChanged != nil {
		out.PeersChanged = make([]types.NodeID, len(c.PeersChanged))
		copy(out.PeersChanged, c.PeersChanged)
	}
	if c.PeersRemoved != nil {
		out.PeersRemoved = make([]types.NodeID, len(c.PeersRemoved))
		copy(out.PeersRemoved, c.PeersRemoved)
	}
	if c.PeerPatches != nil {
		out.PeerPatches = make([]*tailcfg.PeerChange, len(c.PeerPatches))
		copy(out.PeerPatches, c.PeerPatches)
	}
	return out
}

// boolFields extracts all 7 boolean fields as a fixed-size array for comparison.
func boolFields(c Change) [7]bool {
	return [7]bool{
		c.IncludeSelf,
		c.IncludeDERPMap,
		c.IncludeDNS,
		c.IncludeDomain,
		c.IncludePolicy,
		c.SendAllPeers,
		c.RequiresRuntimePeerComputation,
	}
}

// nodeIDSet returns a sorted, deduplicated copy of ids for set comparison.
func nodeIDSet(ids []types.NodeID) []types.NodeID {
	if len(ids) == 0 {
		return nil
	}
	s := make([]types.NodeID, len(ids))
	copy(s, ids)
	slices.Sort(s)
	return slices.Compact(s)
}

// validTypes is the complete set of values Type() may return.
var validTypes = map[string]bool{
	"full":    true,
	"self":    true,
	"policy":  true,
	"patch":   true,
	"peers":   true,
	"config":  true,
	"unknown": true,
}

// -----------------------------------------------------------------------
// Property 1: Boolean commutativity
//   a.Merge(b) and b.Merge(a) produce identical boolean fields.
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanCommutativity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		ab := cloneChange(a).Merge(cloneChange(b))
		ba := cloneChange(b).Merge(cloneChange(a))

		if boolFields(ab) != boolFields(ba) {
			t.Fatalf("boolean commutativity violated:\n  a.Merge(b) = %v\n  b.Merge(a) = %v",
				boolFields(ab), boolFields(ba))
		}
	})
}

// -----------------------------------------------------------------------
// Property 2: Boolean associativity
//   (a.Merge(b)).Merge(c) == a.Merge(b.Merge(c)) for boolean fields.
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanAssociativity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genBoolOnlyChange(t)
		b := genBoolOnlyChange(t)
		c := genBoolOnlyChange(t)

		left := a.Merge(b).Merge(c)
		right := a.Merge(b.Merge(c))

		if boolFields(left) != boolFields(right) {
			t.Fatalf("boolean associativity violated:\n  (a⊕b)⊕c = %v\n  a⊕(b⊕c) = %v",
				boolFields(left), boolFields(right))
		}
	})
}

// -----------------------------------------------------------------------
// Property 3: Identity element
//   Merging with the zero-value Change preserves all fields (modulo
//   uniqueNodeIDs normalization of peer sets).
// -----------------------------------------------------------------------

func TestRapid_Merge_IdentityElement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		zero := Change{}

		// --- right identity: a ⊕ zero ---
		rightID := cloneChange(a).Merge(zero)

		if boolFields(rightID) != boolFields(a) {
			t.Fatalf("right identity violated booleans:\n  a = %v\n  a⊕0 = %v",
				boolFields(a), boolFields(rightID))
		}
		if !slices.Equal(nodeIDSet(rightID.PeersChanged), nodeIDSet(a.PeersChanged)) {
			t.Fatalf("right identity violated PeersChanged:\n  a = %v\n  a⊕0 = %v",
				a.PeersChanged, rightID.PeersChanged)
		}
		if !slices.Equal(nodeIDSet(rightID.PeersRemoved), nodeIDSet(a.PeersRemoved)) {
			t.Fatalf("right identity violated PeersRemoved:\n  a = %v\n  a⊕0 = %v",
				a.PeersRemoved, rightID.PeersRemoved)
		}
		if len(rightID.PeerPatches) != len(a.PeerPatches) {
			t.Fatalf("right identity violated PeerPatches len: a=%d, a⊕0=%d",
				len(a.PeerPatches), len(rightID.PeerPatches))
		}
		if rightID.OriginNode != a.OriginNode {
			t.Fatalf("right identity violated OriginNode: a=%d, a⊕0=%d",
				a.OriginNode, rightID.OriginNode)
		}
		if rightID.TargetNode != a.TargetNode {
			t.Fatalf("right identity violated TargetNode: a=%d, a⊕0=%d",
				a.TargetNode, rightID.TargetNode)
		}
		if a.Reason != "" && rightID.Reason != a.Reason {
			t.Fatalf("right identity violated Reason: a=%q, a⊕0=%q",
				a.Reason, rightID.Reason)
		}

		// --- left identity: zero ⊕ a ---
		leftID := zero.Merge(cloneChange(a))

		if boolFields(leftID) != boolFields(a) {
			t.Fatalf("left identity violated booleans:\n  a = %v\n  0⊕a = %v",
				boolFields(a), boolFields(leftID))
		}
		if !slices.Equal(nodeIDSet(leftID.PeersChanged), nodeIDSet(a.PeersChanged)) {
			t.Fatalf("left identity violated PeersChanged:\n  a = %v\n  0⊕a = %v",
				a.PeersChanged, leftID.PeersChanged)
		}
		if !slices.Equal(nodeIDSet(leftID.PeersRemoved), nodeIDSet(a.PeersRemoved)) {
			t.Fatalf("left identity violated PeersRemoved:\n  a = %v\n  0⊕a = %v",
				a.PeersRemoved, leftID.PeersRemoved)
		}
		if len(leftID.PeerPatches) != len(a.PeerPatches) {
			t.Fatalf("left identity violated PeerPatches len: a=%d, 0⊕a=%d",
				len(a.PeerPatches), len(leftID.PeerPatches))
		}
		if leftID.OriginNode != a.OriginNode {
			t.Fatalf("left identity violated OriginNode: a=%d, 0⊕a=%d",
				a.OriginNode, leftID.OriginNode)
		}
		if leftID.TargetNode != a.TargetNode {
			t.Fatalf("left identity violated TargetNode: a=%d, 0⊕a=%d",
				a.TargetNode, leftID.TargetNode)
		}
	})
}

// -----------------------------------------------------------------------
// Property 4: Boolean idempotence
//   a.Merge(a) preserves all boolean values (OR is idempotent).
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanIdempotence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)

		aa := cloneChange(a).Merge(cloneChange(a))

		if boolFields(aa) != boolFields(a) {
			t.Fatalf("boolean idempotence violated:\n  a      = %v\n  a⊕a = %v",
				boolFields(a), boolFields(aa))
		}
	})
}

// -----------------------------------------------------------------------
// Property 5: Peer set commutativity
//   PeersChanged and PeersRemoved are commutative (set union).
// -----------------------------------------------------------------------

func TestRapid_Merge_PeerSetCommutativity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		ab := cloneChange(a).Merge(cloneChange(b))
		ba := cloneChange(b).Merge(cloneChange(a))

		if !slices.Equal(ab.PeersChanged, ba.PeersChanged) {
			t.Fatalf("PeersChanged commutativity violated:\n  a⊕b = %v\n  b⊕a = %v",
				ab.PeersChanged, ba.PeersChanged)
		}
		if !slices.Equal(ab.PeersRemoved, ba.PeersRemoved) {
			t.Fatalf("PeersRemoved commutativity violated:\n  a⊕b = %v\n  b⊕a = %v",
				ab.PeersRemoved, ba.PeersRemoved)
		}
	})
}

// -----------------------------------------------------------------------
// Property 6: IsEmpty monotonicity
//   Once non-empty, merging can never make it empty.
// -----------------------------------------------------------------------

func TestRapid_Merge_IsEmptyMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		merged := cloneChange(a).Merge(cloneChange(b))

		if !a.IsEmpty() && merged.IsEmpty() {
			t.Fatalf("IsEmpty monotonicity violated (left non-empty):\n  a = %+v\n  b = %+v\n  a⊕b = %+v",
				a, b, merged)
		}
		if !b.IsEmpty() && merged.IsEmpty() {
			t.Fatalf("IsEmpty monotonicity violated (right non-empty):\n  a = %+v\n  b = %+v\n  a⊕b = %+v",
				a, b, merged)
		}
	})
}

// -----------------------------------------------------------------------
// Property 7: IsFull monotonicity
//   A full update stays full after merge.
// -----------------------------------------------------------------------

func TestRapid_Merge_IsFullMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		merged := cloneChange(a).Merge(cloneChange(b))

		if a.IsFull() && !merged.IsFull() {
			t.Fatalf("IsFull monotonicity violated (left full):\n  a = %+v\n  a⊕b = %+v", a, merged)
		}
		if b.IsFull() && !merged.IsFull() {
			t.Fatalf("IsFull monotonicity violated (right full):\n  b = %+v\n  a⊕b = %+v", b, merged)
		}
	})
}

// -----------------------------------------------------------------------
// Property 8: FullUpdate absorption
//   Merging with FullUpdate() always yields IsFull().
// -----------------------------------------------------------------------

func TestRapid_Merge_FullUpdateAbsorption(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		full := FullUpdate()

		right := cloneChange(a).Merge(full)
		if !right.IsFull() {
			t.Fatalf("a⊕FullUpdate is not full:\n  a = %+v\n  result = %+v", a, right)
		}

		left := full.Merge(cloneChange(a))
		if !left.IsFull() {
			t.Fatalf("FullUpdate⊕a is not full:\n  a = %+v\n  result = %+v", a, left)
		}
	})
}

// -----------------------------------------------------------------------
// Property 9: Type classification soundness
//   Type() always returns one of the 7 known values.
// -----------------------------------------------------------------------

func TestRapid_Type_ClassificationSoundness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)

		typ := a.Type()
		if !validTypes[typ] {
			t.Fatalf("Type() returned %q, not in valid set %v", typ, validTypes)
		}
	})
}

// -----------------------------------------------------------------------
// Property 10: FilterForNode / SplitTargetedAndBroadcast partition
//   - broadcast ∪ targeted == input (size invariant)
//   - broadcast changes all have TargetNode==0
//   - targeted changes all have TargetNode!=0
//   - FilterForNode returns exactly the changes whose ShouldSendToNode is true
//   - Broadcast changes pass ShouldSendToNode for every node
// -----------------------------------------------------------------------

func TestRapid_FilterForNode_Partition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 10).Draw(t, "numChanges")
		cs := make([]Change, n)
		for i := range cs {
			cs[i] = genChange(t)
		}

		broadcast, targeted := SplitTargetedAndBroadcast(cs)

		// Size invariant.
		if len(broadcast)+len(targeted) != len(cs) {
			t.Fatalf("partition size: %d + %d != %d",
				len(broadcast), len(targeted), len(cs))
		}

		// Classification invariants.
		for i, c := range broadcast {
			if c.TargetNode != 0 {
				t.Fatalf("broadcast[%d].TargetNode = %d, want 0", i, c.TargetNode)
			}
		}
		for i, c := range targeted {
			if c.TargetNode == 0 {
				t.Fatalf("targeted[%d].TargetNode = 0, want non-zero", i)
			}
		}

		// FilterForNode completeness and soundness.
		testNodeID := genNodeID(t)
		filtered := FilterForNode(testNodeID, cs)

		for i, c := range filtered {
			if !c.ShouldSendToNode(testNodeID) {
				t.Fatalf("filtered[%d] should not be included for node %d", i, testNodeID)
			}
		}

		expectedCount := 0
		for _, c := range cs {
			if c.ShouldSendToNode(testNodeID) {
				expectedCount++
			}
		}
		if len(filtered) != expectedCount {
			t.Fatalf("FilterForNode(%d): got %d, want %d", testNodeID, len(filtered), expectedCount)
		}

		// Broadcast changes should reach every node.
		probeNode := genNodeID(t)
		for _, c := range broadcast {
			if !c.ShouldSendToNode(probeNode) {
				t.Fatalf("broadcast change not sent to node %d", probeNode)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 11: HasFull equivalence
//   HasFull(cs) ↔ any element c in cs satisfies c.IsFull()
// -----------------------------------------------------------------------

func TestRapid_HasFull_Equivalence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 10).Draw(t, "numChanges")
		cs := make([]Change, n)
		for i := range cs {
			cs[i] = genChange(t)
		}

		got := HasFull(cs)
		want := slices.ContainsFunc(cs, func(c Change) bool { return c.IsFull() })

		if got != want {
			t.Fatalf("HasFull=%v, ContainsFunc=%v for %d changes", got, want, len(cs))
		}
	})
}

// -----------------------------------------------------------------------
// Property 12: uniqueNodeIDs idempotent
//   uniqueNodeIDs(uniqueNodeIDs(x)) == uniqueNodeIDs(x)
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		// Work on copies because uniqueNodeIDs sorts in-place.
		ids1 := make([]types.NodeID, len(raw))
		copy(ids1, raw)
		first := uniqueNodeIDs(ids1)

		if first == nil {
			return
		}

		ids2 := make([]types.NodeID, len(first))
		copy(ids2, first)
		second := uniqueNodeIDs(ids2)

		if !slices.Equal(first, second) {
			t.Fatalf("not idempotent: first=%v, second=%v", first, second)
		}
	})
}

// -----------------------------------------------------------------------
// Property 13: uniqueNodeIDs result is always sorted
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_Sorted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		ids := make([]types.NodeID, len(raw))
		copy(ids, raw)
		result := uniqueNodeIDs(ids)

		if result != nil && !slices.IsSorted(result) {
			t.Fatalf("not sorted: %v", result)
		}
	})
}

// -----------------------------------------------------------------------
// Property 14: uniqueNodeIDs no duplicates
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_NoDuplicates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		ids := make([]types.NodeID, len(raw))
		copy(ids, raw)
		result := uniqueNodeIDs(ids)

		for i := 1; i < len(result); i++ {
			if result[i] == result[i-1] {
				t.Fatalf("duplicate at index %d: %v", i, result)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 15: uniqueNodeIDs preserves all input values
//   Every value in the input appears in the output (and vice-versa).
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_PreservesValues(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		ids := make([]types.NodeID, len(raw))
		copy(ids, raw)
		result := uniqueNodeIDs(ids)

		if len(raw) == 0 {
			if result != nil {
				t.Fatalf("uniqueNodeIDs(empty) = %v, want nil", result)
			}
			return
		}

		// All input values present in output.
		resultSet := make(map[types.NodeID]bool, len(result))
		for _, id := range result {
			resultSet[id] = true
		}
		for _, id := range raw {
			if !resultSet[id] {
				t.Fatalf("input value %d dropped: input=%v, output=%v", id, raw, result)
			}
		}

		// No extra values in output.
		inputSet := make(map[types.NodeID]bool, len(raw))
		for _, id := range raw {
			inputSet[id] = true
		}
		for _, id := range result {
			if !inputSet[id] {
				t.Fatalf("output value %d not in input: input=%v, output=%v", id, raw, result)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 16: Mutation safety (documents known bug)
//   Merge must not mutate the receiver's or argument's slices.
//
// NOTE: This test documents a known bug in the current Merge implementation.
// Merge uses append(r.PeersChanged, other.PeersChanged...) which can write
// through to the receiver's backing array when it has spare capacity,
// corrupting the receiver's slice contents. The same applies to PeersRemoved
// and PeerPatches.
//
// This test is expected to FAIL until the bug is fixed. If it passes,
// the bug has been resolved and this comment can be removed.
// -----------------------------------------------------------------------

func TestRapid_Merge_MutationSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		// Snapshot all slice fields before Merge.
		aPeersChanged := make([]types.NodeID, len(a.PeersChanged))
		copy(aPeersChanged, a.PeersChanged)
		aPeersRemoved := make([]types.NodeID, len(a.PeersRemoved))
		copy(aPeersRemoved, a.PeersRemoved)
		aPeerPatches := make([]*tailcfg.PeerChange, len(a.PeerPatches))
		copy(aPeerPatches, a.PeerPatches)

		bPeersChanged := make([]types.NodeID, len(b.PeersChanged))
		copy(bPeersChanged, b.PeersChanged)
		bPeersRemoved := make([]types.NodeID, len(b.PeersRemoved))
		copy(bPeersRemoved, b.PeersRemoved)
		bPeerPatches := make([]*tailcfg.PeerChange, len(b.PeerPatches))
		copy(bPeerPatches, b.PeerPatches)

		aBools := boolFields(a)
		bBools := boolFields(b)
		aOrigin, bOrigin := a.OriginNode, b.OriginNode
		aTarget, bTarget := a.TargetNode, b.TargetNode
		aReason, bReason := a.Reason, b.Reason

		_ = a.Merge(b)

		// Verify receiver (a) not mutated.
		if boolFields(a) != aBools {
			t.Fatal("Merge mutated receiver's boolean fields")
		}
		if a.OriginNode != aOrigin || a.TargetNode != aTarget || a.Reason != aReason {
			t.Fatal("Merge mutated receiver's scalar fields")
		}
		if !slices.Equal(a.PeersChanged, aPeersChanged) {
			t.Fatalf("Merge mutated receiver's PeersChanged: before=%v, after=%v",
				aPeersChanged, a.PeersChanged)
		}
		if !slices.Equal(a.PeersRemoved, aPeersRemoved) {
			t.Fatalf("Merge mutated receiver's PeersRemoved: before=%v, after=%v",
				aPeersRemoved, a.PeersRemoved)
		}
		if !slices.Equal(a.PeerPatches, aPeerPatches) {
			t.Fatal("Merge mutated receiver's PeerPatches")
		}

		// Verify argument (b) not mutated.
		if boolFields(b) != bBools {
			t.Fatal("Merge mutated argument's boolean fields")
		}
		if b.OriginNode != bOrigin || b.TargetNode != bTarget || b.Reason != bReason {
			t.Fatal("Merge mutated argument's scalar fields")
		}
		if !slices.Equal(b.PeersChanged, bPeersChanged) {
			t.Fatalf("Merge mutated argument's PeersChanged: before=%v, after=%v",
				bPeersChanged, b.PeersChanged)
		}
		if !slices.Equal(b.PeersRemoved, bPeersRemoved) {
			t.Fatalf("Merge mutated argument's PeersRemoved: before=%v, after=%v",
				bPeersRemoved, b.PeersRemoved)
		}
		if !slices.Equal(b.PeerPatches, bPeerPatches) {
			t.Fatal("Merge mutated argument's PeerPatches")
		}
	})
}

// -----------------------------------------------------------------------
// Property 17: FullUpdate constructor always produces IsFull().
// -----------------------------------------------------------------------

func TestRapid_Constructors_FullUpdateIsFull(t *testing.T) {
	// This is deterministic, but we use rapid for consistency.
	rapid.Check(t, func(t *rapid.T) {
		f := FullUpdate()
		if !f.IsFull() {
			t.Fatalf("FullUpdate() is not full: %+v", f)
		}
	})
}

// -----------------------------------------------------------------------
// Property 18: SelfUpdate constructor produces IsSelfOnly() for n > 0.
// -----------------------------------------------------------------------

func TestRapid_Constructors_SelfUpdateIsSelfOnly(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := genNodeID(t) // always > 0 since genNodeID uses [1, 20]
		s := SelfUpdate(n)
		if !s.IsSelfOnly() {
			t.Fatalf("SelfUpdate(%d) is not self-only: %+v", n, s)
		}
	})
}
