// Metamorphic relations: pairs of inputs whose served state must agree in
// a stated way, judged through the client's own filter where bytes may
// differ. No oracle states what is served; the relation does.

package v2

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// servedAt is node id's filter as st serves it in mode, cut afresh, and
// its client's view: its own and its peers' capabilities as rendered in
// capability mode, none in address mode.
func servedAt(st *stage, n policymodel.Node, mode SourceMode) ([]tailcfg.FilterRule, policymodel.ClientView, error) {
	if mode != CapabilitySources {
		rules, err := st.ip.Fresh().ForNode(n.ID, ReceiverFacts{})

		return rules, viewOf(n, st.w, nil), err
	}

	rules, err := st.cap.Fresh().ForNode(n.ID, st.recv.Of(n.ID))

	var peers []tailcfg.NodeView
	for _, p := range st.peersOf(n.ID) {
		peers = append(peers, st.render(p, false))
	}

	caps := policymodel.NewNetmapCaps(st.render(n.ID, true), peers)

	return rules, viewOf(n, st.w, &caps), err
}

// verdictsDiffer returns how what a and b serve node n's client differs,
// through the client, in either mode: n in a's world as an, in b's as bn.
func verdictsDiffer(a, b *stage, an, bn policymodel.Node) string {
	for _, mode := range []SourceMode{AddressSources, CapabilitySources} {
		ra, va, errA := servedAt(a, an, mode)
		rb, vb, errB := servedAt(b, bn, mode)

		if errA != nil || errB != nil {
			return fmt.Sprintf("mode %d: %v, %v", mode, errA, errB)
		}

		rep := policymodel.CompareUnder(ra, va, rb, vb)

		// An app capability's values come in the order of the rules
		// granting them, as the client lists them: a reorder moves them.
		rep.Caps = slices.DeleteFunc(rep.Caps, func(d policymodel.CapsDiff) bool { return sameValueSets(d.Ref, d.Cand) })

		if !rep.Equivalent() {
			return fmt.Sprintf("mode %d: n%d is served %s, then n%d %s: %s", mode, an.ID, rulesJSON(ra, nil), bn.ID, rulesJSON(rb, nil), rep)
		}
	}

	return ""
}

// sameValueSets reports whether a and b grant the same capabilities, each
// with the same values in any order.
func sameValueSets(a, b tailcfg.PeerCapMap) bool {
	if len(a) != len(b) {
		return false
	}

	for c, va := range a {
		vb, ok := b[c]
		if !ok || len(va) != len(vb) {
			return false
		}

		sa, sb := make([]string, len(va)), make([]string, len(vb))
		for i := range va {
			sa[i], sb[i] = string(va[i]), string(vb[i])
		}

		slices.Sort(sa)
		slices.Sort(sb)

		if !slices.Equal(sa, sb) {
			return false
		}
	}

	return true
}

// canonicalRules writes rules as a multiset: each rule's JSON, sorted.
func canonicalRules(rules []tailcfg.FilterRule) []string {
	out := make([]string, len(rules))

	for i, r := range rules {
		out[i] = jsonString(r)
	}

	slices.Sort(out)

	return out
}

// permuted is w with its ACLs, its grants and each rule's sources in the
// orders drawn.
func permuted(t *rapid.T, w policymodel.World) policymodel.World {
	p := w.Policy

	shuffle := func(rules []policymodel.Rule, label string) []policymodel.Rule {
		out := rapid.Permutation(rules).Draw(t, label)
		for i := range out {
			out[i].Src = rapid.Permutation(out[i].Src).Draw(t, fmt.Sprintf("%s[%d] sources", label, i))
		}

		return out
	}

	p.ACLs = shuffle(slices.Clone(p.ACLs), "acls")
	p.Grants = shuffle(slices.Clone(p.Grants), "grants")

	return policymodel.World{Policy: p, Topology: w.Topology}
}

// TestRuleOrderChangesNoVerdict reorders a drawn world's ACLs, grants and
// each rule's sources, and holds every node's filter to the original's
// through its client in both modes, its capability-form filter to the
// original's as a rule multiset (capability form merges within a grant,
// so order is all a reorder may move), and peers, route access and stamps
// to the original's. Oracle: the client's filter, and the world itself.
func TestRuleOrderChangesNoVerdict(t *testing.T) {
	t.Parallel()

	var shapes shapeTally

	rapid.Check(t, func(t *rapid.T) {
		w := policymodel.Worlds().Draw(t, "world")
		v := permuted(t, w)

		shapes.add(policymodel.Scenario{Start: w})

		a, errA := stageAt(nil, w, policymodel.Change{})
		b, errB := stageAt(nil, v, policymodel.Change{})

		if errA != nil || errB != nil {
			t.Fatalf("refused: %v, %v", errA, errB)
		}

		for _, n := range w.Topology.Nodes {
			if msg := verdictsDiffer(a, b, n, n); msg != "" {
				t.Fatalf("reordered as\n%#v\n%s", v.Policy, msg)
			}

			ra, _ := a.cap.Fresh().ForNode(n.ID, a.recv.Of(n.ID))
			rb, _ := b.cap.Fresh().ForNode(n.ID, b.recv.Of(n.ID))

			if receiverForm(CapabilitySources, a.recv.Of(n.ID)) == reasonNone && !slices.Equal(canonicalRules(ra), canonicalRules(rb)) {
				t.Fatalf("reordered as\n%#v\nn%d's capability-form filter moved beyond order: %s, then %s", v.Policy, n.ID, rulesJSON(ra, nil), rulesJSON(rb, nil))
			}

			if msg := sameServedSets(a, b, n.ID, n.ID, func(id types.NodeID) types.NodeID { return id }); msg != "" {
				t.Fatalf("reordered as\n%#v\n%s", v.Policy, msg)
			}
		}
	})

	shapes.log(t, "rule order")
}

// sameServedSets compares node an in a with bn in b: peers, with rename
// taking a's IDs to b's, stamps, and route access to each peer.
func sameServedSets(a, b *stage, an, bn types.NodeID, rename func(types.NodeID) types.NodeID) string {
	peers := a.peersOf(an)

	pa := make([]types.NodeID, 0, len(peers))
	for _, p := range peers {
		pa = append(pa, rename(p))
	}

	slices.Sort(pa)

	if pb := b.peersOf(bn); !slices.Equal(pa, pb) {
		return fmt.Sprintf("n%d is shown %v, then n%d %v", an, pa, bn, pb)
	}

	ra, _ := a.roles.Of(an)
	rb, _ := b.roles.Of(bn)

	if sa, sb := a.t.StampsOf(ra), b.t.StampsOf(rb); !slices.Equal(sa, sb) {
		return fmt.Sprintf("n%d is stamped %v, then n%d %v", an, sa, bn, sb)
	}

	for _, p := range a.list {
		routes := p.View().AllApprovedRoutes()
		if len(routes) == 0 {
			continue
		}

		ga, gb := a.sides.RouteAccess(an, routes), b.sides.RouteAccess(bn, routes)
		slices.SortFunc(ga, netip.Prefix.Compare)
		slices.SortFunc(gb, netip.Prefix.Compare)

		if !slices.Equal(ga, gb) {
			return fmt.Sprintf("n%d is given %v of n%d's routes, then n%d %v", an, ga, p.ID, bn, gb)
		}
	}

	return ""
}

// TestEditThenInverseRestoresServedState applies each step of a drawn
// scenario that has an inverse (policymodel.Undo), then the inverse, both
// incrementally, and holds the pipeline after the two to the pipeline
// before them, layer by layer and filter by filter (fingerprintOf): a step
// and its inverse leave no trace. Oracle: the state before.
func TestEditThenInverseRestoresServedState(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")
		shapes.add(s)

		st, err := stageAt(nil, s.Start, policymodel.Change{})
		if err != nil {
			t.Fatalf("the start's policy is refused: %s", stableError(err))
		}

		w := s.Start
		shared := sharesAddress(w)

		for i, step := range s.Steps {
			next, change := w.Commit(step)
			shared = shared || sharesAddress(next)

			after, err := stageAt(st, next, change)
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i+1, stableError(err))
			}

			if inv, ok := policymodel.Undo(w, step); ok {
				back, change := next.Commit(inv)

				restored, err := stageAt(after, back, change)
				if err != nil {
					t.Fatalf("step %d's inverse (%s) is refused: %s", i+1, inv, stableError(err))
				}

				tally.add("inverted")

				if nodeCapsDiffer(restored, st) != "" && shared {
					// The compile's stale node attributes under a shared
					// address (TestPipelineIncrementalMatchesScratch): a
					// document edit compiles them afresh.
					//
					// TODO(kradalby): policy/stale-under-shared-address:
					// delete this exception with the one in
					// TestPipelineIncrementalMatchesScratch.
					tally.add("node attributes stale under a shared address")

					return
				}

				if msg := firstDiff(fingerprintOf(restored, restored.ip.Fresh(), restored.cap.Fresh()), fingerprintOf(st, st.ip.Fresh(), st.cap.Fresh())); msg != "" {
					t.Fatalf("step %d (%s), then its inverse (%s), leave (restored, before): %s", i+1, step, inv, msg)
				}
			} else {
				tally.add("no inverse")
			}

			st, w = after, next
		}
	})

	t.Logf("edit and inverse: %v", &tally)
	shapes.log(t, "edit and inverse")
}

// TestLeaveAndIdenticalJoinRestoresServedState takes a node out of a drawn
// world and registers one like it under the next ID, at the addresses it
// held, in one commit or two, and holds what every node is served to what
// it was served before, the newcomer standing for the node that left:
// filters through the client in both modes, peers, stamps, route access.
// Oracle: the state before, with the node renamed.
func TestLeaveAndIdenticalJoinRestoresServedState(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		w := policymodel.Worlds().Draw(t, "world")
		who := rapid.IntRange(0, len(w.Topology.Nodes)-1).Draw(t, "who")
		together := rapid.Bool().Draw(t, "in one commit")

		shapes.add(policymodel.Scenario{Start: w})

		old := w.Topology.Nodes[who]
		twin := old
		twin.ID = w.Topology.NextID

		steps := []policymodel.Step{{Edits: []policymodel.Edit{policymodel.Leave{ID: old.ID}}}, {Edits: []policymodel.Edit{policymodel.Join{Node: twin}}}}
		if together {
			steps = []policymodel.Step{{Edits: []policymodel.Edit{policymodel.Leave{ID: old.ID}, policymodel.Join{Node: twin}}}}
		}

		before, err := stageAt(nil, w, policymodel.Change{})
		if err != nil {
			t.Fatalf("refused: %s", stableError(err))
		}

		st, cur := before, w

		for _, step := range steps {
			next, change := cur.Commit(step)

			st, err = stageAt(st, next, change)
			if err != nil {
				t.Fatalf("refused after %s: %s", step, stableError(err))
			}

			cur = next
		}

		if got, _ := cur.Topology.Node(twin.ID); got.ID != twin.ID || !sameNodeBut(got, old) {
			// Registration auto-approved what the node that left had not.
			tally.add("newcomer differs by auto-approval")

			return
		}

		tally.add("judged")

		rename := func(id types.NodeID) types.NodeID {
			if id == old.ID {
				return twin.ID
			}

			return id
		}

		for _, n := range w.Topology.Nodes {
			m, _ := cur.Topology.Node(rename(n.ID))

			if msg := verdictsDiffer(before, st, n, m); msg != "" {
				t.Fatalf("n%d left and n%d joined like it: %s", old.ID, twin.ID, msg)
			}

			if msg := sameServedSets(before, st, n.ID, m.ID, rename); msg != "" {
				t.Fatalf("n%d left and n%d joined like it: %s", old.ID, twin.ID, msg)
			}
		}
	})

	t.Logf("leave and join: %v", &tally)
	shapes.log(t, "leave and join")
}

// sameNodeBut reports whether a and b are the same node but for the ID.
func sameNodeBut(a, b policymodel.Node) bool {
	a.ID = b.ID

	return a.String() == b.String()
}

// TestAddingARuleRemovesNoAccess adds to a drawn world's document a rule
// of another drawn document (as an ACL, or a grant without via, whose
// steering can take routes away) and holds that no node loses anything:
// every probe its client accepted before it accepts after, in both modes,
// every app capability a source held it still holds, and every peer and
// route it was given it is still given. A document allowing everything is
// left out: its first rule restricts it. Oracle: the client's filter and
// the world before.
func TestAddingARuleRemovesNoAccess(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		w := policymodel.Worlds().Draw(t, "world")
		donor := policymodel.Policies().Draw(t, "donor")
		grant := rapid.Bool().Draw(t, "as a grant")

		shapes.add(policymodel.Scenario{Start: w})

		rules := donor.List(grant)
		if w.Policy.AllowAll || len(rules) == 0 {
			tally.add("left out")

			return
		}

		extra := rules[rapid.IntRange(0, len(rules)-1).Draw(t, "rule")]
		extra.Via = nil

		v := w
		v.Policy = w.Policy

		if grant {
			v.Policy.Grants = append(slices.Clone(w.Policy.Grants), extra)
		} else {
			v.Policy.ACLs = append(slices.Clone(w.Policy.ACLs), extra)
		}

		a, err := stageAt(nil, w, policymodel.Change{})
		if err != nil {
			t.Fatalf("refused: %s", stableError(err))
		}

		b, err := stageAt(nil, v, policymodel.Change{})
		if err != nil {
			// The donor's rule names what this document does not define.
			tally.add("refused with the rule")

			return
		}

		tally.add("judged")

		for _, n := range w.Topology.Nodes {
			if msg := accessLost(a, b, n); msg != "" {
				t.Fatalf("adding a rule to make\n%#v\n%s", v.Policy, msg)
			}
		}
	})

	t.Logf("adding a rule: %v", &tally)
	shapes.log(t, "adding a rule")
}

// accessLost returns what n had in a that it lacks in b: a probe its
// client accepted, an app capability a source held, a peer, a route.
func accessLost(a, b *stage, n policymodel.Node) string {
	for _, mode := range []SourceMode{AddressSources, CapabilitySources} {
		ra, va, _ := servedAt(a, n, mode)
		rb, vb, _ := servedAt(b, n, mode)

		rep := policymodel.CompareUnder(ra, va, rb, vb)

		for _, d := range rep.Verdicts {
			if d.Ref == filter.Accept && d.Cand != filter.Accept {
				return fmt.Sprintf("mode %d: n%d accepted %s before, refuses it after (%s, then %s)", mode, n.ID, d.Probe, rulesJSON(ra, nil), rulesJSON(rb, nil))
			}
		}

		for _, d := range rep.Caps {
			for c := range d.Ref {
				if _, ok := d.Cand[c]; !ok {
					return fmt.Sprintf("mode %d: %s held %s at n%d (%s) before, not after", mode, d.Src, c, n.ID, d.Dst)
				}
			}
		}
	}

	for _, p := range a.peersOf(n.ID) {
		if !slices.Contains(b.peersOf(n.ID), p) {
			return fmt.Sprintf("n%d saw n%d before, not after", n.ID, p)
		}
	}

	for _, p := range a.list {
		routes := p.View().AllApprovedRoutes()
		if len(routes) == 0 {
			continue
		}

		before, after := a.sides.RouteAccess(n.ID, routes), b.sides.RouteAccess(n.ID, routes)

		for _, r := range before {
			if !slices.Contains(after, r) {
				return fmt.Sprintf("n%d was given n%d's %s before, not after", n.ID, p.ID, r)
			}
		}
	}

	return ""
}

// TestPolicyEditNamingNothingNewKeepsMembership holds, across every step
// of a drawn scenario that edits the document alone and leaves the set of
// selectors it names as the model reads it, that headscale keeps its
// selector table and what follows from that: postings are compared
// selector by selector (Postings.Changed is not all); where no group
// moved either, the user sets, roles and postings are kept by identity;
// and every grant the edit left as it was keeps its template. Oracle: the
// model's selector set (policymodel), not headscale's.
func TestPolicyEditNamingNothingNewKeepsMembership(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")
		shapes.add(s)

		st, err := stageAt(nil, s.Start, policymodel.Change{})
		if err != nil {
			t.Fatalf("the start's policy is refused: %s", stableError(err))
		}

		w := s.Start

		for i, step := range s.Steps {
			next, change := w.Commit(step)

			prev := st

			st, err = stageAt(prev, next, change)
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i+1, stableError(err))
			}

			if policyOnly(step) && sameSels(w.Policy.Selectors(), next.Policy.Selectors()) {
				tally.add("judged")

				if msg := keptAcross(prev, st, reflect.DeepEqual(w.Policy.Groups, next.Policy.Groups)); msg != "" {
					t.Fatalf("step %d (%s) names nothing new: %s", i+1, step, msg)
				}
			}

			w = next
		}
	})

	t.Logf("naming nothing new: %v", &tally)
	shapes.log(t, "naming nothing new")
}

func keptAcross(prev, cur *stage, groupsKept bool) string {
	if cur.sel.table != prev.sel.table {
		return "the selector table is new"
	}

	if _, all := cur.posts.Changed(prev.posts); all {
		return "Postings.Changed says all"
	}

	if groupsKept {
		switch {
		case cur.us != prev.us:
			return "the user sets are new"
		case !cur.roles.Same(prev.roles):
			return "the roles are new"
		case !cur.posts.Same(prev.posts):
			return "the postings are new"
		}
	}

	for _, gt := range cur.t.grants {
		var equals []*GrantTemplate

		for _, pt := range prev.t.grants {
			if reflect.DeepEqual(pt.src, gt.src) {
				equals = append(equals, pt)
			}
		}

		if len(equals) > 0 && !slices.Contains(equals, gt) {
			return "a grant the edit left keeps no template: " + grantJSON(gt)
		}
	}

	return ""
}
