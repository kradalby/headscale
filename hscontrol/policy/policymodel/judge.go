package policymodel

import (
	"fmt"
	"maps"
	"math/bits"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

// Verdicts are the differences from the reference a property allows when
// it holds the rules a node is served to the reference's rules for it,
// each counted; anything else fails it. Every property judging served
// rules shares them, so that one allowance means one thing wherever the
// rules come from.
type Verdicts struct {
	// CrossFamilyICMP: capability form refuses a packet carrying the
	// other family's ICMP protocol, which address form accepts: decided as
	// malformed, failing closed.
	CrossFamilyICMP int
	// Hidden: a verdict or app capability on an address the client is
	// shown no node at, which no packet carries (disable-ipv4).
	Hidden int
	// RepeatedValues: an app capability's values come once per
	// destination entry of a grant that names the receiver, where the
	// reference gives them once per grant. Reported, not encoded; no
	// capture holds an app grant with two destinations.
	RepeatedValues int
	// Contested counts the differences that are exactly some contested
	// clauses of the reference, by the set of clauses.
	Contested map[Contested]int
}

func (c *Verdicts) addContested(k Contested, n int) {
	if c.Contested == nil {
		c.Contested = map[Contested]int{}
	}

	c.Contested[k] += n
}

// Headscale is every contested clause: the reference less it is
// headscale's reading, each clause restated together with every other.
var Headscale = func() Contested {
	var all Contested
	for _, k := range ContestedClauses {
		all |= k
	}

	return all
}()

// attribute holds a difference from the reference to headscale's reading:
// reproduces tells whether the reference less some clauses gives what
// production does. Production must be the reference less [Headscale]
// exactly, so no mix of clauses forgives more than all of them do
// together. It returns the clauses the difference is counted under: the
// first that alone reproduces it, else the fewest that do together
// found by leaving clauses back in one at a time.
func attribute(reproduces func(Contested) bool) (Contested, bool) {
	if !reproduces(Headscale) {
		return 0, false
	}

	for _, k := range ContestedClauses {
		if reproduces(k) {
			return k, true
		}
	}

	set := Headscale

	for _, k := range ContestedClauses {
		if rest := set &^ k; bits.OnesCount16(uint16(rest)) > 1 && reproduces(rest) {
			set = rest
		}
	}

	return set, true
}

// inexact names clauses that reproduce a difference headscale's reading
// does not: every clause but one, which is then restated otherwise than
// headscale behaves beside the others; else one or two alone.
func inexact(reproduces func(Contested) bool) Contested {
	for _, k := range ContestedClauses {
		if reproduces(Headscale &^ k) {
			return Headscale &^ k
		}
	}

	for i, a := range ContestedClauses {
		if reproduces(a) {
			return a
		}

		for _, b := range ContestedClauses[i+1:] {
			if reproduces(a | b) {
				return a | b
			}
		}
	}

	return 0
}

// ContestedCounts lists counts by clause set, in the order of the sets.
func ContestedCounts(counts map[Contested]int) []string {
	var parts []string

	for _, k := range slices.Sorted(maps.Keys(counts)) {
		if counts[k] > 0 {
			open := ""
			if k.FailsOpen() {
				open = ", fails open"
			}

			parts = append(parts, fmt.Sprintf("%d %s%s", counts[k], k, open))
		}
	}

	return parts
}

func (c *Verdicts) String() string {
	parts := ContestedCounts(c.Contested)

	return fmt.Sprintf("allowed %d cross-family ICMP, %d on hidden addresses; suspected: %d app values repeated; contested %v",
		c.CrossFamilyICMP, c.Hidden, c.RepeatedValues, parts)
}

// judge holds rep, a comparison of the reference's rules (as Ref) with
// production's got (as Cand) at node id, to the allowed classes, and
// returns the differences left.
func (c *Verdicts) judge(rep Report, ref *Ref, id types.NodeID, view ClientView, got []tailcfg.FilterRule, capForm bool) Report {
	if capForm {
		crossed, rest := rep.SplitCrossFamilyICMP()
		c.CrossFamilyICMP += crossed
		rep = rest
	}

	hidden, rest := rep.SplitHidden(view.Hidden)
	c.Hidden += hidden
	rep = rest

	rep.Caps = slices.DeleteFunc(rep.Caps, func(d CapsDiff) bool {
		// TODO(kradalby): policy/app-values-repeated: cosmetic, no verdict
		// moves. An app grant with "dst": ["*", "*"] gives the receiver
		// its capability values twice in CapsWithValues: production
		// writes one CapGrant per destination entry naming the receiver
		// (capGrantRules in expand.go), the reference one per grant. No
		// capture holds an app grant with two destinations. Delete this
		// allowance once production merges the entries, or once a capture
		// shows the hosted service repeating them.
		if sameUpToRepeats(d.Ref, d.Cand) {
			c.RepeatedValues++

			return true
		}

		return false
	})

	return rep
}

// CompareAt holds production's rules got at node id to the reference
// through the client under view, and returns what is left once the
// allowed classes are taken out; capForm allows the class only capability
// form has. A node whose whole difference is headscale's reading
// ([Headscale]) is counted under the clauses that make it (see
// [attribute]).
func (c *Verdicts) CompareAt(ref *Ref, id types.NodeID, got []tailcfg.FilterRule, view ClientView, capForm bool) Report {
	var trial Verdicts

	rep := trial.judge(Compare(ref.Rules(id), got, view), ref, id, view, got, capForm)
	if !rep.Equivalent() {
		rests, classes := map[Contested]Report{}, map[Contested]Verdicts{}
		reproduces := func(k Contested) bool {
			var without Verdicts

			rest := without.judge(Compare(ref.Without(k).Rules(id), got, view), ref, id, view, got, capForm)
			rests[k], classes[k] = rest, without

			return rest.Equivalent()
		}

		if k, ok := attribute(reproduces); ok {
			c.addContested(k, len(rep.Verdicts)+len(rep.Caps))
			rep, trial = rests[k], classes[k]
		} else {
			rep.Inexact = inexact(reproduces)
		}
	}

	c.CrossFamilyICMP += trial.CrossFamilyICMP
	c.Hidden += trial.Hidden
	c.RepeatedValues += trial.RepeatedValues

	return rep
}

// sameUpToRepeats reports whether cand grants what ref does, in the same
// order, with some runs of values repeated whole: each capability's values
// in ref split into runs, cand each run one or more times over. A grant
// whose two destination entries both name the receiver repeats its whole
// list.
func sameUpToRepeats(ref, cand tailcfg.PeerCapMap) bool {
	if len(ref) != len(cand) {
		return false
	}

	for c, rv := range ref {
		cv, ok := cand[c]
		if !ok || !repeatsOf(c, rv, cv) {
			return false
		}
	}

	return true
}

// repeatsOf reports whether cand is ref split into runs, each repeated
// one or more times.
func repeatsOf(c peercap.Cap, ref, cand []tailcfg.RawMessage) bool {
	same := func(a, b tailcfg.RawMessage) bool {
		return SamePeerCaps(tailcfg.PeerCapMap{c: {a}}, tailcfg.PeerCapMap{c: {b}})
	}

	// done[i][j]: ref[i:] and cand[j:] match.
	done := make([][]bool, len(ref)+1)
	for i := range done {
		done[i] = make([]bool, len(cand)+1)
	}

	done[len(ref)][len(cand)] = true

	for i := range slices.Backward(ref) {
		for j := len(cand) - 1; j >= 0; j-- {
			for l := 1; i+l <= len(ref) && !done[i][j]; l++ {
				for k := j; k+l <= len(cand) && slices.EqualFunc(ref[i:i+l], cand[k:k+l], same); k += l {
					if done[i+l][k+l] {
						done[i][j] = true

						break
					}
				}
			}
		}
	}

	return done[0][0]
}

// ContestedPeers reports whether headscale's reading shows node id
// exactly got, and the clauses that make it (see [attribute]).
func ContestedPeers(ref *Ref, id types.NodeID, got []types.NodeID) (Contested, bool) {
	return attribute(func(k Contested) bool { return slices.Equal(got, ref.Without(k).Peers(id)) })
}

// ContestedRoutes reports whether headscale's reading gives viewer
// exactly got of peer's routes, both sorted, and the clauses that make it
// (see [attribute]).
func ContestedRoutes(ref *Ref, viewer, peer types.NodeID, got []netip.Prefix) (Contested, bool) {
	return attribute(func(k Contested) bool {
		want := ref.Without(k).Routes(viewer, peer)
		slices.SortFunc(want, netip.Prefix.Compare)

		return slices.Equal(got, want)
	})
}
