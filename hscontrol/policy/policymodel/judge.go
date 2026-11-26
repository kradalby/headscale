package policymodel

import (
	"fmt"
	"maps"
	"math/bits"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
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

	return fmt.Sprintf("allowed %d cross-family ICMP, %d on hidden addresses; contested %v",
		c.CrossFamilyICMP, c.Hidden, parts)
}

// judge holds rep, a comparison of the reference's rules with production's
// under view, to the allowed classes, and returns the differences left.
func (c *Verdicts) judge(rep Report, view ClientView, capForm bool) Report {
	if capForm {
		crossed, rest := rep.SplitCrossFamilyICMP()
		c.CrossFamilyICMP += crossed
		rep = rest
	}

	hidden, rest := rep.SplitHidden(view.Hidden)
	c.Hidden += hidden
	rep = rest

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

	rep := trial.judge(Compare(ref.Rules(id), got, view), view, capForm)
	if !rep.Equivalent() {
		rests, classes := map[Contested]Report{}, map[Contested]Verdicts{}
		reproduces := func(k Contested) bool {
			var without Verdicts

			rest := without.judge(Compare(ref.Without(k).Rules(id), got, view), view, capForm)
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

	return rep
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
