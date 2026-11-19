package policymodel

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// Verdicts are the differences from the reference a property allows when
// it holds the rules a node is served to the reference's rules for it,
// each counted; anything else fails it. Every property judging served
// rules shares them, so that one allowance means one thing wherever the
// rules come from.
type Verdicts struct {
	// Unrouted: the client takes packets for a route its node announces
	// but is not approved for, through a rule whose destination is "*";
	// the captures show exactly that.
	Unrouted int
	// UnroutedWhole: the same through any other destination entry that
	// also names something the node serves, written whole. No capture
	// holds one; reported as a question, not encoded.
	UnroutedWhole int
	// CrossFamilyICMP: capability form refuses a packet carrying the
	// other family's ICMP protocol, which address form accepts: decided as
	// malformed, failing closed.
	CrossFamilyICMP int
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

// ContestedSets are the sets of contested clauses a difference is tried
// against, in order: each alone, each pair, then all of them.
var ContestedSets = func() []Contested {
	cs := ContestedClauses
	out := slices.Clone(cs)

	var all Contested

	for i, a := range cs {
		all |= a

		for _, b := range cs[i+1:] {
			out = append(out, a|b)
		}
	}

	return append(out, all)
}()

func (c *Verdicts) String() string {
	var parts []string

	for _, k := range ContestedSets {
		if c.Contested[k] > 0 {
			open := ""
			if k.FailsOpen() {
				open = ", fails open"
			}

			parts = append(parts, fmt.Sprintf("%d %s%s", c.Contested[k], k, open))
		}
	}

	return fmt.Sprintf("allowed %d cross-family ICMP, %d through * on unapproved routes; suspected: %d through other whole destinations on unapproved routes, %d app values repeated; contested %v",
		c.CrossFamilyICMP, c.Unrouted, c.UnroutedWhole, c.RepeatedValues, parts)
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

	var star, whole func(Probe) bool

	rep.Verdicts = slices.DeleteFunc(rep.Verdicts, func(d VerdictDiff) bool {
		if d.Ref != filter.Drop || d.Cand != filter.Accept || ref.Serves(id, d.Probe.Dst) || !view.LocalNets.Contains(d.Probe.Dst) {
			return false
		}

		if star == nil {
			star, whole = StarAccepts(got, view), wholeAccepts(got, view, ref.Served(id))
		}

		switch {
		case star(d.Probe):
			c.Unrouted++
		case whole(d.Probe):
			// TODO(kradalby): policy/unrouted-whole-destination: fails
			// open, narrow. A destination entry that reaches the node is
			// written whole, so the client also accepts the rest of it
			// inside a route the node announces unapproved: host h-pub
			// 100.64.0.0/30, `* -> h-pub:*`, n1 on 100.64.0.1 announcing
			// 100.64.0.0/30 unapproved accepts packets to 100.64.0.0.
			// Nobody routes those to n1. The captures show this only
			// through *, which the case above accepts; none decides any
			// other entry. Production: dstPorts in expand.go keeps a
			// literal entry whole once receiver.overlaps finds it
			// reaching the node. Delete this case once entries are cut to
			// what the node serves, or once a capture shows the hosted
			// service doing it.
			c.UnroutedWhole++
		default:
			return false
		}

		return true
	})

	return rep
}

// CompareAt holds production's rules got at node id to the reference
// through the client under view, and returns what is left once the
// allowed classes are taken out; capForm allows the class only capability
// form has. A node whose whole difference is the reference less some
// contested clauses is counted under those clauses.
func (c *Verdicts) CompareAt(ref *Ref, id types.NodeID, got []tailcfg.FilterRule, view ClientView, capForm bool) Report {
	var trial Verdicts

	rep := trial.judge(Compare(ref.Rules(id), got, view), ref, id, view, got, capForm)
	if !rep.Equivalent() {
		for _, k := range ContestedSets {
			var without Verdicts

			rest := without.judge(Compare(ref.Without(k).Rules(id), got, view), ref, id, view, got, capForm)
			if rest.Equivalent() {
				c.addContested(k, len(rep.Verdicts)+len(rep.Caps))
				rep, trial = rest, without

				break
			}
		}
	}

	c.Unrouted += trial.Unrouted
	c.UnroutedWhole += trial.UnroutedWhole
	c.CrossFamilyICMP += trial.CrossFamilyICMP
	c.RepeatedValues += trial.RepeatedValues

	return rep
}

// sameUpToRepeats reports whether cand grants what ref does, in the same
// order, with some values repeated more often: the same runs of equal
// values, none shorter.
func sameUpToRepeats(ref, cand tailcfg.PeerCapMap) bool {
	if len(ref) != len(cand) {
		return false
	}

	type run struct {
		v tailcfg.RawMessage
		n int
	}

	runs := func(c peercap.Cap, vs []tailcfg.RawMessage) []run {
		var out []run

		for _, v := range vs {
			if len(out) > 0 && SamePeerCaps(tailcfg.PeerCapMap{c: {out[len(out)-1].v}}, tailcfg.PeerCapMap{c: {v}}) {
				out[len(out)-1].n++

				continue
			}

			out = append(out, run{v: v, n: 1})
		}

		return out
	}

	for c, rv := range ref {
		cv, ok := cand[c]
		if !ok {
			return false
		}

		rr, cr := runs(c, rv), runs(c, cv)
		if len(rr) != len(cr) {
			return false
		}

		for i := range rr {
			if cr[i].n < rr[i].n || !SamePeerCaps(tailcfg.PeerCapMap{c: {rr[i].v}}, tailcfg.PeerCapMap{c: {cr[i].v}}) {
				return false
			}
		}
	}

	return true
}

// acceptsThrough returns whether rules accept a probe through a
// destination entry keep admits, as the client would with view.
func acceptsThrough(rules []tailcfg.FilterRule, view ClientView, keep func(tailcfg.NetPortRange) bool) func(Probe) bool {
	var kept []tailcfg.FilterRule

	for _, r := range rules {
		var dsts []tailcfg.NetPortRange

		for _, d := range r.DstPorts {
			if keep(d) {
				dsts = append(dsts, d)
			}
		}

		if len(dsts) > 0 {
			r.DstPorts, r.CapGrant = dsts, nil
			kept = append(kept, r)
		}
	}

	ms, err := filter.MatchesFromFilterRules(kept)
	if err != nil || len(ms) == 0 {
		return func(Probe) bool { return false }
	}

	f := filter.New(ms, view.HasCap, view.LocalNets, nil, nil, logger.Discard)

	return func(p Probe) bool { return f.RunIn(p.Packet(), 0) == filter.Accept }
}

// StarAccepts returns whether rules accept a probe through a destination
// written "*". That is the one way the captures show a node taking packets
// for a route it announces but is not approved for: every such captured
// accept comes from such a rule.
func StarAccepts(rules []tailcfg.FilterRule, view ClientView) func(Probe) bool {
	return acceptsThrough(rules, view, func(d tailcfg.NetPortRange) bool { return d.IP == "*" })
}

// wholeAccepts returns whether rules accept a probe through a destination
// entry that also names something the node serves (served): a rule that
// reaches the node, written whole. "*" is one; the captures hold no other.
func wholeAccepts(rules []tailcfg.FilterRule, view ClientView, served *netipx.IPSet) func(Probe) bool {
	return acceptsThrough(rules, view, func(d tailcfg.NetPortRange) bool {
		if d.IP == "*" {
			return true
		}

		r, err := netipx.ParseIPRange(d.IP)
		if err != nil {
			p, perr := netip.ParsePrefix(d.IP)
			if perr != nil {
				a, aerr := netip.ParseAddr(d.IP)
				if aerr != nil {
					return false
				}

				p = netip.PrefixFrom(a, a.BitLen())
			}

			r = netipx.RangeOfPrefix(p)
		}

		return served.OverlapsRange(r)
	})
}

// ContestedPeers reports which contested clauses, left out of the
// reference, show node id exactly got.
func ContestedPeers(ref *Ref, id types.NodeID, got []types.NodeID) (Contested, bool) {
	for _, k := range ContestedSets {
		if slices.Equal(got, ref.Without(k).Peers(id)) {
			return k, true
		}
	}

	return 0, false
}

// ContestedRoutes reports which contested clauses, left out of the
// reference, give viewer exactly got of peer's routes, both sorted.
func ContestedRoutes(ref *Ref, viewer, peer types.NodeID, got []netip.Prefix) (Contested, bool) {
	for _, k := range ContestedSets {
		want := ref.Without(k).Routes(viewer, peer)
		slices.SortFunc(want, netip.Prefix.Compare)

		if slices.Equal(got, want) {
			return k, true
		}
	}

	return 0, false
}

// MergesApart reports whether w has a self destination and a user whose
// nodes' addresses sort otherwise as text than as addresses.
//
// TODO(kradalby): policy/merge-order: the compile writes a self rule's
// sources in address order and every other rule's as text, and merges
// rules only on equal text, so the filter audit takes two forms that
// merged one source set's rules apart for a disagreement (see
// TestServedAuditAgreesWhateverTheMergeOrder in state). Drop this when
// that test runs unskipped.
func MergesApart(w World) bool {
	if !SelfDestination(w.Policy) {
		return false
	}

	byUser := map[uint][]netip.Addr{}

	for _, n := range w.Topology.Nodes {
		if len(n.Tags) == 0 {
			byUser[n.User] = append(byUser[n.User], n.Addrs()...)
		}
	}

	return slices.ContainsFunc(slices.Collect(maps.Values(byUser)), SortsApart)
}

// SelfDestination reports whether a rule of p has autogroup:self among its
// destinations.
func SelfDestination(p Policy) bool {
	self := func(d Dest) bool { return d.Sel.Kind == SelSelf }

	return slices.ContainsFunc(slices.Concat(p.ACLs, p.Grants), func(r Rule) bool { return slices.ContainsFunc(r.Dst, self) })
}

// SortsApart reports whether addrs sort otherwise as text than as
// addresses: one user's, the merge order's other half.
func SortsApart(addrs []netip.Addr) bool {
	text := slices.SortedFunc(slices.Values(addrs), func(a, b netip.Addr) int { return strings.Compare(a.String(), b.String()) })

	return !slices.IsSortedFunc(text, netip.Addr.Compare)
}
