package policymodel

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
)

// formReach is what the capability-form properties can judge in one
// drawn scenario, read as the reference properties read it: every node at
// the start, the step's readers after each step. reads counts reads by
// [View.AddressFormReason], capReads those [Ref.CapSources] requires a
// capability at; shapes names what the scenario holds.
type formReach struct {
	reads    map[string]int
	capReads int
	shapes   map[string]bool
}

// reachOf measures s.
func reachOf(s Scenario) formReach {
	fr := formReach{reads: map[string]int{}, shapes: map[string]bool{}}
	worlds := s.Worlds()
	last := map[types.NodeID]string{}
	lastRules := map[types.NodeID]map[RuleRef]string{}

	for i, w := range worlds {
		v, ref := NewView(w), RefOf(w)

		var reads []types.NodeID

		if i == 0 {
			for _, n := range w.Topology.Nodes {
				reads = append(reads, n.ID)
			}
		} else {
			reads = s.Steps[i-1].Reads
		}

		for _, id := range reads {
			if n, ok := w.Topology.Node(id); ok {
				fr.read(v, ref, n, last, lastRules)
			}
		}

		fr.world(v)
	}

	for i, st := range s.Steps {
		cur := worlds[i]

		for _, e := range st.Edits {
			if a, ok := e.(SetApp); ok && valuesPastFirst(cur.Policy.Rule(a.Rule).App, a.App) {
				fr.shapes["app-values-past-first"] = true
			}

			cur = cur.Apply(e)
		}
	}

	return fr
}

// read measures a read of n, last and lastRules being what n's earlier
// reads found: its fallback, and the kind of each rule naming it.
func (fr *formReach) read(v *View, ref *Ref, n Node, last map[types.NodeID]string, lastRules map[types.NodeID]map[RuleRef]string) {
	why := v.AddressFormReason(n)
	fr.reads[why]++

	if was, seen := last[n.ID]; seen && was != why && was == "" {
		fr.shapes["flip-into-"+why] = true
	} else if seen && was != why && why == "" {
		fr.shapes["flip-out-of-"+was] = true
	}

	last[n.ID] = why

	if why != "" {
		delete(lastRules, n.ID)

		return
	}

	rules := v.ruleKindsAt(n)
	for r, kind := range rules {
		if was, ok := lastRules[n.ID][r]; ok && was != kind && was == "" {
			fr.shapes["rule-gains-"+kind] = true
		} else if ok && was != kind && kind == "" {
			fr.shapes["rule-loses-"+was] = true
		}
	}

	lastRules[n.ID] = rules

	if ref.OutOfDomain() != "" {
		return
	}

	caps := ref.CapSources(n.ID)
	if len(caps) == 0 {
		return
	}

	fr.capReads++
	fr.shapes["cap-read"] = true

	if slices.ContainsFunc(caps, func(c string) bool { return strings.HasPrefix(c, "owner:") }) {
		fr.shapes["cap-read-self"] = true
	}

	for _, r := range v.rulesAt(n) {
		ids, lits := 0, 0

		for _, s := range r.Src {
			switch {
			case !identityKind(s.Kind):
				lits++
			case len(v.addressed(s)) == 0:
				fr.shapes["cap-read-identity-naming-nobody"] = true
				ids++
			default:
				ids++
			}
		}

		if ids > 0 && lits > 0 {
			fr.shapes["cap-read-mixed"] = true
		}

		if ids > 1 {
			fr.shapes["cap-read-several-identities"] = true
		}
	}
}

// world measures what v's world holds whoever reads.
func (fr *formReach) world(v *View) {
	w := v.World

	for _, r := range slices.Concat(w.Policy.ACLs, w.Policy.Grants) {
		if len(r.App) > 1 {
			fr.shapes["app-capabilities"] = true
		}

		if slices.ContainsFunc(r.App, func(a App) bool { return a.Value >= appSingles }) {
			fr.shapes["app-values"] = true
		}

		if slices.ContainsFunc(slices.Concat(r.Src, r.dstSels()), func(s Sel) bool {
			return (s.Kind == SelPrefix || s.Kind == SelHost) && v.selPrefix(s) == Prefixes[publicPrefix6]
		}) {
			fr.shapes["public-ipv6-rule"] = true
		}
	}
}

// valuesPastFirst reports whether b grants a's capabilities with, for one
// of them, as many values and the same first, differing after it.
func valuesPastFirst(a, b []App) bool {
	if len(a) != len(b) {
		return false
	}

	differ := false

	for i := range a {
		va, vb := AppValues[a[i].Value], AppValues[b[i].Value]

		switch {
		case a[i].Cap != b[i].Cap:
			return false
		case len(va) == len(vb) && va[0] == vb[0] && !slices.Equal(va, vb):
			differ = true
		}
	}

	return differ
}

func (r Rule) dstSels() []Sel {
	out := make([]Sel, len(r.Dst))
	for i, d := range r.Dst {
		out[i] = d.Sel
	}

	return out
}

func identityKind(k SelKind) bool {
	return k == SelUser || k == SelGroup || k == SelTag || k == SelMember || k == SelTagged
}

// addressed is the members of s holding an address.
func (v *View) addressed(s Sel) []Node {
	return slices.DeleteFunc(v.MembersOf(s), func(n Node) bool { return len(n.Addrs()) == 0 })
}

// rulesAt is the rules whose destinations name n, by identity or address.
func (v *View) rulesAt(n Node) []Rule {
	var out []Rule

	for _, ref := range v.World.Policy.Refs() {
		r := v.World.Policy.Rule(ref)
		if slices.ContainsFunc(r.Dst, func(d Dest) bool { return v.names(d.Sel, n) || d.Sel.Kind == SelSelf && !n.Tagged() }) {
			out = append(out, r)
		}
	}

	return out
}

// ruleKindsAt is, for each rule naming n, whether it goes as addresses by
// its own kind: "cap-grant", "portless", or "" for neither.
func (v *View) ruleKindsAt(n Node) map[RuleRef]string {
	out := map[RuleRef]string{}

	for _, ref := range v.World.Policy.Refs() {
		r := v.World.Policy.Rule(ref)
		if !slices.ContainsFunc(r.Dst, func(d Dest) bool { return v.names(d.Sel, n) }) {
			continue
		}

		switch {
		case len(r.App) > 0:
			out[ref] = "cap-grant"
		case hasProto(r, ref.Grant, "gre"):
			out[ref] = "portless"
		default:
			out[ref] = ""
		}
	}

	return out
}

// capFormFloors are the least count of drawn scenarios, of
// coverageSamples, holding each shape [reachOf] names: about half of what
// the generators reach, as in TestCoverage.
var capFormFloors = map[string]int{
	"cap-read": 200, "cap-read-self": 90, "cap-read-mixed": 50, "cap-read-several-identities": 100,
	"cap-read-identity-naming-nobody": 100,
	"flip-into-routes":                130, "flip-out-of-routes": 70, "flip-into-client": 55, "flip-out-of-client": 30,
	"flip-into-app-connector": 25, "flip-out-of-app-connector": 25, "flip-into-service-host": 25, "flip-out-of-service-host": 25,
	"rule-gains-cap-grant": 35, "rule-loses-cap-grant": 35, "rule-gains-portless": 15, "rule-loses-portless": 15,
	"app-values": 100, "app-capabilities": 45, "app-values-past-first": 20, "public-ipv6-rule": 25,
}

// capFormReadShare is the least share of reads at which a capability is
// required, about half of what the generators reach.
const capFormReadShare = 0.09

// TestCapFormCoverage measures what the capability-form properties can
// judge over drawn scenarios, and fails below each floor: reads requiring
// a capability and the kinds of rule they read, receivers flipping into
// and out of each fallback and rules into and out of address form at a
// receiver sent capabilities, app capabilities of several values and
// keys, public IPv6 in rules. Run with -v for the table.
func TestCapFormCoverage(t *testing.T) {
	t.Parallel()

	reads, scenarios := map[string]int{}, map[string]int{}
	total, capReads := 0, 0
	gen := Scenarios(coverageSteps)

	for i := range coverageSamples {
		fr := reachOf(gen.Example(i))

		for k, n := range fr.reads {
			reads[k] += n
			total += n
		}

		capReads += fr.capReads

		for k := range fr.shapes {
			scenarios[k]++
		}
	}

	share := float64(capReads) / float64(max(1, total))

	var table strings.Builder

	fmt.Fprintf(&table, "reads %d by why their receiver must be sent addresses %v; requiring a capability %d (%.2f, floor %.2f)\n", total, reads, capReads, share, capFormReadShare)

	for _, k := range slices.Sorted(maps.Keys(capFormFloors)) {
		fmt.Fprintf(&table, "%-34s %5d %5d\n", k, scenarios[k], capFormFloors[k])

		if scenarios[k] < capFormFloors[k] {
			t.Errorf("%s in %d of %d scenarios, floor %d", k, scenarios[k], coverageSamples, capFormFloors[k])
		}
	}

	if share < capFormReadShare {
		t.Errorf("a capability is required at %.2f of reads, floor %.2f", share, capFormReadShare)
	}

	t.Logf("capability form over %d scenarios:\n%s", coverageSamples, table.String())
}
