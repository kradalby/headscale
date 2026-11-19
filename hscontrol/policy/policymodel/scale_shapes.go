package policymodel

import (
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
)

// wide is how many nodes make a selector, a rule or a peer class wide:
// more than the tailnets drawn before large ones could hold.
const wide = 10

// scaleShapes are the shapes of size and structure: worlds the size real
// tailnets reach, fan-out through one selector, rule or class, and edit
// scripts that keep working on one node or one rule.
var scaleShapes = []Shape{
	{Name: "dozen-nodes", Why: "a tailnet of a dozen nodes or more", Min: 0.015, World: func(v *View) bool { return len(v.nodes) >= 12 }},
	{Name: "dozens-of-nodes", Why: "a tailnet of two dozen nodes or more", Min: 0.007, World: func(v *View) bool { return len(v.nodes) >= 24 }},
	{Name: "crowd-of-users", Why: "more users than any one token names", Min: 0.035, World: func(v *View) bool { return len(v.users) > len(defaultUsers) }},
	{Name: "wide-selector", Why: "many nodes behind one identity a rule names", Min: 0.01, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(slices.Concat(r.Src, dstSels(r)), func(s Sel) bool { return byOwner(s) && len(v.MembersOf(s)) >= wide })
		})
	}},
	{Name: "wide-rule", Why: "one rule received by many nodes", Min: 0.011, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool { return len(v.MembersOf(dstSels(r)...)) >= wide })
	}},
	{Name: "wide-class", Why: "many nodes one rule links both ways, one peer class", Min: 0.008, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			src, dst := v.MembersOf(r.Src...), v.MembersOf(dstSels(r)...)

			return len(src) >= wide && len(dst) >= wide &&
				len(slices.DeleteFunc(src, func(n Node) bool { return !slices.ContainsFunc(dst, func(m Node) bool { return m.ID == n.ID }) })) >= wide
		})
	}},
	{Name: "three-rules-one-key", Why: "three rules merging into one at a receiver", Min: 0.035, World: threeRulesOneKey},
	{Name: "long-policy", Why: "a dozen rules or more", Min: 0.008, World: func(v *View) bool {
		return len(v.World.Policy.ACLs)+len(v.World.Policy.Grants) >= 12
	}},
	{Name: "several-routers-and-exits", Why: "more than one subnet router and more than one exit node", Min: 0.015, World: func(v *View) bool {
		var routers, exits int

		for _, n := range v.nodes {
			if slices.ContainsFunc(served(n), func(r int) bool { return r < numRulePrefixes }) {
				routers++
			}

			if n.Exit() {
				exits++
			}
		}

		return routers >= 2 && exits >= 2
	}},
	{Name: "three-routers-of-one-route", Why: "an election among three routers", Min: 0.02, World: threeRouters},
	{Name: "node-with-several-tags", Why: "a node several tags own", Min: 0.065, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(n.Tags) >= 2 })
	}},
	{Name: "overlapping-groups", Why: "a user both groups hold, both named", Min: 0.05, World: func(v *View) bool {
		named := v.World.Policy.referenced().groups

		return named[0] && named[1] && slices.ContainsFunc(v.users, func(u User) bool {
			return inGroup(v, 0, u.ID) && inGroup(v, 1, u.ID)
		})
	}},
	{Name: "v6-only-pair-and-dual-stack", Why: "two IPv6-only nodes beside a dual-stack one", Min: 0.045, World: func(v *View) bool {
		var v6, dual int

		for _, n := range v.nodes {
			switch {
			case n.V4.IsValid() && n.V6.IsValid():
				dual++
			case n.V6.IsValid():
				v6++
			}
		}

		return v6 >= 2 && dual > 0
	}},
	{Name: "steps-in-a-dozen-nodes", Why: "edits committed in a tailnet of a dozen nodes or more", Min: 0.015, Step: func(b, _ *View, st Step) bool {
		return len(st.Edits) > 0 && len(b.nodes) >= 12
	}},
	{Name: "long-scenario", Why: "two dozen steps or more", Min: 0.011, Seq: func(_ []*View, steps []Step) bool { return len(steps) >= 24 }},
	{Name: "node-lifecycle", Why: "a node joins, a later step edits it and a later one deletes it", Min: 0.019, Seq: nodeLifecycle},
	{Name: "node-edited-in-three-steps", Why: "one node written by three steps", Min: 0.12, Seq: func(_ []*View, steps []Step) bool {
		return slices.ContainsFunc(stepsPerObject(steps, true), func(c int) bool { return c >= 3 })
	}},
	{Name: "rule-edited-twice", Why: "one rule edited in place by two steps", Min: 0.045, Seq: func(_ []*View, steps []Step) bool {
		return slices.ContainsFunc(stepsPerObject(steps, false), func(c int) bool { return c >= 2 })
	}},
}

func dstSels(r Rule) []Sel {
	out := make([]Sel, len(r.Dst))
	for i, d := range r.Dst {
		out[i] = d.Sel
	}

	return out
}

// byOwner reports whether s names nodes by who owns them.
func byOwner(s Sel) bool {
	return slices.Contains([]SelKind{SelUser, SelGroup, SelTag, SelMember, SelTagged}, s.Kind)
}

func inGroup(v *View, g int, user uint) bool {
	return slices.ContainsFunc(v.World.Policy.Groups[g], func(ref int) bool { return slices.Contains(v.RefUsers(ref), user) })
}

func threeRouters(v *View) bool {
	for r := range numRulePrefixes {
		if len(v.routersOf(r, nil)) >= 3 {
			return true
		}
	}

	return false
}

// threeRulesOneKey reports whether three rules, none a self rule, share
// sources and a protocol and reach one node.
func threeRulesOneKey(v *View) bool {
	p := v.World.Policy
	refs := p.Refs()

	for i, a := range refs {
		var same []RuleRef

		for _, b := range refs[i+1:] {
			if sameSourcesAndProtocol(p.Rule(a), a.Grant, p.Rule(b), b.Grant) {
				same = append(same, b)
			}
		}

		if len(same) < 2 {
			continue
		}

		for _, n := range v.nodes {
			reached := 0

			for _, ref := range append([]RuleRef{a}, same...) {
				if slices.ContainsFunc(p.Rule(ref).Dst, func(d Dest) bool { return v.names(d.Sel, n) }) {
					reached++
				}
			}

			if reached >= 3 {
				return true
			}
		}
	}

	return false
}

// nodeLifecycle reports whether a node joined, was written by a later
// step and deleted by a later one still.
func nodeLifecycle(_ []*View, steps []Step) bool {
	stage := map[types.NodeID]int{}

	for _, st := range steps {
		for _, e := range st.Edits {
			switch e := e.(type) {
			case Join:
				stage[e.Node.ID] = 1
			case Leave:
				if stage[e.ID] == 2 {
					return true
				}
			default:
				for _, id := range writtenNodes(e) {
					if stage[id] == 1 {
						stage[id] = 2
					}
				}
			}
		}
	}

	return false
}

// stepsPerObject counts, for each node (or each rule), the steps that
// wrote it: rules by place, which a rule added or removed in front moves,
// so counting stops at such a write.
func stepsPerObject(steps []Step, nodes bool) []int {
	count := map[any]int{}

	for _, st := range steps {
		seen := map[any]bool{}

		for _, e := range st.Edits {
			if !nodes {
				switch e.(type) {
				case AddRule, RemoveRule, SwapRules, AllowAll:
					clear(count)
				}
			}

			var keys []any

			if nodes {
				for _, id := range writtenNodes(e) {
					keys = append(keys, id)
				}
			} else if ref, ok := editedRule(e); ok {
				keys = append(keys, ref)
			}

			for _, k := range keys {
				if !seen[k] {
					seen[k] = true
					count[k]++
				}
			}
		}
	}

	out := make([]int, 0, len(count))
	for _, c := range count {
		out = append(out, c)
	}

	return out
}

// writtenNodes is the existing nodes e writes.
func writtenNodes(e Edit) []types.NodeID {
	switch e := e.(type) {
	case Leave:
		return []types.NodeID{e.ID}
	case Retag:
		return []types.NodeID{e.ID}
	case SetAddr:
		return []types.NodeID{e.ID}
	case SwapAddrs:
		return []types.NodeID{e.A, e.B}
	case Announce:
		return []types.NodeID{e.ID}
	case Withdraw:
		return []types.NodeID{e.ID}
	case Approve:
		return []types.NodeID{e.ID}
	case Unapprove:
		return []types.NodeID{e.ID}
	case SetClient:
		return []types.NodeID{e.ID}
	case SetExpired:
		return []types.NodeID{e.ID}
	case SetOnline:
		return []types.NodeID{e.ID}
	}

	return nil
}

// editedRule is the rule e edits in place.
func editedRule(e Edit) (RuleRef, bool) {
	switch e := e.(type) {
	case SetSel:
		return e.Rule, true
	case SetPorts:
		return e.Rule, true
	case SetProto:
		return e.Rule, true
	case SetIP:
		return e.Rule, true
	case SetApp:
		return e.Rule, true
	case SetVia:
		return e.Rule, true
	case AddSel:
		return e.Rule, true
	case RemoveSel:
		return e.Rule, true
	}

	return RuleRef{}, false
}
