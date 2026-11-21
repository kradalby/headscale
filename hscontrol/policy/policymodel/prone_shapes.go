package policymodel

import (
	"fmt"
	"slices"
	"strings"

	"tailscale.com/tailcfg"
)

// proneShapes are the neighbourhoods findings came from (see prone.go):
// via grants to autogroup:internet at exit nodes and public routes, routes
// announced unapproved inside a destination, several contested clauses at
// one node, and nodes moving onto an identity that auto-approves a route
// they announce. Their floors sit five standard deviations under what the
// coverage sample holds, as a count drawn afresh would.
var proneShapes = []Shape{
	{Name: "via-exit-router-among-sources", Why: "a via exit node among the sources of its grant to autogroup:internet", Min: 0.025, World: func(v *View) bool {
		return len(v.viaExitSources()) > 0
	}},
	{Name: "via-exit-source-public-peer", Why: "such a router beside another node serving a public subnet route", Min: 0.025, World: func(v *View) bool {
		return slices.ContainsFunc(v.viaExitSources(), func(r Node) bool {
			return v.anyNode(func(n Node) bool { return n.ID != r.ID && slices.ContainsFunc(served(n), publicRoute) })
		})
	}},
	{Name: "public-route-mixed-tag-routers", Why: "a public route served by a via router of a grant and by a node without its tags", Min: 0.01, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			if len(r.Via) == 0 {
				return false
			}

			for route := range numRulePrefixes {
				if routers := v.routersOf(route, nil); publicRoute(route) && len(routers) > 1 &&
					slices.ContainsFunc(routers, func(n Node) bool { return carries(n, r.Via) }) &&
					slices.ContainsFunc(routers, func(n Node) bool { return !carries(n, r.Via) }) {
					return true
				}
			}

			return false
		})
	}},
	{Name: "via-exit-one-family", Why: "a via exit node of one family under a grant to autogroup:internet", Min: 0.025, World: func(v *View) bool {
		return slices.ContainsFunc(v.viaExits(), oneFamily)
	}},
	{Name: "via-exit-public-other-family", Why: "a via exit node of one family serving a public route of the other", Min: 0.008, World: func(v *View) bool {
		return slices.ContainsFunc(v.viaExits(), func(n Node) bool {
			return oneFamily(n) && slices.ContainsFunc(served(n), func(r int) bool {
				return publicRoute(r) && Prefixes[r].Addr().Is4() != slices.Contains(served(n), exit4)
			})
		})
	}},
	{Name: "via-router-unavailable", Why: "a via router offline or expired", Min: 0.02, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return len(r.Via) > 0 && v.anyNode(func(n Node) bool { return (n.Offline || n.Expired) && v.viaRouterOf(r, n) })
		})
	}},
	{Name: "unapproved-inside-via-destination", Why: "a via router announcing unapproved a route inside a destination it routes part of", Min: 0.015, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return len(r.Via) > 0 && slices.ContainsFunc(r.Dst, func(d Dest) bool {
				return v.anyNode(func(n Node) bool { return carries(n, r.Via) && unapprovedInside(v, d.Sel, n) })
			})
		})
	}},
	{Name: "unapproved-inside-destination-at-exit", Why: "an exit node announcing unapproved a route inside a destination it routes part of", Min: 0.015, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.Dst, func(d Dest) bool {
				return v.anyNode(func(n Node) bool { return n.Exit() && unapprovedInside(v, d.Sel, n) })
			})
		})
	}},
	{Name: "via-route-over-node", Why: "a via router's route holding another node's address", Min: 0.015, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return len(r.Via) > 0 && v.anyNode(func(n Node) bool {
				return v.viaRouterOf(r, n) && slices.ContainsFunc(served(n), func(rt int) bool {
					return rt < numRulePrefixes && v.anyNode(func(m Node) bool { return m.ID != n.ID && slices.ContainsFunc(m.Addrs(), Prefixes[rt].Contains) })
				})
			})
		})
	}},
	{Name: "three-clauses-at-a-node", Why: "three contested clauses each deciding one node's rules", Min: 0.01, World: threeClauses},
	{Name: "retag-onto-approver", Why: "a retag onto a tag that auto-approves a route the node announces", Min: 0.01, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[Retag](st), func(e Retag) bool {
			return len(e.Tags) > 0 && nodeMoved(b, a, e.ID, func(was, is Node) bool { return len(dropRoutes(is.Approved, was.Approved)) > 0 })
		})
	}},
	{Name: "login-onto-approver", Why: "a tagged node logging in as a user who auto-approves a route it announces", Min: 0.008, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[Retag](st), func(e Retag) bool {
			return len(e.Tags) == 0 && nodeMoved(b, a, e.ID, func(was, is Node) bool {
				return was.Tagged() && slices.ContainsFunc(dropRoutes(is.Announced, is.Approved), func(r int) bool { return a.Approvable(is, r) })
			})
		})
	}},
	{Name: "approvers-moved-under-announced", Why: "the auto-approvers come to approve a route a node announces, which nothing approves yet", Min: 0.01, Step: func(b, a *View, st Step) bool {
		return len(edits[SetAutoApprovers](st)) > 0 && a.anyNode(func(n Node) bool {
			return slices.ContainsFunc(dropRoutes(n.Announced, n.Approved), func(r int) bool {
				was, ok := b.World.Topology.Node(n.ID)

				return ok && !b.Approvable(was, r) && a.Approvable(n, r)
			})
		})
	}},
	{Name: "approved-after-approvers-moved", Why: "a route approved by a later write once the auto-approvers moved under it", Min: 0.009, Seq: approvedAfterApproversMoved},
}

func publicRoute(r int) bool { return r < numRulePrefixes && public(Prefixes[r]) }

func carries(n Node, tags []int) bool {
	return slices.ContainsFunc(tags, func(t int) bool { return slices.Contains(n.Tags, t) })
}

func oneFamily(n Node) bool {
	return len(slices.DeleteFunc(served(n), func(r int) bool { return r < exit4 })) == 1
}

// viaExits are the exit nodes carrying a via tag of a grant to
// autogroup:internet.
func (v *View) viaExits() []Node {
	var out []Node

	for _, n := range v.nodes {
		if n.Exit() && slices.ContainsFunc(v.World.Policy.Grants, func(r Rule) bool { return internetVia(r) && carries(n, r.Via) }) {
			out = append(out, n)
		}
	}

	return out
}

// viaExitSources are the via exit nodes among their grant's sources.
func (v *View) viaExitSources() []Node {
	var out []Node

	for _, n := range v.nodes {
		if n.Exit() && slices.ContainsFunc(v.World.Policy.Grants, func(r Rule) bool {
			return internetVia(r) && carries(n, r.Via) && slices.ContainsFunc(v.MembersOf(r.Src...), func(m Node) bool { return m.ID == n.ID })
		}) {
			out = append(out, n)
		}
	}

	return out
}

func internetVia(r Rule) bool {
	return len(r.Via) > 0 && slices.ContainsFunc(r.Dst, func(d Dest) bool { return d.Sel.Kind == SelInternet })
}

// viaRouterOf reports whether n is one of via rule r's routers: it carries
// a via tag and serves a route a destination prefix overlaps, or an exit
// route under autogroup:internet.
func (v *View) viaRouterOf(r Rule, n Node) bool {
	if !carries(n, r.Via) {
		return false
	}

	if n.Exit() && internetVia(r) {
		return true
	}

	return slices.ContainsFunc(r.Dst, func(d Dest) bool {
		return (d.Sel.Kind == SelPrefix || d.Sel.Kind == SelHost) && slices.ContainsFunc(served(n), func(rt int) bool {
			return rt < numRulePrefixes && Prefixes[rt].Overlaps(v.selPrefix(d.Sel))
		})
	})
}

// unapprovedInside reports whether n serves a subnet route overlapping
// destination d and announces unapproved a route inside it.
func unapprovedInside(v *View, d Sel, n Node) bool {
	if d.Kind != SelPrefix && d.Kind != SelHost {
		return false
	}

	p := v.selPrefix(d)

	return slices.ContainsFunc(served(n), func(r int) bool { return r < numRulePrefixes && Prefixes[r].Overlaps(p) }) &&
		slices.ContainsFunc(dropRoutes(n.Announced, n.Approved), func(r int) bool {
			return r < numRulePrefixes && p.Bits() <= Prefixes[r].Bits() && p.Contains(Prefixes[r].Addr())
		})
}

// threeClauses reports whether three contested clauses each, left out of
// the reference alone, change the rules it gives one node. Only clauses
// the policy can bring into play are read, and three must be: reading the
// document and leaving a clause out build the reference again.
func threeClauses(v *View) bool {
	ks := inPlay(v.World.Policy)
	if len(ks) < 3 {
		return false
	}

	ref := RefOf(v.World)
	if ref.OutOfDomain() != "" {
		return false
	}

	withouts := make([]*Ref, len(ks))
	for i, k := range ks {
		withouts[i] = ref.Without(k)
	}

	for _, n := range ref.nodes {
		rules, decides := ruleText(ref.Rules(n.ID)), 0

		for i, o := range withouts {
			if ruleText(o.Rules(n.ID)) != rules {
				decides++
			}

			if decides == 3 {
				return true
			}

			if decides+len(withouts)-i-1 < 3 {
				break
			}
		}
	}

	return false
}

// inPlay are the contested clauses that can change a node's rules under
// p: those whose kind of rule p holds.
func inPlay(p Policy) []Contested {
	rules := slices.Concat(p.ACLs, p.Grants)
	has := func(f func(Rule) bool) bool { return slices.ContainsFunc(rules, f) }
	dst := func(r Rule, k SelKind) bool {
		return slices.ContainsFunc(r.Dst, func(d Dest) bool { return d.Sel.Kind == k })
	}
	via := has(func(r Rule) bool { return len(r.Via) > 0 })

	in := map[Contested]bool{
		OthersSelf:              has(func(r Rule) bool { return dst(r, SelSelf) }),
		StarApprovedRoutes:      has(func(r Rule) bool { return slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelAll }) }),
		InternetAtSubnetRouters: has(func(r Rule) bool { return len(r.Via) == 0 && dst(r, SelInternet) }),
		AppWildcard:             has(func(r Rule) bool { return len(r.App) > 0 && dst(r, SelAll) }),
		ViaOwnAddress:           via,
		ViaReach:                via,
		ViaSelf:                 has(func(r Rule) bool { return len(r.Via) > 0 && dst(r, SelSelf) }),
		ViaExitInternet:         has(func(r Rule) bool { return len(r.Via) > 0 && dst(r, SelInternet) }),
	}

	var out []Contested

	for _, k := range ContestedClauses {
		if in[k] {
			out = append(out, k)
		}
	}

	return out
}

// ruleText is rules written out in a sorted order, which two readings
// that split or order one rule otherwise share.
func ruleText(rules []tailcfg.FilterRule) string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = fmt.Sprint(r)
	}

	slices.Sort(out)

	return strings.Join(out, "\n")
}

// approvedAfterApproversMoved reports whether a step's auto-approvers
// came to approve a route a node announced unapproved, and a later step
// approved it.
func approvedAfterApproversMoved(vs []*View, steps []Step) bool {
	for i, st := range steps {
		if len(edits[SetAutoApprovers](st)) == 0 {
			continue
		}

		for _, n := range vs[i+1].nodes {
			for _, r := range dropRoutes(n.Announced, n.Approved) {
				was, ok := vs[i].World.Topology.Node(n.ID)
				if !ok || vs[i].Approvable(was, r) || !vs[i+1].Approvable(n, r) {
					continue
				}

				for j := i + 2; j < len(vs); j++ {
					if later, ok := vs[j].World.Topology.Node(n.ID); ok && slices.Contains(later.AutoApproved, r) {
						return true
					}
				}
			}
		}
	}

	return false
}
