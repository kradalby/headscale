package policymodel

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
)

// Shape is a named shape a case can contain, computed from the case
// itself and meaning exactly what its name says of the plan. A shape only
// headscale can count (where a merged rule lands, which routers' cover
// moved) is counted in policy/v2 from headscale's own counters, not here.
// A shape is one of three kinds: World holds of some world of the
// scenario, Step of some step (with the worlds either side of it), Seq of
// the whole sequence.
type Shape struct {
	Name string
	// Why is what the shape exercises.
	Why string
	// Min is the least share of drawn scenarios, at the step count
	// builders run, that must contain the shape.
	Min float64

	World func(v *View) bool
	Step  func(before, after *View, st Step) bool
	Seq   func(vs []*View, steps []Step) bool
}

// Classify returns the names of the shapes s contains, in table order.
func Classify(s Scenario, shapes []Shape) []string {
	vs := make([]*View, 0, len(s.Steps)+1)
	for _, w := range s.Worlds() {
		vs = append(vs, NewView(w))
	}

	var out []string

	for _, sh := range shapes {
		if sh.contains(vs, s.Steps) {
			out = append(out, sh.Name)
		}
	}

	return out
}

func (sh Shape) contains(vs []*View, steps []Step) bool {
	switch {
	case sh.World != nil:
		return slices.ContainsFunc(vs, sh.World)
	case sh.Step != nil:
		for i, st := range steps {
			if sh.Step(vs[i], vs[i+1], st) {
				return true
			}
		}

		return false
	case sh.Seq != nil:
		return sh.Seq(vs, steps)
	}

	return false
}

// served is n's announced and approved routes.
func served(n Node) []int {
	var out []int

	for _, r := range n.Approved {
		if slices.Contains(n.Announced, r) {
			out = append(out, r)
		}
	}

	return out
}

func (v *View) anyRule(f func(r Rule, grant bool) bool) bool {
	for _, ref := range v.World.Policy.Refs() {
		if f(v.World.Policy.Rule(ref), ref.Grant) {
			return true
		}
	}

	return false
}

func (v *View) anyNode(f func(Node) bool) bool { return slices.ContainsFunc(v.nodes, f) }

func (v *View) exitPresent() bool { return v.anyNode(Node.Exit) }

func (v *View) sharedAddr() bool {
	return v.anyNode(func(n Node) bool {
		return slices.ContainsFunc(n.Addrs(), func(a netip.Addr) bool { return v.heldByOther(n, a) })
	})
}

func (v *View) outsideAddr() bool {
	return v.anyNode(func(n Node) bool { return slices.ContainsFunc(n.Addrs(), Outside) })
}

// heldByOther reports whether a node other than n holds a.
func (v *View) heldByOther(n Node, a netip.Addr) bool {
	return a.IsValid() && v.anyNode(func(m Node) bool { return m.ID != n.ID && slices.Contains(m.Addrs(), a) })
}

// protos is the protocols of the filter rules r compiles to: an ACL's
// one, a grant's one per ip entry.
func protos(r Rule, grant bool) []int {
	if !grant {
		return []int{r.Proto}
	}

	out := make([]int, len(r.IP))
	for i, ip := range r.IP {
		out[i] = ip.Proto
	}

	return out
}

// sameSourcesAndProtocol reports whether a and b, neither a self rule,
// name the same sources and share a protocol: their filter rules have one
// merge key wherever both reach a node.
func sameSourcesAndProtocol(a Rule, ag bool, b Rule, bg bool) bool {
	return !a.selfRule() && !b.selfRule() && slices.Equal(a.Src, b.Src) &&
		slices.ContainsFunc(protos(a, ag), func(p int) bool { return slices.Contains(protos(b, bg), p) })
}

func hasProto(r Rule, grant bool, names ...string) bool {
	return slices.ContainsFunc(protos(r, grant), func(p int) bool { return slices.Contains(names, Protos[p]) })
}

func hasPorts(r Rule, grant bool, names ...string) bool {
	if grant {
		return slices.ContainsFunc(r.IP, func(ip IP) bool { return slices.Contains(names, Ports[ip.Ports]) })
	}

	return slices.ContainsFunc(r.Dst, func(d Dest) bool { return slices.Contains(names, Ports[d.Ports]) })
}

var private = func() *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
		b.AddPrefix(netip.MustParsePrefix(p))
	}

	s, _ := b.IPSet()

	return s
}()

// public reports whether p reaches beyond private and tailnet space.
func public(p netip.Prefix) bool { return !private.ContainsPrefix(p) }

// reachesInternet reports whether a destination names public space.
func (v *View) reachesInternet(d Sel) bool {
	switch d.Kind { //nolint:exhaustive // identities reach it through their members, below
	case SelHost, SelPrefix:
		return public(v.selPrefix(d))
	case SelInternet:
		return true
	case SelSelf:
		return false
	}

	for _, n := range v.MembersOf(d) {
		if slices.ContainsFunc(n.Addrs(), func(a netip.Addr) bool { return public(netip.PrefixFrom(a, a.BitLen())) }) {
			return true
		}
	}

	return false
}

// touches reports whether a and b do not overlap and one begins where
// the other ends.
func touches(a, b netip.Prefix) bool {
	if a.Overlaps(b) || a.Addr().Is4() != b.Addr().Is4() {
		return false
	}

	return netipx.PrefixLastIP(a).Next() == b.Masked().Addr() || netipx.PrefixLastIP(b).Next() == a.Masked().Addr()
}

func onlyPolicy(st Step) bool {
	for _, e := range st.Edits {
		switch e.(type) {
		case SetPorts, SetProto, SetIP, SetApp, SetVia, SwapRules, SetSel, AddSel, RemoveSel, SetGroup, SetHost,
			SetTagOwners, AddRule, RemoveRule, AllowAll, SetRules, ReplaceUserRefs, SetSSH, SetNodeAttrs, SetAutoApprovers:
		default:
			return false
		}
	}

	return len(st.Edits) > 0
}

func edits[E Edit](st Step) []E {
	var out []E

	for _, e := range st.Edits {
		if x, ok := e.(E); ok {
			out = append(out, x)
		}
	}

	return out
}

func sameSet(a, b []Sel) bool {
	return !slices.ContainsFunc(a, func(s Sel) bool { return !slices.Contains(b, s) }) &&
		!slices.ContainsFunc(b, func(s Sel) bool { return !slices.Contains(a, s) })
}

func samePolicy(b, a *View) bool {
	return reflect.DeepEqual(b.World.Policy, a.World.Policy) || string(b.World.Policy.HuJSON()) == string(a.World.Policy.HuJSON())
}

// ruleChanged reports whether the rule ref names moved across a step that
// kept the rule lists' lengths, so the same index is the same rule.
func ruleChanged(b, a *View, ref RuleRef) bool {
	bl, al := b.World.Policy.List(ref.Grant), a.World.Policy.List(ref.Grant)

	return len(bl) == len(al) && ref.I < len(bl) && !reflect.DeepEqual(bl[ref.I], al[ref.I])
}

// nodeMoved reports whether node id kept across the step changed by f.
func nodeMoved(b, a *View, id types.NodeID, f func(was, is Node) bool) bool {
	was, okb := b.World.Topology.Node(id)
	is, oka := a.World.Topology.Node(id)

	return okb && oka && f(was, is)
}

// addrMoves reports, for family, whether some node kept across the step
// gained, lost or changed its address.
func addrMoves(before, after *View, family int, moved func(was, is netip.Addr) bool) bool {
	for _, n := range after.nodes {
		if o, ok := before.World.Topology.Node(n.ID); ok && moved(o.Addr(family), n.Addr(family)) {
			return true
		}
	}

	return false
}

func gained(was, is netip.Addr) bool { return !was.IsValid() && is.IsValid() }
func lost(was, is netip.Addr) bool   { return was.IsValid() && !is.IsValid() }
func moved(was, is netip.Addr) bool  { return was.IsValid() && is.IsValid() && was != is }

// readAt reports whether node id's session reads after step i (0 is the
// start, which every session reads).
func readAt(steps []Step, i int, id types.NodeID) bool {
	return i == 0 || slices.Contains(steps[i-1].Reads, id)
}

// Required is the shapes the generators must reach; a builder adds a row
// for each shape its properties need. Floors sit at about half of what the
// generators reach at the step count builders run, so they catch a
// generator that stops reaching a shape, not noise.
var Required = []Shape{
	// Topology.
	{Name: "unaddressed", Why: "a node no address set holds (database only)", Min: 0.15, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(n.Addrs()) == 0 })
	}},
	{Name: "shared-address", Why: "the client asks one node per address (database only)", Min: 0.035, World: (*View).sharedAddr},
	{Name: "single-family", Why: "rules that reach a node in one family only", Min: 0.3, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(n.Addrs()) == 1 })
	}},
	{Name: "outside-address", Why: "addresses * and the tailnet ranges do not cover (database only)", Min: 0.05, World: (*View).outsideAddr},
	{Name: "user-without-nodes", Why: "a user a token names who owns nothing", Min: 0.3, World: func(v *View) bool {
		return slices.ContainsFunc(v.users, func(u User) bool {
			return !v.anyNode(func(n Node) bool { return n.User == u.ID })
		})
	}},
	{Name: "oidc-user", Why: "a user named by the identity provider", Min: 0.25, World: func(v *View) bool {
		return slices.ContainsFunc(v.users, User.OIDC)
	}},
	{Name: "shared-user-name", Why: "two users with one name, which only OIDC allows", Min: 0.1, World: func(v *View) bool {
		for i, u := range v.users {
			if slices.ContainsFunc(v.users[i+1:], func(o User) bool { return o.Name == u.Name }) {
				return true
			}
		}

		return false
	}},
	{Name: "ambiguous-user", Why: "a token the document holds that two users answer to", Min: 0.05, World: func(v *View) bool {
		return len(v.AmbiguousRefs()) > 0
	}},
	{Name: "route-over-node", Why: "a router is on the side of the nodes its routes cover", Min: 0.15, World: func(v *View) bool {
		return v.anyNode(func(r Node) bool {
			return slices.ContainsFunc(r.Approved, func(rt int) bool {
				return rt < numRulePrefixes && v.anyNode(func(n Node) bool {
					return n.ID != r.ID && slices.ContainsFunc(n.Addrs(), Prefixes[rt].Contains)
				})
			})
		})
	}},
	{Name: "route-touching-destination", Why: "a served route that begins where a rule's destination ends", Min: 0.02, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool {
			return slices.ContainsFunc(served(n), func(rt int) bool {
				return v.anyRule(func(r Rule, _ bool) bool {
					return slices.ContainsFunc(r.Dst, func(d Dest) bool {
						return (d.Sel.Kind == SelHost || d.Sel.Kind == SelPrefix) && touches(v.selPrefix(d.Sel), Prefixes[rt])
					})
				})
			})
		})
	}},
	{Name: "exit-node", Why: "exits see what reaches the internet", Min: 0.1, World: (*View).exitPresent},
	{Name: "exit-one-family", Why: "an exit route in one family leaves own rules reaching nothing", Min: 0.04, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool {
			return n.Exit() && len(slices.DeleteFunc(served(n), func(r int) bool { return r < exit4 })) == 1
		})
	}},
	{Name: "approved-unannounced", Why: "approved routes count for * sources, announced or not", Min: 0.15, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(dropRoutes(n.Approved, n.Announced)) > 0 })
	}},
	{Name: "announced-unapproved", Why: "local nets follow announced routes", Min: 0.25, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(dropRoutes(n.Announced, n.Approved)) > 0 })
	}},
	{Name: "auto-approved", Why: "a route the auto-approvers approved", Min: 0.045, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(n.AutoApproved) > 0 })
	}},
	{Name: "service-host", Why: "a service host's filter goes as addresses", Min: 0.055, World: func(v *View) bool { return len(v.ServiceHosts()) > 0 }},
	{Name: "app-connector", Why: "an app connector's filter goes as addresses", Min: 0.1, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return n.Client == AppConnector })
	}},
	{Name: "unofficial-client", Why: "a client that looks no capability up", Min: 0.2, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return n.Client == Unknown || n.Client == TailscaleRS })
	}},
	{Name: "expired-node", Why: "expiry", Min: 0.15, World: func(v *View) bool { return v.anyNode(func(n Node) bool { return n.Expired }) }},
	{Name: "offline-node", Why: "online state", Min: 0.2, World: func(v *View) bool { return v.anyNode(func(n Node) bool { return n.Offline }) }},

	// Policy.
	{Name: "allow-all", Why: "no rule section at all, which allows everything", Min: 0.065, World: func(v *View) bool { return v.World.Policy.AllowAll }},
	{Name: "named-by-address-only", Why: "a node a rule names through a host or prefix", Min: 0.1, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			for _, d := range r.Dst {
				if (d.Sel.Kind == SelHost || d.Sel.Kind == SelPrefix) && len(v.MembersOf(d.Sel)) > 0 {
					return true
				}
			}

			return slices.ContainsFunc(r.Src, func(s Sel) bool { return (s.Kind == SelHost || s.Kind == SelPrefix) && len(v.MembersOf(s)) > 0 })
		})
	}},
	{Name: "self-rule", Why: "owner rules, cut per owner", Min: 0.2, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool { return r.selfRule() })
	}},
	{Name: "self-and-shared-rule", Why: "one ACL with a self and another destination", Min: 0.065, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool { return r.selfRule() && len(r.Dst) > 1 })
	}},
	{Name: "via-grant", Why: "via steering", Min: 0.09, World: func(v *View) bool { return v.anyRule(func(r Rule, _ bool) bool { return len(r.Via) > 0 }) }},
	{Name: "via-router-among-sources", Why: "a via router that is also a source", Min: 0.015, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			for _, tag := range r.Via {
				for _, n := range v.MembersOf(r.Src...) {
					if slices.Contains(n.Tags, tag) {
						return true
					}
				}
			}

			return false
		})
	}},
	{Name: "app-grant", Why: "capability rules, sent by address", Min: 0.15, World: func(v *View) bool { return v.anyRule(func(r Rule, _ bool) bool { return len(r.App) > 0 }) }},
	{Name: "app-companion", Why: "capabilities the compile adds a reverse rule for", Min: 0.1, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.App, func(a App) bool { return strings.HasPrefix(Apps[a.Cap], "tailscale.com/") })
		})
	}},
	{Name: "icmp-rule", Why: "ICMP, matched apart from ports", Min: 0.095, World: func(v *View) bool {
		return v.anyRule(func(r Rule, g bool) bool { return hasProto(r, g, "icmp", "ipv6-icmp") })
	}},
	{Name: "sctp-rule", Why: "the third ported protocol", Min: 0.06, World: func(v *View) bool { return v.anyRule(func(r Rule, g bool) bool { return hasProto(r, g, "sctp") }) }},
	{Name: "portless-rule", Why: "protocols the client matches by address only", Min: 0.05, World: func(v *View) bool { return v.anyRule(func(r Rule, g bool) bool { return hasProto(r, g, "gre") }) }},
	{Name: "port-range", Why: "port ranges and lists", Min: 0.15, World: func(v *View) bool {
		return v.anyRule(func(r Rule, g bool) bool { return hasPorts(r, g, "80-443", "22,443") })
	}},
	{Name: "port-boundary", Why: "ports at the edges of the range", Min: 0.2, World: func(v *View) bool {
		return v.anyRule(func(r Rule, g bool) bool { return hasPorts(r, g, "1", "65535") })
	}},
	{Name: "internet-dst", Why: "autogroup:internet", Min: 0.1, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.Dst, func(d Dest) bool { return d.Sel.Kind == SelInternet })
		})
	}},
	{Name: "danger-all-src", Why: "a literal source of everything", Min: 0.095, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelDangerAll })
		})
	}},
	{Name: "same-sources-and-protocol", Why: "two rules whose filter rules share a merge key", Min: 0.06, World: func(v *View) bool {
		refs := v.World.Policy.Refs()
		for i, a := range refs {
			for _, b := range refs[i+1:] {
				if sameSourcesAndProtocol(v.World.Policy.Rule(a), a.Grant, v.World.Policy.Rule(b), b.Grant) {
					return true
				}
			}
		}

		return false
	}},
	{Name: "group-member-names-nobody", Why: "a group member that adds no one", Min: 0.35, World: func(v *View) bool {
		for _, g := range v.World.Policy.Groups {
			if slices.ContainsFunc(g, func(ref int) bool { return len(v.RefUsers(ref)) == 0 }) {
				return true
			}
		}

		return false
	}},
	{Name: "ssh-rule", Why: "SSH, which makes no peers", Min: 0.15, World: func(v *View) bool { return len(v.World.Policy.SSH) > 0 }},
	{Name: "ssh-check", Why: "check actions", Min: 0.035, World: func(v *View) bool {
		return slices.ContainsFunc(v.World.Policy.SSH, func(r SSHRule) bool { return r.Check })
	}},
	{Name: "auto-approvers", Why: "route auto-approval", Min: 0.15, World: func(v *View) bool {
		aa := v.World.Policy.AutoApprovers

		return len(aa.Routes) > 0 || len(aa.Exit) > 0
	}},

	// Pairs.
	{Name: "tag-all-unaddressed", Why: "a tag destination resolving to no address", Min: 0.01, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.Dst, func(d Dest) bool {
				ms := v.MembersOf(d.Sel)

				return d.Sel.Kind == SelTag && len(ms) > 0 && !slices.ContainsFunc(ms, func(n Node) bool { return len(n.Addrs()) > 0 })
			})
		})
	}},
	{Name: "self-from-star-outside-owner", Why: "* as a self source names owners by range", Min: 0.004, World: func(v *View) bool {
		star := slices.ContainsFunc(v.World.Policy.ACLs, func(r Rule) bool {
			return r.selfRule() && slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelAll })
		})

		return star && v.anyNode(func(n Node) bool { return !n.Tagged() && slices.ContainsFunc(n.Addrs(), Outside) })
	}},
	{Name: "addressless-owner-routes-own-node", Why: "an owner with no address reaching its own node by route", Min: 0.015, World: func(v *View) bool {
		return v.anyNode(func(r Node) bool {
			return !r.Tagged() && len(r.Addrs()) == 0 && v.anyNode(func(n Node) bool {
				return n.ID != r.ID && !n.Tagged() && n.User == r.User && slices.ContainsFunc(r.Approved, func(rt int) bool {
					return slices.ContainsFunc(n.Addrs(), Prefixes[rt].Contains)
				})
			})
		})
	}},
	{Name: "outside-address-exit", Why: "exit visibility with addresses outside the tailnet", Min: 0.015, World: func(v *View) bool { return v.outsideAddr() && v.exitPresent() }},
	{Name: "shared-address-cap-receiver", Why: "sharing decides capability form for eligible receivers", Min: 0.03, World: func(v *View) bool {
		return v.sharedAddr() && v.anyNode(v.Eligible)
	}},
	{Name: "cap-to-internet-with-exit", Why: "the inputs of one-way visibility: a member's app grant to public space, and an exit", Min: 0.015, World: func(v *View) bool {
		return v.exitPresent() && slices.ContainsFunc(v.World.Policy.Grants, func(r Rule) bool {
			return len(r.App) > 0 && len(v.MembersOf(r.Src...)) > 0 &&
				slices.ContainsFunc(r.Dst, func(d Dest) bool { return v.reachesInternet(d.Sel) })
		})
	}},
	{Name: "via-star-outside-viewer", Why: "a viewer outside the tailnet under a * via source", Min: 0.004, World: func(v *View) bool {
		return v.outsideAddr() && slices.ContainsFunc(v.World.Policy.Grants, func(r Rule) bool {
			return len(r.Via) > 0 && slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelAll })
		})
	}},
	{Name: "companion-outside", Why: "companion rules with addresses outside the tailnet", Min: 0.01, World: func(v *View) bool {
		return v.outsideAddr() && v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.App, func(a App) bool { return strings.HasPrefix(Apps[a.Cap], "tailscale.com/") })
		})
	}},
	{Name: "portless-to-cap-receiver", Why: "a portless rule to a receiver sent capabilities", Min: 0.02, World: func(v *View) bool {
		return v.anyRule(func(r Rule, g bool) bool {
			if !hasProto(r, g, "gre") {
				return false
			}

			for _, d := range r.Dst {
				if slices.ContainsFunc(v.MembersOf(d.Sel), v.Eligible) {
					return true
				}
			}

			return false
		})
	}},

	// Steps.
	{Name: "policy-edit-keeps-selectors", Why: "an edit that keeps the selector table", Min: 0.15, Step: func(b, a *View, st Step) bool {
		return onlyPolicy(st) && !samePolicy(b, a) && sameSet(b.World.Policy.Selectors(), a.World.Policy.Selectors())
	}},
	{Name: "policy-edit-changes-selectors", Why: "an edit that mints a new selector table", Min: 0.15, Step: func(b, a *View, st Step) bool {
		return onlyPolicy(st) && !sameSet(b.World.Policy.Selectors(), a.World.Policy.Selectors())
	}},
	{Name: "rule-side-moved", Why: "a rule's source or destination moves", Min: 0.045, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[SetSel](st), func(e SetSel) bool { return ruleChanged(b, a, e.Rule) })
	}},
	{Name: "selector-list-length-changed", Why: "a rule gains or loses a source or destination", Min: 0.06, Step: func(b, a *View, st Step) bool {
		return len(edits[AddSel](st)) > 0 || slices.ContainsFunc(edits[RemoveSel](st), func(e RemoveSel) bool { return ruleChanged(b, a, e.Rule) })
	}},
	{Name: "ip-list-changed", Why: "a grant's protocols and ports move in place", Min: 0.02, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[SetIP](st), func(e SetIP) bool { return ruleChanged(b, a, e.Rule) })
	}},
	{Name: "app-capabilities-changed", Why: "only a grant's capabilities or their values move", Min: 0.025, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[SetApp](st), func(e SetApp) bool { return ruleChanged(b, a, e.Rule) })
	}},
	{Name: "via-changed", Why: "a grant's via tags move", Min: 0.009, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[SetVia](st), func(e SetVia) bool { return ruleChanged(b, a, e.Rule) })
	}},
	{Name: "allow-all-to-rules", Why: "the first rule after allowing everything", Min: 0.03, Step: func(b, a *View, _ Step) bool {
		return b.World.Policy.AllowAll && !a.World.Policy.AllowAll
	}},
	{Name: "rules-to-allow-all", Why: "every rule gone, allowing everything", Min: 0.03, Step: func(b, a *View, _ Step) bool {
		return !b.World.Policy.AllowAll && a.World.Policy.AllowAll
	}},
	{Name: "host-edit-named", Why: "a host's prefix edited while rules keep naming it", Min: 0.015, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[SetHost](st), func(e SetHost) bool {
			return b.World.Policy.referenced().hosts[e.Host] && b.World.Policy.Hosts[e.Host] != a.World.Policy.Hosts[e.Host]
		})
	}},
	{Name: "service-host-flip-by-policy", Why: "a receiver fact flipped by the policy alone", Min: 0.006, Step: func(b, a *View, st Step) bool {
		return onlyPolicy(st) && !slices.Equal(b.ServiceHosts(), a.ServiceHosts())
	}},
	{Name: "user-refs-replaced", Why: "the write that fixes a token users made ambiguous", Min: 0.03, Step: func(_, _ *View, st Step) bool {
		return len(edits[ReplaceUserRefs](st)) > 0
	}},
	{Name: "user-edit-makes-token-ambiguous", Why: "an accepted document whose token users then make ambiguous", Min: 0.05, Step: func(b, a *View, _ Step) bool {
		return len(b.AmbiguousRefs()) == 0 && len(a.AmbiguousRefs()) > 0
	}},
	{Name: "announce-approve-served-route", Why: "one write announces and approves a route another node serves", Min: 0.05, Step: func(b, _ *View, st Step) bool {
		for _, an := range edits[Announce](st) {
			if !slices.ContainsFunc(edits[Approve](st), func(ap Approve) bool { return ap.ID == an.ID }) {
				continue
			}

			if b.anyNode(func(n Node) bool {
				return n.ID != an.ID && slices.ContainsFunc(served(n), func(r int) bool {
					return slices.ContainsFunc(an.Routes, func(x int) bool { return Prefixes[x].Overlaps(Prefixes[r]) })
				})
			}) {
				return true
			}
		}

		return false
	}},
	{Name: "announce-auto-approved", Why: "an announcement the auto-approvers approve at once", Min: 0.01, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[Announce](st), func(e Announce) bool {
			return nodeMoved(b, a, e.ID, func(was, is Node) bool { return len(is.AutoApproved) > len(was.AutoApproved) })
		})
	}},
	{Name: "withdraw-drops-auto-approval", Why: "a withdrawn route's auto-approval goes", Min: 0.007, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[Withdraw](st), func(e Withdraw) bool {
			return nodeMoved(b, a, e.ID, func(was, is Node) bool { return len(is.Approved) < len(was.Approved) })
		})
	}},
	{Name: "address-gained-v4", Why: "a node gains an IPv4 address", Min: 0.03, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 4, gained) }},
	{Name: "address-gained-v6", Why: "a node gains an IPv6 address", Min: 0.01, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 6, gained) }},
	{Name: "address-lost-v4", Why: "a node loses its IPv4 address", Min: 0.02, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 4, lost) }},
	{Name: "address-lost-v6", Why: "a node loses its IPv6 address", Min: 0.025, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 6, lost) }},
	{Name: "address-moved-v4", Why: "a node moves to another IPv4 address", Min: 0.07, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 4, moved) }},
	{Name: "address-moved-v6", Why: "a node moves to another IPv6 address", Min: 0.03, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 6, moved) }},
	{Name: "address-onto-shared", Why: "a node moving onto an address another holds (database only)", Min: 0.002, Step: func(b, a *View, _ Step) bool {
		for _, n := range a.nodes {
			o, ok := b.World.Topology.Node(n.ID)
			if !ok {
				continue
			}

			for _, f := range []int{4, 6} {
				if n.Addr(f) != o.Addr(f) && a.heldByOther(n, n.Addr(f)) {
					return true
				}
			}
		}

		return false
	}},
	{Name: "delete-and-reuse-address", Why: "an address freed and handed out again in one commit", Min: 0.1, Step: func(b, _ *View, st Step) bool {
		for _, l := range edits[Leave](st) {
			gone, _ := b.World.Topology.Node(l.ID)

			if slices.ContainsFunc(edits[Join](st), func(j Join) bool {
				return slices.ContainsFunc(gone.Addrs(), func(x netip.Addr) bool { return slices.Contains(j.Node.Addrs(), x) })
			}) {
				return true
			}
		}

		return false
	}},
	{Name: "several-edits-in-a-step", Why: "edits committed together", Min: 0.25, Step: func(_, _ *View, st Step) bool { return len(st.Edits) > 1 }},
	{Name: "retag", Why: "a node's tags change", Min: 0.07, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[Retag](st), func(e Retag) bool {
			return len(e.Tags) > 0 && nodeMoved(b, a, e.ID, func(was, is Node) bool { return !slices.Equal(was.Tags, is.Tags) })
		})
	}},
	{Name: "untag", Why: "a tagged node logs in as a user", Min: 0.01, Step: func(b, a *View, st Step) bool {
		return slices.ContainsFunc(edits[Retag](st), func(e Retag) bool {
			return len(e.Tags) == 0 && nodeMoved(b, a, e.ID, func(was, is Node) bool { return was.Tagged() && !is.Tagged() })
		})
	}},
	{Name: "user-added", Why: "user churn", Min: 0.15, Step: func(_, _ *View, st Step) bool { return len(edits[AddUser](st)) > 0 }},
	{Name: "user-deleted", Why: "user churn", Min: 0.055, Step: func(_, _ *View, st Step) bool { return len(edits[DeleteUser](st)) > 0 }},
	{Name: "user-renamed", Why: "token resolution follows names", Min: 0.08, Step: func(_, _ *View, st Step) bool { return len(edits[RenameUser](st)) > 0 }},
	{Name: "user-email-changed", Why: "token resolution follows e-mails", Min: 0.035, Step: func(_, _ *View, st Step) bool { return len(edits[SetEmail](st)) > 0 }},
	{Name: "receiver-flip", Why: "a node's capability form flips", Min: 0.15, Step: func(b, a *View, _ Step) bool {
		for _, n := range a.nodes {
			if o, ok := b.World.Topology.Node(n.ID); ok && b.Eligible(o) != a.Eligible(n) {
				return true
			}
		}

		return false
	}},
	{Name: "partial-read", Why: "some sessions read a commit, others do not", Min: 0.25, Step: func(_, a *View, st Step) bool {
		return len(st.Reads) > 0 && len(st.Reads) < len(a.nodes)
	}},
	{Name: "long-unread", Why: "a session reads after three commits it did not", Min: 0.1, Seq: longUnread},
	{Name: "flip-move-flip-back", Why: "a filter carried across a form flip, a move and a flip back", Min: 0.04, Seq: flipMoveFlipBack},
}

// longUnread reports whether some node's session reads after three or
// more steps it did not read.
func longUnread(vs []*View, steps []Step) bool {
	for _, n := range vs[0].nodes {
		unread := 0

		for i := 1; i < len(vs); i++ {
			if _, ok := vs[i].World.Topology.Node(n.ID); !ok {
				break
			}

			if !readAt(steps, i, n.ID) {
				unread++

				continue
			}

			if unread >= 3 {
				return true
			}

			unread = 0
		}
	}

	return false
}

// flipMoveFlipBack reports whether a node's session read, then, with it
// not reading, the node's eligibility flipped, its address alone moved,
// its eligibility flipped back; and then it read: the filter it holds was
// carried across all three.
func flipMoveFlipBack(vs []*View, steps []Step) bool {
	for _, n := range vs[0].nodes {
		stage := 0

		for i := 1; i < len(vs); i++ {
			was, okb := vs[i-1].World.Topology.Node(n.ID)
			is, oka := vs[i].World.Topology.Node(n.ID)

			if !okb || !oka {
				break
			}

			flip := vs[i-1].Eligible(was) != vs[i].Eligible(is)
			move := was.V4 != is.V4 || was.V6 != is.V6
			read := readAt(steps, i, n.ID)

			switch {
			case stage == 0 && flip && !read:
				stage = 1
			case stage == 1 && move && !flip && !read:
				stage = 2
			case stage == 2 && flip:
				if read {
					return true
				}

				stage = 3
			case stage == 3 && read:
				return true
			case read:
				stage = 0
			}
		}
	}

	return false
}
