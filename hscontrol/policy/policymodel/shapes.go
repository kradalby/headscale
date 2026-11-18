package policymodel

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
)

// Shape is a named shape a case can contain, computed from the case
// itself. A shape is one of three kinds: World holds of some world of the
// scenario, Step of some step (with the worlds either side of it), Seq of
// the whole sequence.
type Shape struct {
	Name string
	// Why is what the shape exercises.
	Why string
	// Min is the least share of drawn cases that must contain the shape:
	// of Worlds for a world shape, and of Scenarios for every shape.
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

// View answers what a world's selectors name. It is for classifying, not
// an oracle; TestGeneratedPoliciesCompile in policy/v2 holds its service
// hosts and eligibility to headscale's, so the shapes built on them mean
// what they say.
type View struct {
	World World

	users        []User
	nodes        []Node
	serviceHosts []types.NodeID
}

// NewView indexes w.
func NewView(w World) *View {
	v := &View{World: w, users: w.Topology.Users, nodes: w.Topology.Nodes}

	// nodeAttrs resolve their targets to addresses and grant to every
	// node holding one: a node sharing a target's address gets them too,
	// and a node without addresses never does.
	for _, n := range v.nodes {
		if slices.ContainsFunc(w.Policy.NodeAttrs, func(a NodeAttr) bool {
			return slices.Contains(a.Attrs, attrServiceHost) && slices.ContainsFunc(n.Addrs(), func(ip netip.Addr) bool {
				return slices.ContainsFunc(a.Targets, func(s Sel) bool { return v.resolves(s, ip) })
			})
		}) {
			v.serviceHosts = append(v.serviceHosts, n.ID)
		}
	}

	return v
}

// chromeOSVM is cut from what * resolves to.
var chromeOSVM = netip.MustParsePrefix("100.115.92.0/23")

// resolves reports whether s, resolved to addresses, holds ip.
func (v *View) resolves(s Sel, ip netip.Addr) bool {
	switch s.Kind { //nolint:exhaustive // identities resolve to their members, below
	case SelAll:
		return (tailnetV4.Contains(ip) || tailnetV6.Contains(ip)) && !chromeOSVM.Contains(ip)
	case SelDangerAll:
		return true
	case SelHost, SelPrefix:
		return v.selPrefix(s).Contains(ip)
	case SelSelf, SelInternet:
		return false
	}

	return slices.ContainsFunc(v.MembersOf(s), func(n Node) bool { return slices.Contains(n.Addrs(), ip) })
}

// RefUsers returns the users UserRefs[ref] names: the one user with that
// e-mail, else the one with that name, or for a domain every user with an
// e-mail there. Two candidates name nobody.
func (v *View) RefUsers(ref int) []uint {
	token := UserRefs[ref]

	if domain, ok := strings.CutPrefix(token, "user:*@"); ok {
		var out []uint

		for _, u := range v.users {
			if _, d, ok := strings.CutLast(u.Email, "@"); ok && strings.EqualFold(d, domain) {
				out = append(out, u.ID)
			}
		}

		return out
	}

	token = strings.TrimSuffix(token, "@")

	for _, match := range []func(User) bool{
		func(u User) bool { return u.Email == token },
		func(u User) bool { return u.Name == token },
	} {
		var ids []uint

		for _, u := range v.users {
			if match(u) {
				ids = append(ids, u.ID)
			}
		}

		if len(ids) == 1 {
			return ids
		}

		if len(ids) > 1 {
			return nil
		}
	}

	return nil
}

// MembersOf returns the nodes any of sels names: by identity, or by
// address for hosts and prefixes.
func (v *View) MembersOf(sels ...Sel) []Node {
	var out []Node

	for _, n := range v.nodes {
		if slices.ContainsFunc(sels, func(s Sel) bool { return v.names(s, n) }) {
			out = append(out, n)
		}
	}

	return out
}

func (v *View) names(s Sel, n Node) bool {
	owned := func(refs ...int) bool {
		if n.Tagged() {
			return false
		}

		for _, r := range refs {
			if slices.Contains(v.RefUsers(r), n.User) {
				return true
			}
		}

		return false
	}

	switch s.Kind {
	case SelAll, SelDangerAll:
		return true
	case SelUser:
		return owned(s.I)
	case SelGroup:
		return owned(v.World.Policy.Groups[s.I]...)
	case SelTag:
		return slices.Contains(n.Tags, s.I)
	case SelMember:
		return !n.Tagged()
	case SelTagged:
		return n.Tagged()
	case SelHost, SelPrefix:
		p := v.selPrefix(s)

		return slices.ContainsFunc(n.Addrs(), p.Contains)
	case SelSelf, SelInternet:
	}

	return false
}

func (v *View) selPrefix(s Sel) netip.Prefix {
	if s.Kind == SelHost {
		return Prefixes[v.World.Policy.HostPrefix(s.I)]
	}

	return Prefixes[s.I]
}

// ServiceHosts is the nodes nodeAttrs makes service hosts.
func (v *View) ServiceHosts() []types.NodeID { return v.serviceHosts }

// Eligible reports whether n can be sent capability sources, as far as
// the model knows: an official client handling only its own addresses.
func (v *View) Eligible(n Node) bool {
	return n.Client == Official && len(n.Announced) == 0 && !slices.Contains(v.serviceHosts, n.ID)
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
	for i, n := range v.nodes {
		for _, m := range v.nodes[i+1:] {
			for _, a := range n.Addrs() {
				if slices.Contains(m.Addrs(), a) {
					return true
				}
			}
		}
	}

	return false
}

func (v *View) outsideAddr() bool {
	return v.anyNode(func(n Node) bool { return slices.ContainsFunc(n.Addrs(), Outside) })
}

// protos is a rule's protocols as a merge key compares them.
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

// sameKey reports whether a and b have the same sources and protocols, so
// their filter rules merge.
func sameKey(a Rule, ag bool, b Rule, bg bool) bool {
	return slices.Equal(a.Src, b.Src) && slices.Equal(protos(a, ag), protos(b, bg))
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

// cover is, for each router, the rule sides its served subnet routes
// overlap, each written as the side's selectors: what moves when a
// document edit changes which rules reach a router.
func (v *View) cover() map[types.NodeID][]string {
	out := map[types.NodeID][]string{}

	for _, n := range v.nodes {
		var routes []netip.Prefix

		for _, r := range served(n) {
			if r < numRulePrefixes {
				routes = append(routes, Prefixes[r])
			}
		}

		if len(routes) == 0 {
			continue
		}

		var sides []string

		for _, ref := range v.World.Policy.Refs() {
			r := v.World.Policy.Rule(ref)

			dst := make([]Sel, len(r.Dst))
			for i, d := range r.Dst {
				dst[i] = d.Sel
			}

			for side, sels := range [][]Sel{r.Src, dst} {
				if slices.ContainsFunc(routes, func(rt netip.Prefix) bool { return v.overlaps(sels, rt) }) {
					sides = append(sides, [...]string{"src ", "dst "}[side]+joinSels(sels))
				}
			}
		}

		slices.Sort(sides)
		out[n.ID] = sides
	}

	return out
}

func (v *View) overlaps(sels []Sel, rt netip.Prefix) bool {
	for _, s := range sels {
		switch s.Kind { //nolint:exhaustive // identities overlap through their members, in default
		case SelAll:
			if rt.Overlaps(tailnetV4) || rt.Overlaps(tailnetV6) {
				return true
			}
		case SelDangerAll:
			return true
		case SelInternet:
			if public(rt) {
				return true
			}
		case SelHost, SelPrefix:
			if v.selPrefix(s).Overlaps(rt) {
				return true
			}
		case SelSelf:
		default:
			for _, n := range v.MembersOf(s) {
				if slices.ContainsFunc(n.Addrs(), rt.Contains) {
					return true
				}
			}
		}
	}

	return false
}

func onlyPolicy(st Step) bool {
	for _, e := range st {
		switch e.(type) {
		case SetPorts, SetProto, SwapRules, SetSel, SetGroup, SetHost, SetTagOwners, AddRule, RemoveRule,
			SetSSH, SetNodeAttrs, SetAutoApprovers:
		default:
			return false
		}
	}

	return true
}

func has[E Edit](st Step) bool {
	return slices.ContainsFunc(st, func(e Edit) bool { _, ok := e.(E); return ok })
}

func sameSet(a, b []Sel) bool {
	return !slices.ContainsFunc(a, func(s Sel) bool { return !slices.Contains(b, s) }) &&
		!slices.ContainsFunc(b, func(s Sel) bool { return !slices.Contains(a, s) })
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

// heldByOther reports whether a node other than n holds a.
func (v *View) heldByOther(n Node, a netip.Addr) bool {
	return a.IsValid() && v.anyNode(func(m Node) bool { return m.ID != n.ID && slices.Contains(m.Addrs(), a) })
}

// Required is the shapes the generators must reach; a builder adds a row
// for each shape its properties need. Floors sit at about half of what the generators reach,
// so they catch a generator that stops reaching a shape, not noise.
var Required = []Shape{
	// Topology.
	{Name: "unaddressed", Why: "a node no address set holds", Min: 0.15, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(n.Addrs()) == 0 })
	}},
	{Name: "shared-address", Why: "the client asks one node per address", Min: 0.2, World: (*View).sharedAddr},
	{Name: "single-family", Why: "rules that reach a node in one family only", Min: 0.25, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(n.Addrs()) == 1 })
	}},
	{Name: "outside-address", Why: "addresses * and the tailnet ranges do not cover", Min: 0.15, World: (*View).outsideAddr},
	{Name: "tagged-with-user", Why: "IsTagged, not UserID, decides ownership", Min: 0.1, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return n.Tagged() && n.User != 0 })
	}},
	{Name: "user-without-nodes", Why: "a user a token names who owns nothing", Min: 0.2, World: func(v *View) bool {
		return slices.ContainsFunc(v.users, func(u User) bool {
			return !v.anyNode(func(n Node) bool { return n.User == u.ID })
		})
	}},
	{Name: "ambiguous-user", Why: "a token two users match names nobody", Min: 0.07, World: func(v *View) bool {
		for i, u := range v.users {
			if slices.ContainsFunc(v.users[i+1:], func(o User) bool { return o.Name == u.Name || u.Email != "" && o.Email == u.Email }) {
				return true
			}
		}

		return false
	}},
	{Name: "route-over-node", Why: "a router is on the side of the nodes its routes cover", Min: 0.12, World: func(v *View) bool {
		return v.anyNode(func(r Node) bool {
			return slices.ContainsFunc(r.Approved, func(rt int) bool {
				return rt < numRulePrefixes && v.anyNode(func(n Node) bool {
					return n.ID != r.ID && slices.ContainsFunc(n.Addrs(), Prefixes[rt].Contains)
				})
			})
		})
	}},
	{Name: "exit-node", Why: "exits see what reaches the internet", Min: 0.15, World: (*View).exitPresent},
	{Name: "exit-one-family", Why: "an exit route in one family leaves own rules reaching nothing", Min: 0.04, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool {
			return n.Exit() && len(slices.DeleteFunc(served(n), func(r int) bool { return r < exit4 })) == 1
		})
	}},
	{Name: "approved-unannounced", Why: "approved routes count for * sources, announced or not", Min: 0.1, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(dropRoutes(n.Approved, n.Announced)) > 0 })
	}},
	{Name: "announced-unapproved", Why: "local nets follow announced routes", Min: 0.15, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return len(dropRoutes(n.Announced, n.Approved)) > 0 })
	}},
	{Name: "service-host", Why: "a receiver fact that sends addresses", Min: 0.04, World: func(v *View) bool { return len(v.serviceHosts) > 0 }},
	{Name: "app-connector", Why: "a receiver fact that sends addresses", Min: 0.07, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return n.Client == AppConnector })
	}},
	{Name: "unofficial-client", Why: "a client that looks no capability up", Min: 0.14, World: func(v *View) bool {
		return v.anyNode(func(n Node) bool { return n.Client == Unknown || n.Client == TailscaleRS })
	}},
	{Name: "expired-node", Why: "expiry", Min: 0.15, World: func(v *View) bool { return v.anyNode(func(n Node) bool { return n.Expired }) }},
	{Name: "offline-node", Why: "online state", Min: 0.18, World: func(v *View) bool { return v.anyNode(func(n Node) bool { return n.Offline }) }},

	// Policy.
	{Name: "named-by-address-only", Why: "a node a rule names through a host or prefix", Min: 0.12, World: func(v *View) bool {
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
	{Name: "via-grant", Why: "via steering", Min: 0.08, World: func(v *View) bool { return v.anyRule(func(r Rule, _ bool) bool { return len(r.Via) > 0 }) }},
	{Name: "via-router-among-sources", Why: "a via router that is also a source", Min: 0.012, World: func(v *View) bool {
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
	{Name: "icmp-rule", Why: "ICMP, matched apart from ports", Min: 0.09, World: func(v *View) bool {
		return v.anyRule(func(r Rule, g bool) bool { return hasProto(r, g, "icmp", "ipv6-icmp") })
	}},
	{Name: "sctp-rule", Why: "the third ported protocol", Min: 0.04, World: func(v *View) bool { return v.anyRule(func(r Rule, g bool) bool { return hasProto(r, g, "sctp") }) }},
	{Name: "portless-rule", Why: "protocols the client matches by address only", Min: 0.06, World: func(v *View) bool { return v.anyRule(func(r Rule, g bool) bool { return hasProto(r, g, "gre") }) }},
	{Name: "port-range", Why: "port ranges and lists", Min: 0.18, World: func(v *View) bool {
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
	{Name: "danger-all-src", Why: "a literal source of everything", Min: 0.1, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelDangerAll })
		})
	}},
	{Name: "same-key-rules", Why: "rules whose filter rules merge", Min: 0.06, World: func(v *View) bool {
		refs := v.World.Policy.Refs()
		for i, a := range refs {
			for _, b := range refs[i+1:] {
				if sameKey(v.World.Policy.Rule(a), a.Grant, v.World.Policy.Rule(b), b.Grant) {
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
	{Name: "ssh-check", Why: "check actions", Min: 0.02, World: func(v *View) bool {
		return slices.ContainsFunc(v.World.Policy.SSH, func(r SSHRule) bool { return r.Check })
	}},
	{Name: "auto-approvers", Why: "route auto-approval", Min: 0.12, World: func(v *View) bool {
		aa := v.World.Policy.AutoApprovers

		return len(aa.Routes) > 0 || len(aa.Exit) > 0
	}},

	// Pairs.
	{Name: "own-rule-merge-key", Why: "an own rule that reaches nothing still places a merged rule", Min: 0.012, World: func(v *View) bool {
		thin := v.anyNode(func(n Node) bool {
			return !n.Tagged() && len(n.Addrs()) < 2 || n.Exit() && len(served(n)) < 2
		})

		return thin && v.anyRule(func(a Rule, ag bool) bool {
			return a.selfRule() && v.anyRule(func(b Rule, bg bool) bool { return !b.selfRule() && sameKey(a, ag, b, bg) })
		})
	}},
	{Name: "tag-all-unaddressed", Why: "a rule whose destination resolves to nothing", Min: 0.008, World: func(v *View) bool {
		return v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.Dst, func(d Dest) bool {
				ms := v.MembersOf(d.Sel)

				return d.Sel.Kind == SelTag && len(ms) > 0 && !slices.ContainsFunc(ms, func(n Node) bool { return len(n.Addrs()) > 0 })
			})
		})
	}},
	{Name: "self-from-star-outside-owner", Why: "* as a self source names owners by range", Min: 0.016, World: func(v *View) bool {
		star := slices.ContainsFunc(v.World.Policy.ACLs, func(r Rule) bool {
			return r.selfRule() && slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelAll })
		})

		return star && v.anyNode(func(n Node) bool { return !n.Tagged() && slices.ContainsFunc(n.Addrs(), Outside) })
	}},
	{Name: "addressless-owner-routes-own-node", Why: "an owner with no address reaching its own node by route", Min: 0.014, World: func(v *View) bool {
		return v.anyNode(func(r Node) bool {
			return !r.Tagged() && len(r.Addrs()) == 0 && v.anyNode(func(n Node) bool {
				return n.ID != r.ID && !n.Tagged() && n.User == r.User && slices.ContainsFunc(r.Approved, func(rt int) bool {
					return slices.ContainsFunc(n.Addrs(), Prefixes[rt].Contains)
				})
			})
		})
	}},
	{Name: "outside-address-exit", Why: "exit visibility with addresses outside the tailnet", Min: 0.05, World: func(v *View) bool { return v.outsideAddr() && v.exitPresent() }},
	{Name: "shared-address-cap-receiver", Why: "sharing decides capability form for eligible receivers", Min: 0.18, World: func(v *View) bool {
		return v.sharedAddr() && v.anyNode(v.Eligible)
	}},
	{Name: "cap-to-internet-with-exit", Why: "exits see such sources one way", Min: 0.014, World: func(v *View) bool {
		return v.exitPresent() && slices.ContainsFunc(v.World.Policy.Grants, func(r Rule) bool {
			return len(r.App) > 0 && len(v.MembersOf(r.Src...)) > 0 &&
				slices.ContainsFunc(r.Dst, func(d Dest) bool { return v.reachesInternet(d.Sel) })
		})
	}},
	{Name: "via-star-outside-viewer", Why: "a viewer outside the tailnet under a * via source", Min: 0.008, World: func(v *View) bool {
		return v.outsideAddr() && slices.ContainsFunc(v.World.Policy.Grants, func(r Rule) bool {
			return len(r.Via) > 0 && slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelAll })
		})
	}},
	{Name: "companion-outside", Why: "companion rules with addresses outside the tailnet", Min: 0.035, World: func(v *View) bool {
		return v.outsideAddr() && v.anyRule(func(r Rule, _ bool) bool {
			return slices.ContainsFunc(r.App, func(a App) bool { return strings.HasPrefix(Apps[a.Cap], "tailscale.com/") })
		})
	}},
	{Name: "portless-to-cap-receiver", Why: "a portless rule to a receiver sent capabilities", Min: 0.014, World: func(v *View) bool {
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
	{Name: "policy-edit-keeps-selectors", Why: "an edit that keeps the selector table", Min: 0.3, Step: func(b, a *View, st Step) bool {
		return onlyPolicy(st) && !samePolicy(b, a) && sameSet(b.World.Policy.Selectors(), a.World.Policy.Selectors())
	}},
	{Name: "policy-edit-changes-selectors", Why: "an edit that mints a new selector table", Min: 0.22, Step: func(b, a *View, st Step) bool {
		return onlyPolicy(st) && !sameSet(b.World.Policy.Selectors(), a.World.Policy.Selectors())
	}},
	{Name: "rule-side-moved", Why: "a rule's source or destination moves", Min: 0.11, Step: func(b, a *View, st Step) bool {
		return has[SetSel](st) && !samePolicy(b, a)
	}},
	{Name: "host-edit-named", Why: "a host's prefix edited while rules keep naming it", Min: 0.05, Step: func(b, a *View, st Step) bool {
		for _, e := range st {
			if h, ok := e.(SetHost); ok {
				if b.World.Policy.referenced().hosts[h.Host] {
					return true
				}
			}
		}

		return false
	}},
	{Name: "router-cover-moved-by-policy", Why: "a router's cover moves with no node written", Min: 0.1, Step: func(b, a *View, st Step) bool {
		if !onlyPolicy(st) {
			return false
		}

		cb, ca := b.cover(), a.cover()
		for id, sides := range cb {
			if !slices.Equal(sides, ca[id]) {
				return true
			}
		}

		return false
	}},
	{Name: "service-host-flip-by-policy", Why: "a receiver fact flipped by the policy alone", Min: 0.026, Step: func(b, a *View, st Step) bool {
		return onlyPolicy(st) && !slices.Equal(b.serviceHosts, a.serviceHosts)
	}},
	{Name: "announce-approve-served-route", Why: "one write announces and approves a route another node serves", Min: 0.12, Step: func(b, _ *View, st Step) bool {
		for _, e := range st {
			an, ok := e.(Announce)
			if !ok || !slices.ContainsFunc(st, func(o Edit) bool {
				ap, ok := o.(Approve)

				return ok && ap.ID == an.ID && slices.Equal(ap.Routes, an.Routes)
			}) {
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
	{Name: "address-gained-v4", Why: "a node gains an IPv4 address", Min: 0.07, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 4, gained) }},
	{Name: "address-gained-v6", Why: "a node gains an IPv6 address", Min: 0.07, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 6, gained) }},
	{Name: "address-lost-v4", Why: "a node loses its IPv4 address", Min: 0.028, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 4, lost) }},
	{Name: "address-lost-v6", Why: "a node loses its IPv6 address", Min: 0.04, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 6, lost) }},
	{Name: "address-moved-v4", Why: "a node moves to another IPv4 address", Min: 0.09, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 4, moved) }},
	{Name: "address-moved-v6", Why: "a node moves to another IPv6 address", Min: 0.09, Step: func(b, a *View, _ Step) bool { return addrMoves(b, a, 6, moved) }},
	{Name: "address-onto-shared", Why: "a node moving onto an address another holds", Min: 0.06, Step: func(b, a *View, _ Step) bool {
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
	{Name: "group-member-joins-at-shared", Why: "a group member joining at another user's node's address", Min: 0.09, Step: func(b, _ *View, st Step) bool {
		for _, e := range st {
			j, ok := e.(Join)
			if !ok || j.Node.Tagged() {
				continue
			}

			inGroup := slices.ContainsFunc(b.World.Policy.Groups[:], func(g []int) bool {
				return slices.ContainsFunc(g, func(ref int) bool { return slices.Contains(b.RefUsers(ref), j.Node.User) })
			})
			if inGroup && b.anyNode(func(m Node) bool {
				return m.User != j.Node.User && slices.ContainsFunc(m.Addrs(), func(x netip.Addr) bool { return slices.Contains(j.Node.Addrs(), x) })
			}) {
				return true
			}
		}

		return false
	}},
	{Name: "delete-and-reuse-address", Why: "an address freed and taken in one commit", Min: 0.22, Step: func(b, _ *View, st Step) bool {
		for _, e := range st {
			l, ok := e.(Leave)
			if !ok {
				continue
			}

			gone, _ := b.World.Topology.Node(l.ID)

			if slices.ContainsFunc(st, func(o Edit) bool {
				j, ok := o.(Join)

				return ok && slices.ContainsFunc(gone.Addrs(), func(x netip.Addr) bool { return slices.Contains(j.Node.Addrs(), x) })
			}) {
				return true
			}
		}

		return false
	}},
	{Name: "delete-and-reuse-id", Why: "an ID freed and taken in one commit", Min: 0.15, Step: func(_, _ *View, st Step) bool {
		return slices.ContainsFunc(st, func(e Edit) bool {
			l, ok := e.(Leave)

			return ok && slices.ContainsFunc(st, func(o Edit) bool { j, ok := o.(Join); return ok && j.Node.ID == l.ID })
		})
	}},
	{Name: "several-edits-in-a-step", Why: "edits committed together", Min: 0.35, Step: func(_, _ *View, st Step) bool { return len(st) > 1 }},
	{Name: "retag", Why: "ownership changes", Min: 0.15, Step: func(_, _ *View, st Step) bool {
		return slices.ContainsFunc(st, func(e Edit) bool { r, ok := e.(Retag); return ok && len(r.Tags) > 0 })
	}},
	{Name: "untag", Why: "ownership changes", Min: 0.028, Step: func(_, _ *View, st Step) bool {
		return slices.ContainsFunc(st, func(e Edit) bool { r, ok := e.(Retag); return ok && len(r.Tags) == 0 })
	}},
	{Name: "owner-change", Why: "ownership changes", Min: 0.13, Step: func(_, _ *View, st Step) bool { return has[SetOwner](st) }},
	{Name: "user-added", Why: "user churn", Min: 0.22, Step: func(_, _ *View, st Step) bool { return has[AddUser](st) }},
	{Name: "user-deleted", Why: "user churn", Min: 0.12, Step: func(_, _ *View, st Step) bool { return has[DeleteUser](st) }},
	{Name: "user-renamed", Why: "token resolution follows names", Min: 0.19, Step: func(_, _ *View, st Step) bool { return has[RenameUser](st) }},
	{Name: "user-email-changed", Why: "token resolution follows e-mails", Min: 0.15, Step: func(_, _ *View, st Step) bool { return has[SetEmail](st) }},
	{Name: "receiver-flip", Why: "a node's capability form flips", Min: 0.25, Step: func(b, a *View, _ Step) bool {
		for _, n := range a.nodes {
			if o, ok := b.World.Topology.Node(n.ID); ok && b.Eligible(o) != a.Eligible(n) {
				return true
			}
		}

		return false
	}},
	{Name: "flip-move-flip-back", Why: "carried filters across a flip, a move and a flip back", Min: 0.006, Seq: flipMoveFlipBack},
}

func samePolicy(b, a *View) bool {
	return string(b.World.Policy.HuJSON()) == string(a.World.Policy.HuJSON())
}

// flipMoveFlipBack reports whether some node's eligibility flips, then its
// address alone moves, then its eligibility flips back.
func flipMoveFlipBack(vs []*View, _ []Step) bool {
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

			switch {
			case stage == 0 && flip:
				stage = 1
			case stage == 1 && move && !flip:
				stage = 2
			case stage == 2 && flip:
				return true
			}
		}
	}

	return false
}
