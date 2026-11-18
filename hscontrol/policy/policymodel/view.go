package policymodel

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
)

// View answers, for one world, what headscale's documentation says its
// selectors and user tokens name, which nodes nodeAttrs makes service
// hosts, which routes the auto-approvers approve, and which nodes can be
// sent capability sources. The model applies edits with it and the
// classifier names shapes with it. TestModelMatchesProduction in
// policy/v2 holds its user tokens, their ambiguity, service hosts,
// auto-approval and eligibility to headscale's own on every generated
// world; membership of the other selectors nothing checks.
type View struct {
	World World

	users []User
	nodes []Node

	hosts []types.NodeID
	built bool
}

// NewView indexes w.
func NewView(w World) *View {
	return &View{World: w, users: w.Topology.Users, nodes: w.Topology.Nodes}
}

// chromeOSVM is cut from what * resolves to.
var chromeOSVM = netip.MustParsePrefix("100.115.92.0/23")

// resolves reports whether s, resolved to addresses as a compile resolves
// aliases, holds ip.
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

// holds reports whether one of sels, resolved to addresses, holds an
// address of n.
func (v *View) holds(sels []Sel, n Node) bool {
	return slices.ContainsFunc(n.Addrs(), func(ip netip.Addr) bool {
		return slices.ContainsFunc(sels, func(s Sel) bool { return v.resolves(s, ip) })
	})
}

// RefUsers returns the users UserRefs[ref] names: for a domain every user
// with an e-mail there; else the user with that provider identifier, or
// the one user with that e-mail, or failing that the one with that name.
// Two candidates at a step name nobody.
func (v *View) RefUsers(ref int) []uint {
	ids, _ := v.resolveRef(ref)

	return ids
}

// Ambiguous reports whether UserRefs[ref] matches several users at the
// step that decides it, which a policy write refuses.
func (v *View) Ambiguous(ref int) bool {
	_, ambiguous := v.resolveRef(ref)

	return ambiguous
}

func (v *View) resolveRef(ref int) ([]uint, bool) {
	token := UserRefs[ref]

	if domain, ok := strings.CutPrefix(token, "user:*@"); ok {
		var out []uint

		for _, u := range v.users {
			if _, d, ok := strings.CutLast(u.Email, "@"); ok && strings.EqualFold(d, domain) {
				out = append(out, u.ID)
			}
		}

		return out, false
	}

	token = strings.TrimSuffix(token, "@")

	if i := slices.IndexFunc(v.users, func(u User) bool { return u.OIDC() && u.Provider == token }); i >= 0 {
		return []uint{v.users[i].ID}, false
	}

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
			return ids, false
		}

		if len(ids) > 1 {
			return nil, true
		}
	}

	return nil, false
}

// AmbiguousRefs returns the user tokens the document holds that several
// users answer to: what a policy write refuses.
func (v *View) AmbiguousRefs() []int {
	var out []int

	if len(v.users) == 0 {
		return nil
	}

	for _, ref := range v.World.Policy.userRefs() {
		if v.Ambiguous(ref) {
			out = append(out, ref)
		}
	}

	return out
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

// ServiceHosts is the nodes nodeAttrs makes service hosts. nodeAttrs
// resolve their targets to addresses and grant to every node holding one:
// a node sharing a target's address gets them too, and a node without
// addresses never does.
func (v *View) ServiceHosts() []types.NodeID {
	if !v.built {
		v.built = true

		for _, n := range v.nodes {
			if slices.ContainsFunc(v.World.Policy.NodeAttrs, func(a NodeAttr) bool {
				return slices.Contains(a.Attrs, attrServiceHost) && v.holds(a.Targets, n)
			}) {
				v.hosts = append(v.hosts, n.ID)
			}
		}
	}

	return v.hosts
}

// Eligible reports whether n can be sent capability sources: an official
// client handling only its own addresses.
func (v *View) Eligible(n Node) bool {
	return n.Client == Official && len(n.Announced) == 0 && !slices.Contains(v.ServiceHosts(), n.ID)
}

// Approvable reports whether the auto-approvers approve route r for n: an
// exit route if an exit approver holds one of n's addresses, any other if
// an approver of a prefix holding it does.
func (v *View) Approvable(n Node, r int) bool {
	aa := v.World.Policy.AutoApprovers
	if r == exit4 || r == exit6 {
		return v.holds(aa.Exit, n)
	}

	return slices.ContainsFunc(aa.Routes, func(ra RouteApproval) bool {
		p := Prefixes[ra.Route]

		return p.Bits() <= Prefixes[r].Bits() && p.Overlaps(Prefixes[r]) && v.holds(ra.By, n)
	})
}
