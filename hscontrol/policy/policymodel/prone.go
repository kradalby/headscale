package policymodel

import (
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// Neighbourhoods where findings came from, drawn often enough that what
// lies beside a finding is met too: a via grant to autogroup:internet
// meeting exit nodes and public subnet routes, routes announced unapproved
// inside a via destination, contested clauses stacked on one node, and a
// node moving onto an identity that auto-approves a route it announces.

// viaInternetWorlds: one world in so many draws [viaInternetWorld].
const viaInternetWorlds = 6

// viaInternet is how [viaInternetWorld] draws its neighbourhood; the zero
// value is the plainest.
type viaInternet struct {
	// src indexes viaInternetSrcs: who the grant is from.
	src int
	// extra indexes viaInternetDsts: a destination beside the internet.
	extra int
	// family is the router's exit routes: both, IPv4 alone, IPv6 alone.
	family int
	// proto indexes viaInternetProtos.
	proto int
	// ownPublic: the router also serves a public prefix, of the family it
	// does not exit when it exits one.
	ownPublic bool
	// unapproved: the router serves 10.0.0.0/24 and announces 10.0.1.0/24
	// unapproved, both inside 10.0.0.0/16, which the grant names too.
	unapproved bool
	// approvedOnly: the peer is approved for 10.0.0.0/24 it does not
	// announce, which * as a source reads.
	approvedOnly bool
	// peerV6: the peer's public route is 2001:4860::/32, not 8.8.8.0/24.
	peerV6 bool
	// peerTagged: the peer carries the via tag.
	peerTagged bool
	// shared: the router serves the peer's public route too.
	shared bool
	// down: the router is offline; expired: the peer is, untagged.
	down, expired bool
	// plain: members also reach the internet without via.
	plain bool
}

var (
	viaInternetSrcs = [][]SelKind{{SelTagged}, {SelMember, SelTagged}, {SelAll}, {SelTag}, {SelMember}}
	// The extra destinations: 8.8.8.0/24, 10.0.0.0/16, 2001:4860::/32.
	viaInternetDsts   = []int{-1, publicPrefix, 1, publicPrefix6}
	viaInternetProtos = []string{"", "udp", "tcp", "icmp"}
	viaInternetExits  = [][]int{{exit4, exit6}, {exit4}, {exit6}}

	viaInternets = rapid.Custom(func(t *rapid.T) viaInternet {
		return viaInternet{
			src:          index(t, len(viaInternetSrcs), "src"),
			extra:        index(t, len(viaInternetDsts), "extra"),
			family:       index(t, len(viaInternetExits), "family"),
			proto:        index(t, len(viaInternetProtos), "proto"),
			ownPublic:    rapid.Bool().Draw(t, "own-public"),
			unapproved:   rapid.Bool().Draw(t, "unapproved"),
			approvedOnly: rapid.Bool().Draw(t, "approved-only"),
			peerV6:       rapid.Bool().Draw(t, "peer-v6"),
			peerTagged:   rapid.Bool().Draw(t, "peer-tagged"),
			shared:       rapid.Bool().Draw(t, "shared"),
			down:         chance(t, 4, "down"),
			expired:      chance(t, 4, "expired"),
			plain:        chance(t, 3, "plain"),
		}
	})
)

// viaInternetWorld adds to w a grant to autogroup:internet via the first
// tag w's tagOwners defines ([ownedTag]), most often from sources its
// router is among, and makes two nodes of w that router, an exit node, and
// a peer serving a public subnet route. The drawn rules stay, so the
// clauses they meet stack on the same nodes. A world of fewer than three
// nodes is left as it is, and one allowing everything, which another
// shape needs.
func viaInternetWorld(w *World, who int, d viaInternet) {
	t := &w.Topology

	tag := ownedTag(w.Policy)
	if len(t.Nodes) < 3 || tag < 0 || w.Policy.AllowAll {
		return
	}

	var src []Sel
	// Only a tag reads the index: any other kind keeps it zero, or it
	// would be a second selector of that kind to the model.
	for _, k := range viaInternetSrcs[d.src] {
		s := Sel{Kind: k}
		if k == SelTag {
			s.I = tag
		}

		src = append(src, s)
	}

	grant := Rule{Src: src, Dst: []Dest{{Sel: Sel{Kind: SelInternet}}}, IP: []IP{{Proto: slices.Index(Protos, viaInternetProtos[d.proto])}}, Via: []int{tag}}
	for i, x := range viaInternetDsts {
		if x >= 0 && (i == d.extra || d.unapproved && x == 1) {
			grant.Dst = append(grant.Dst, Dest{Sel: Sel{Kind: SelPrefix, I: x}})
		}
	}

	w.Policy.Grants = append(w.Policy.Grants, grant)

	if d.plain {
		w.Policy.ACLs = append(w.Policy.ACLs, Rule{Src: []Sel{{Kind: SelMember}}, Dst: []Dest{{Sel: Sel{Kind: SelInternet}}}})
	}

	nodes := t.Nodes
	first := 1 + who%(len(nodes)-1)
	second := 1 + first%(len(nodes)-1)

	serve := func(n *Node, routes ...int) {
		n.Announced, n.Approved = addRoutes(n.Announced, routes), addRoutes(n.Approved, routes)
	}

	public := publicPrefix
	if d.peerV6 {
		public = publicPrefix6
	}

	// Tagged nodes do not expire.
	r := &nodes[first]
	r.User, r.Tags, r.Offline, r.Expired = 0, []int{tag}, d.down, false
	r.Announced = dropRoutes(r.Announced, []int{exit4, exit6})
	r.Approved = dropRoutes(r.Approved, []int{exit4, exit6})
	serve(r, viaInternetExits[d.family]...)

	if d.ownPublic {
		serve(r, map[int]int{0: publicPrefix, 1: publicPrefix6, 2: publicPrefix}[d.family])
	}

	if d.unapproved {
		serve(r, 0)
		r.Announced = addRoutes(r.Announced, []int{touching})
		r.Approved = dropRoutes(r.Approved, []int{touching})
	}

	if d.shared {
		serve(r, public)
	}

	p := &nodes[second]
	serve(p, public)

	if d.approvedOnly {
		p.Announced, p.Approved = dropRoutes(p.Announced, []int{0}), addRoutes(p.Approved, []int{0})
	}

	switch {
	case d.peerTagged:
		p.User, p.Tags, p.Expired = 0, []int{tag}, false
	case d.expired && !p.Tagged():
		p.Expired = true
	}
}

// stackedRouters: one world in so many draws [stackedRouter].
const stackedRouters = 8

// stackedRouter makes a node of w, of another user than some node with an
// IPv6 address, a router of fd7a:115c:a1e0::/120, which holds that
// address, and of the public 2001:4860::/32; approves 10.0.0.0/24 for a
// third node that does not announce it; and adds rules from * to every
// user's own devices and to the public prefix, and from the members to the
// internet. The router then meets three contested clauses at once: others'
// self rules, * adding approved routes and the internet at subnet routers.
// A world of fewer than three nodes is left as it is, and one allowing
// everything.
func stackedRouter(w *World, who int) {
	nodes := w.Topology.Nodes
	if len(nodes) < 3 || w.Policy.AllowAll {
		return
	}

	r, a, o := &nodes[1+who%(len(nodes)-1)], &nodes[0], &nodes[1+(who+1)%(len(nodes)-1)]

	if !a.V6.IsValid() {
		a.V6 = ownAddr(6, uint64(a.ID))
	}

	users := w.Topology.Users

	r.Tags, r.User = nil, users[0].ID
	if i := slices.IndexFunc(users, func(u User) bool { return u.ID != a.User }); !a.Tagged() && i >= 0 {
		r.User = users[i].ID
	}

	routes := []int{5, publicPrefix6}
	r.Announced, r.Approved = addRoutes(r.Announced, routes), addRoutes(r.Approved, routes)
	o.Announced, o.Approved = dropRoutes(o.Announced, []int{0}), addRoutes(o.Approved, []int{0})

	all := Sel{Kind: SelAll}
	w.Policy.ACLs = append(w.Policy.ACLs,
		Rule{Src: []Sel{all}, Dst: []Dest{{Sel: Sel{Kind: SelSelf}}}},
		Rule{Src: []Sel{all}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix, I: publicPrefix6}}}},
		Rule{Src: []Sel{{Kind: SelMember}}, Dst: []Dest{{Sel: Sel{Kind: SelInternet}}}})
}

// approverScripts: one scenario in so many ends with [approverScript].
const approverScripts = 6

// The ways a node comes to be approved for a route it announces, once the
// auto-approvers start approving it for an identity it does not hold.
const (
	approverRetag    = iota // retagged onto the approving tag
	approverLogin           // a tagged node logs in as the approving user
	approverAnnounce        // it announces another route
	approverAway            // approved by its own identity, retagged off it
	numApproverWays
)

// approverScript is steps on a node of w that announces a route its
// owner's approvers do not approve: it announces the route where it does
// not already; the auto-approvers come to approve the route for a tag the
// node does not carry, or for a user, and every session reads; then the
// node is retagged onto the tag, logs in as the user, or announces a
// further route, and every session reads. Auto-approval runs on the last
// step alone, if at all. Or the other way off an approver
// ([approverAwayScript]). None when no route is left to approve, or w
// holds a token users made ambiguous, which no policy write gets past.
func approverScript(w World, who, way int) []Step {
	v := NewView(w)
	nodes := w.Topology.Nodes

	if len(v.AmbiguousRefs()) > 0 {
		return nil
	}

	all := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		all = append(all, n.ID)
	}

	for k := range nodes {
		n := nodes[(who+k)%len(nodes)]
		if way == approverLogin && !n.Tagged() {
			continue
		}

		if way == approverAway {
			if steps := approverAwayScript(v, n, all); len(steps) > 0 {
				return steps
			}

			continue
		}

		route, ok := unapprovable(v, n)
		if !ok {
			continue
		}

		by, last, ok := approverFor(v, n, way, route)
		if !ok {
			continue
		}

		var steps []Step
		if !slices.Contains(n.Announced, route) {
			steps = append(steps, Step{Edits: []Edit{Announce{n.ID, []int{route}}}})
		}

		return append(steps,
			Step{Edits: []Edit{SetAutoApprovers{approving(w.Policy.AutoApprovers, route, by)}}, Reads: all},
			Step{Edits: []Edit{last}, Reads: all})
	}

	return nil
}

// approving is aa with by approving route too, in route's entry: the
// document keys approvers by route.
func approving(aa AutoApprovers, route int, by Sel) AutoApprovers {
	aa = aa.clone()
	if i := slices.IndexFunc(aa.Routes, func(ra RouteApproval) bool { return ra.Route == route }); i >= 0 {
		aa.Routes[i].By = append(aa.Routes[i].By, by)
	} else {
		aa.Routes = append(aa.Routes, RouteApproval{Route: route, By: []Sel{by}})
	}

	return aa
}

// approverAwayScript is three steps on n: the auto-approvers come to
// approve a route it does not announce for its own identity; it announces
// the route, which they approve; it is retagged onto a tag the policy
// defines that does not approve it, and the approval stays. None when n
// has no identity a token names alone, or no route or tag is left.
func approverAwayScript(v *View, n Node, all []types.NodeID) []Step {
	by, ok := ownIdentity(v, n)
	if !ok {
		return nil
	}

	route := -1

	for _, r := range []int{0, publicPrefix, touching, publicPrefix6, 2} {
		if !slices.Contains(n.Announced, r) && !slices.Contains(n.Approved, r) && !v.Approvable(n, r) {
			route = r

			break
		}
	}

	tag := slices.IndexFunc(allTags, func(t int) bool {
		return v.World.Policy.DefinesTag(t) && !slices.Contains(n.Tags, t) && (by.Kind != SelTag || by.I != t)
	})
	if route < 0 || tag < 0 {
		return nil
	}

	return []Step{
		{Edits: []Edit{SetAutoApprovers{approving(v.World.Policy.AutoApprovers, route, by)}}, Reads: all},
		{Edits: []Edit{Announce{n.ID, []int{route}}}},
		{Edits: []Edit{Retag{n.ID, []int{tag}, 0}}, Reads: all},
	}
}

// unapprovable is a subnet route n announces unapproved, else one it may
// announce, that no approver approves for it.
func unapprovable(v *View, n Node) (int, bool) {
	for _, r := range dropRoutes(n.Announced, n.Approved) {
		if r < numRulePrefixes && !v.Approvable(n, r) {
			return r, true
		}
	}

	for _, r := range []int{0, publicPrefix, touching, publicPrefix6, 2} {
		if !slices.Contains(n.Announced, r) && !slices.Contains(n.Approved, r) && !v.Approvable(n, r) {
			return r, true
		}
	}

	return 0, false
}

// approverFor is the approver of route for n's way onto it, and the edit
// that takes n there: a tag n does not carry, a user other than n's own
// whom a token names alone, or n's own owner for a further announcement.
func approverFor(v *View, n Node, way, route int) (Sel, Edit, bool) {
	switch way {
	case approverRetag:
		for tag := range numTags {
			if !slices.Contains(n.Tags, tag) {
				return Sel{Kind: SelTag, I: tag}, Retag{n.ID, []int{tag}, 0}, true
			}
		}
	case approverLogin:
		for ref := range UserRefs {
			if us := v.RefUsers(ref); len(us) == 1 {
				return Sel{Kind: SelUser, I: ref}, Retag{n.ID, nil, us[0]}, true
			}
		}
	case approverAnnounce:
		by, ok := ownIdentity(v, n)
		if !ok {
			break
		}

		for _, r := range []int{0, publicPrefix, touching, publicPrefix6} {
			if r != route && !slices.Contains(n.Announced, r) {
				return by, Announce{n.ID, []int{r}}, true
			}
		}
	}

	return Sel{}, nil, false
}

// ownIdentity is a selector naming n by what owns it: its first tag, or
// a token naming its user alone.
func ownIdentity(v *View, n Node) (Sel, bool) {
	if n.Tagged() {
		return Sel{Kind: SelTag, I: n.Tags[0]}, true
	}

	for ref := range UserRefs {
		if us := v.RefUsers(ref); len(us) == 1 && us[0] == n.User {
			return Sel{Kind: SelUser, I: ref}, true
		}
	}

	return Sel{}, false
}

// approvingTag is a tag the policy defines that n does not carry and
// that auto-approves a route n announces unapproved: a retag onto it
// approves the route.
func approvingTag(w World, n Node) (int, bool) {
	if len(dropRoutes(n.Announced, n.Approved)) == 0 {
		return 0, false
	}

	for tag := range numTags {
		if !w.Policy.DefinesTag(tag) || slices.Contains(n.Tags, tag) {
			continue
		}

		if after, ok := w.Apply(Retag{n.ID, []int{tag}, 0}).Topology.Node(n.ID); ok && len(after.Approved) > len(n.Approved) {
			return tag, true
		}
	}

	return 0, false
}
