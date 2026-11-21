package policymodel

import (
	"slices"

	"pgregory.net/rapid"
)

// Neighbourhoods where findings came from, drawn often enough that what
// lies beside a finding is met too: a via grant to autogroup:internet
// meeting exit nodes and public subnet routes, routes announced unapproved
// inside a via destination, and contested clauses stacked on one node.

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
// nodes is left as it is.
func viaInternetWorld(w *World, who int, d viaInternet) {
	t := &w.Topology

	tag := ownedTag(w.Policy)
	if len(t.Nodes) < 3 || tag < 0 {
		return
	}

	var src []Sel
	for _, k := range viaInternetSrcs[d.src] {
		src = append(src, Sel{Kind: k, I: tag})
	}

	grant := Rule{Src: src, Dst: []Dest{{Sel: Sel{Kind: SelInternet}}}, IP: []IP{{Proto: slices.Index(Protos, viaInternetProtos[d.proto])}}, Via: []int{tag}}
	for i, x := range viaInternetDsts {
		if x >= 0 && (i == d.extra || d.unapproved && x == 1) {
			grant.Dst = append(grant.Dst, Dest{Sel: Sel{Kind: SelPrefix, I: x}})
		}
	}

	w.Policy.Grants, w.Policy.AllowAll = append(w.Policy.Grants, grant), false

	if d.plain {
		w.Policy.ACLs = append(w.Policy.ACLs, Rule{Src: []Sel{{Kind: SelMember}}, Dst: []Dest{{Sel: Sel{Kind: SelInternet}}}})
	}

	nodes := t.Nodes
	first := 1 + who%(len(nodes)-1)
	second := 1 + first%(len(nodes)-1)

	addressed := func(n *Node) {
		if len(n.Addrs()) == 0 {
			n.V4, n.V6 = ownAddr(4, uint64(n.ID)), ownAddr(6, uint64(n.ID))
		}
	}

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
	addressed(r)

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
	addressed(p)

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
// A world of fewer than three nodes is left as it is.
func stackedRouter(w *World, who int) {
	nodes := w.Topology.Nodes
	if len(nodes) < 3 {
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
	w.Policy.AllowAll = false
	w.Policy.ACLs = append(w.Policy.ACLs,
		Rule{Src: []Sel{all}, Dst: []Dest{{Sel: Sel{Kind: SelSelf}}}},
		Rule{Src: []Sel{all}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix, I: publicPrefix6}}}},
		Rule{Src: []Sel{{Kind: SelMember}}, Dst: []Dest{{Sel: Sel{Kind: SelInternet}}}})
}
