package v2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"sync"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Who sees whom, which of a peer's routes a viewer gets, and via steering,
// from the templates and the role sets instead of from matchers parsed out
// of filter rules. A node's side set holds every atom that puts it on a
// side of some rule as the compile's address sets do: membership, holding
// a member's address or routing over one, a literal's addresses, exit-ness,
// the same-user clique, and the per-owner and per-router facts of self and
// via rules. Two nodes with the same side set see the same peers, so peer
// classes are keyed by it; see [Sides] and [RolePeers].

// family indexes per-family tables: 0 for IPv4, 1 for IPv6.
func family(a netip.Addr) int {
	if a.Is4() {
		return 0
	}

	return 1
}

// litIndex finds the address selectors whose literal holds an address or
// overlaps a route without trying each one.
type litIndex struct {
	byPrefix map[netip.Prefix][]SelectorID
	lens     [2][]int
	sorted   []litPrefix
}

type litPrefix struct {
	p  netip.Prefix
	id SelectorID
}

func (ix *litIndex) add(p netip.Prefix, id SelectorID) {
	if ix.byPrefix == nil {
		ix.byPrefix = map[netip.Prefix][]SelectorID{}
	}

	p = p.Masked()
	if _, ok := ix.byPrefix[p]; !ok {
		f := family(p.Addr())
		if !slices.Contains(ix.lens[f], p.Bits()) {
			ix.lens[f] = append(ix.lens[f], p.Bits())
		}
	}

	ix.byPrefix[p] = append(ix.byPrefix[p], id)
	ix.sorted = append(ix.sorted, litPrefix{p: p, id: id})
}

func (ix *litIndex) finish() {
	slices.SortFunc(ix.sorted, func(a, b litPrefix) int { return a.p.Addr().Compare(b.p.Addr()) })
}

// holding appends the selectors whose literal holds a.
func (ix *litIndex) holding(a netip.Addr, out []SelectorID) []SelectorID {
	for _, l := range ix.lens[family(a)] {
		p, _ := a.Prefix(l)
		out = append(out, ix.byPrefix[p]...)
	}

	return out
}

// overlapping appends the selectors whose literal overlaps route: those
// holding it, and those inside it.
func (ix *litIndex) overlapping(route netip.Prefix, out []SelectorID) []SelectorID {
	route = route.Masked()

	for _, l := range ix.lens[family(route.Addr())] {
		if l <= route.Bits() {
			p, _ := route.Addr().Prefix(l)
			out = append(out, ix.byPrefix[p]...)
		}
	}

	r := netipx.RangeOfPrefix(route)

	i, _ := slices.BinarySearchFunc(ix.sorted, r.From(), func(e litPrefix, a netip.Addr) int { return e.p.Addr().Compare(a) })
	for ; i < len(ix.sorted) && ix.sorted[i].p.Addr().Compare(r.To()) <= 0; i++ {
		if ix.sorted[i].p.Bits() > route.Bits() {
			out = append(out, ix.sorted[i].id)
		}
	}

	return out
}

// prefixLens are the prefix lengths a prefix-keyed index holds, by family,
// so finding the prefixes holding an address probes only those.
type prefixLens [2][]int

func lensOf[V any](groups *graph.Map[netip.Prefix, V]) prefixLens {
	var out prefixLens

	for p := range groups.All() {
		f := family(p.Addr())
		if !slices.Contains(out[f], p.Bits()) {
			out[f] = append(out[f], p.Bits())
		}
	}

	return out
}

// containing calls fn with the entries of groups whose prefix holds a.
func containing[V any](groups *graph.Map[netip.Prefix, V], lens prefixLens, a netip.Addr, fn func(netip.Prefix, V)) {
	for _, l := range lens[family(a)] {
		p, _ := a.Prefix(l)
		if v, ok := groups.Get(p); ok {
			fn(p, v)
		}
	}
}

// grantSides is one grant template as rule sides of atoms: its port rules,
// its capability rule and the companions, which run the other way. A via
// grant keeps what decides its routers.
type grantSides struct {
	port, capg, comp bool

	src, portDst, capDst, compSrc, compDst []Role
	portInet, capInet, compInet            bool

	// self grants: the sources, as atoms of the addresses they hold.
	selfAddr []Role
	selfPort bool

	viaTags     []SelectorID
	viaDst      []SelectorID
	viaInternet bool
	// viaPublic: a destination holds a public address, which shows the
	// sources an exit node carrying a via tag.
	viaPublic bool
	viaPorts  bool
}

// steerGrant is one grant as via steering reads it, in the order the
// compile prepares them: the document's grants, its ACLs whole, then the
// app parts of grants with via.
type steerGrant struct {
	via bool
	key string
	// tags are the via tags, as selectors.
	tags []SelectorID
	src  []Role
	dsts []SelectorID
	// internet is set when the destinations name autogroup:internet;
	// internetAlias when they name it or *; appOnly for a capability
	// without ip, which never reaches the internet.
	internet, internetAlias, appOnly bool
	// lits is what the address destinations resolve to; idents the
	// identity destinations; inetLit whether the grant reaches the
	// internet without counting the members.
	lits    *netipx.IPSet
	idents  []SelectorID
	inetLit bool
}

// sidePlan is what the templates say about sides, built once per
// [Templates].
type sidePlan struct {
	t     *Templates
	table *SelectorTable

	lits litIndex
	// lit and litInet hold each address selector's literal as a set and
	// whether it reaches the internet; nil and false for others.
	lit     []*netipx.IPSet
	litInet []bool

	grants []grantSides
	// selfPort and selfApp hold, per self grant with port rules and with a
	// capability, its sources by address.
	selfPort, selfApp [][]Role
	vias              []int

	steer  []steerGrant
	hasVia bool
	// viaReads are the via grants' tags and identity destinations, sorted:
	// the selectors whose members the via plan reads; viaIdents the
	// destinations alone, whose members' addresses it reads too.
	viaReads, viaIdents []SelectorID
}

func (t *Templates) sidePlan() *sidePlan {
	t.planOnce.Do(func() { t.plan = newSidePlan(t) })

	return t.plan
}

// atomCtx is where a selector's addresses are written, which decides what
// a few selectors mean.
type atomCtx uint8

const (
	// ctxSrc is a rule's SrcIPs: * adds every approved subnet route.
	ctxSrc atomCtx = iota
	// ctxPortDst is a rule's DstPorts: * is written "*", every address.
	ctxPortDst
	// ctxResolve is the alias's resolution, even one with an error.
	ctxResolve
	// ctxResolveOK skips a resolution with an error.
	ctxResolveOK
	// ctxCapDst is a capability's destinations: ctxResolveOK, but * is
	// every address, as in ctxPortDst.
	ctxCapDst
)

var (
	atomAll      = Role{kind: roleAll}
	atomApproved = Role{kind: roleApproved}
	atomExit     = Role{kind: roleExit}
)

func literalRole(id SelectorID) Role { return Role{kind: roleLiteral, value: uint64(id)} }

// atoms appends the atoms selector id puts on a side in ctx.
func (p *sidePlan) atoms(id SelectorID, ctx atomCtx, out []Role) []Role {
	s := p.table.Selector(id)

	switch {
	case s.Kind.HoldsNodes():
		return append(out, SelectorRole(id))
	case s.Kind == SelectorDangerAll, s.Kind == SelectorWildcard && (ctx == ctxPortDst || ctx == ctxCapDst):
		return append(out, atomAll)
	case s.Kind == SelectorSelf, s.Kind == SelectorUnresolvable:
		return out
	}

	l := p.t.literals[id]
	if l.res == nil || (ctx == ctxResolveOK || ctx == ctxCapDst) && l.err != nil {
		return out
	}

	out = append(out, literalRole(id))
	// * as a source takes every approved route, announced or not.
	if s.Kind == SelectorWildcard && ctx == ctxSrc {
		out = append(out, atomApproved)
	}

	return out
}

// inet reports whether ids, written in ctx, reach the internet: only
// literals can, as NewState refuses a node address outside the tailnet.
func (p *sidePlan) inet(ids []SelectorID, ctx atomCtx) bool {
	for _, id := range ids {
		s := p.table.Selector(id)

		switch {
		case s.Kind.HoldsNodes(), s.Kind == SelectorSelf, s.Kind == SelectorUnresolvable:
		case s.Kind == SelectorDangerAll, s.Kind == SelectorWildcard && (ctx == ctxPortDst || ctx == ctxCapDst):
			return true
		default:
			l := p.t.literals[id]
			if l.res != nil && (ctx != ctxResolveOK && ctx != ctxCapDst || l.err == nil) && p.litInet[id] {
				return true
			}
		}
	}

	return false
}

func (p *sidePlan) atomsOf(ids []SelectorID, ctx atomCtx) []Role {
	var out []Role
	for _, id := range ids {
		out = p.atoms(id, ctx, out)
	}

	slices.SortFunc(out, compareRoles)

	return slices.Compact(out)
}

// resolvesOK reports whether id resolves without an error.
func (p *sidePlan) resolvesOK(id SelectorID) bool {
	s := p.table.Selector(id)

	switch {
	case s.Kind.HoldsNodes(), s.Kind == SelectorWildcard, s.Kind == SelectorDangerAll:
		return true
	case s.Kind == SelectorSelf, s.Kind == SelectorUnresolvable:
		return false
	}

	l := p.t.literals[id]

	return l.res != nil && l.err == nil
}

func newSidePlan(t *Templates) *sidePlan {
	table := t.table()
	p := &sidePlan{
		t: t, table: table,
		lit:     make([]*netipx.IPSet, table.Len()),
		litInet: make([]bool, table.Len()),
		grants:  make([]grantSides, len(t.grants)),
	}

	for _, s := range table.sels {
		if s.Kind.HoldsNodes() || s.Kind == SelectorDangerAll {
			continue
		}

		l := t.literals[s.ID]
		if l.res == nil {
			continue
		}

		var b netipx.IPSetBuilder
		for _, pfx := range l.res.Prefixes() {
			b.AddPrefix(pfx)
			p.lits.add(pfx, s.ID)
		}

		p.lit[s.ID], _ = b.IPSet()
		p.litInet[s.ID] = util.HasInternetDestination(p.lit[s.ID])
	}

	p.lits.finish()

	for g, gt := range t.grants {
		if gt.none {
			continue
		}

		gs := &p.grants[g]
		ports := slices.ContainsFunc(gt.ip, func(r ipRule) bool { return len(r.ports) > 0 })

		if gt.kind == grantVia {
			gs.src = p.atomsOf(gt.srcs, ctxSrc)
			gs.viaDst = gt.dsts
			gs.viaInternet = gt.viaInternet
			gs.viaPublic = p.inet(gt.dsts, ctxResolveOK)
			gs.viaPorts = ports

			for _, tag := range gt.via {
				if s, ok := table.Lookup(string(tag)); ok {
					gs.viaTags = append(gs.viaTags, s.ID)
				}
			}

			p.vias = append(p.vias, g)

			continue
		}

		gs.src = p.atomsOf(gt.srcs, ctxSrc)

		if len(gt.dsts) > 0 {
			gs.port = ports
			gs.portDst = p.atomsOf(gt.dsts, ctxPortDst)
			gs.portInet = p.inet(gt.dsts, ctxPortDst)

			if gt.app != nil && slices.ContainsFunc(gt.dsts, p.resolvesOK) {
				gs.capg = true
				gs.capDst = p.atomsOf(gt.dsts, ctxCapDst)
				gs.capInet = p.inet(gt.dsts, ctxCapDst)

				gs.comp = hasCompanion(gt.app)
				if gs.comp {
					gs.compSrc = p.atomsOf(gt.dsts, ctxResolveOK)
					if gt.dstWildcard {
						gs.compSrc = append(gs.compSrc, atomApproved)
						slices.SortFunc(gs.compSrc, compareRoles)
						gs.compSrc = slices.Compact(gs.compSrc)
					}

					gs.compDst = p.atomsOf(gt.srcs, ctxResolve)
					gs.compInet = p.inet(gt.srcs, ctxResolve)
				}
			}
		}

		if gt.kind == grantSelf {
			gs.selfAddr = p.atomsOf(gt.srcs, ctxResolve)
			// "*" names an owner's node by its own addresses only: the
			// approved routes are not in its resolution.
			gs.selfAddr = slices.DeleteFunc(gs.selfAddr, func(r Role) bool { return r == atomApproved })

			if ports {
				gs.selfPort = true
				p.selfPort = append(p.selfPort, gs.selfAddr)
			}

			if gt.app != nil {
				p.selfApp = append(p.selfApp, gs.selfAddr)
			}
		}
	}

	p.steer, p.hasVia = steerGrants(p)

	for _, st := range p.steer {
		if st.via {
			p.viaReads = append(p.viaReads, st.tags...)
			p.viaReads = append(p.viaReads, st.idents...)
			p.viaIdents = append(p.viaIdents, st.idents...)
		}
	}

	slices.Sort(p.viaReads)
	p.viaReads = slices.Compact(p.viaReads)
	slices.Sort(p.viaIdents)
	p.viaIdents = slices.Compact(p.viaIdents)

	return p
}

// hasCompanion reports whether a capability map holds one with a
// companion, which the compile writes the other way.
func hasCompanion(app tailcfg.PeerCapMap) bool {
	return slices.ContainsFunc(companionCaps, func(c companionCap) bool {
		_, ok := app[c.original]

		return ok
	})
}

// steerGrants lists the grants via steering reads, as the compile lists
// them; none without a via grant.
func steerGrants(p *sidePlan) ([]steerGrant, bool) {
	pol := p.t.sel.pol
	if pol == nil || !slices.ContainsFunc(pol.Grants, Grant.HasVia) {
		return nil, false
	}

	lookup := func(a Alias) (SelectorID, bool) {
		if a == nil {
			return 0, false
		}

		s, ok := p.table.Lookup(a.String())

		return s.ID, ok
	}

	var out []steerGrant

	add := func(g Grant) {
		st := steerGrant{via: g.HasVia(), appOnly: len(g.InternetProtocols) == 0 && len(g.App) > 0}

		for _, a := range g.Sources {
			if id, ok := lookup(a); ok {
				st.src = p.atoms(id, ctxResolveOK, st.src)
			}
		}

		slices.SortFunc(st.src, compareRoles)
		st.src = slices.Compact(st.src)

		for _, a := range g.Destinations {
			if ag, ok := a.(*AutoGroup); ok && ag.Is(AutoGroupInternet) {
				st.internet, st.internetAlias = true, true

				continue
			}

			if _, ok := a.(Asterix); ok {
				st.internetAlias = true
			}

			if id, ok := lookup(a); ok {
				st.dsts = append(st.dsts, id)
			}
		}

		var b netipx.IPSetBuilder

		for _, id := range st.dsts {
			switch {
			case p.table.Selector(id).Kind.HoldsNodes():
				st.idents = append(st.idents, id)
			case p.resolvesOK(id):
				if l := p.t.literals[id]; l.res != nil {
					for _, pfx := range l.res.Prefixes() {
						b.AddPrefix(pfx)
					}
				}
			}
		}

		slices.Sort(st.idents)
		st.idents = slices.Compact(st.idents)
		st.lits, _ = b.IPSet()
		st.inetLit = !st.appOnly && (st.internetAlias || util.HasInternetDestination(st.lits))

		if st.via {
			st.key = viaTags(g.Via)

			for _, tag := range g.Via {
				if id, ok := lookup(new(tag)); ok {
					st.tags = append(st.tags, id)
				}
			}
		}

		out = append(out, st)
	}

	for _, g := range pol.Grants {
		add(g)
	}

	for _, acl := range pol.ACLs {
		dsts := make(Aliases, 0, len(acl.Destinations))
		for _, d := range acl.Destinations {
			dsts = append(dsts, d.Alias)
		}

		add(Grant{Sources: acl.Sources, Destinations: dsts})
	}

	for _, g := range pol.Grants {
		if app, ok := g.appPart(); ok {
			add(app)
		}
	}

	return out, true
}

// sideFacts is what one node brings to sides: its own addresses and
// routes, which nodes it holds an address of, and what that makes it.
type sideFacts struct {
	roles RoleSet

	ips []netip.Addr
	// routes are the subnet routes, sorted: sides read them as a set.
	routes []netip.Prefix
	// share holds the nodes holding one of ips, the node itself among them
	// when it has any.
	share []types.NodeID

	addrLit, routeLit []SelectorID
	approvedAddr      bool
	exit              bool
	// exits are the exit routes, which serve a via grant's destinations.
	exits   []netip.Prefix
	clique  uint64
	cliqued bool
	owner   uint
	owned   bool
	// namedPort and namedApp report that a self grant with port rules, and
	// one with a capability, names the node by one of its addresses.
	namedPort, namedApp bool
	targets             []int
	touch               RoleSet
}

func (f *sideFacts) routed() bool { return len(f.routes) > 0 }

// coverAtoms are the atoms of the touch sets of the nodes with an address
// inside one subnet route, router atoms aside, each with how many of them
// hold it, sorted by atom. A join inside the route moves counts; only an
// atom that comes or goes moves the side sets of the routers serving it.
type coverAtoms []atomCount

type atomCount struct {
	r Role
	n int32
}

func (c coverAtoms) has(r Role) bool {
	_, ok := slices.BinarySearchFunc(c, r, func(a atomCount, r Role) int { return compareRoles(a.r, r) })

	return ok
}

// counted reports whether cover counts hold r: a router atom names one
// node, so the routers over it are found through the targeted nodes.
func counted(r Role) bool { return r.kind != roleRouter }

// plus returns c with d added, and whether an atom came or went.
func (c coverAtoms) plus(d map[Role]int32) (coverAtoms, bool) {
	adds := make([]atomCount, 0, len(d))
	for r, n := range d {
		if n != 0 {
			adds = append(adds, atomCount{r: r, n: n})
		}
	}

	if len(adds) == 0 {
		return c, false
	}

	slices.SortFunc(adds, func(a, b atomCount) int { return compareRoles(a.r, b.r) })

	out := make(coverAtoms, 0, len(c)+len(adds))
	moved := false

	for i, j := 0, 0; i < len(c) || j < len(adds); {
		switch {
		case j == len(adds) || i < len(c) && compareRoles(c[i].r, adds[j].r) < 0:
			out = append(out, c[i])
			i++
		case i == len(c) || compareRoles(adds[j].r, c[i].r) < 0:
			// A count below zero is a bug the audit's rebuild reports.
			if adds[j].n > 0 {
				out = append(out, adds[j])
				moved = true
			}

			j++
		default:
			if n := c[i].n + adds[j].n; n > 0 {
				out = append(out, atomCount{r: c[i].r, n: n})
			} else {
				moved = true
			}

			i++
			j++
		}
	}

	return out, moved
}

// Sides holds every node's side set and, per atom, the nodes holding it.
// Updating it recomputes the nodes a change can reach: the changed nodes,
// those sharing an address one of them held or holds, the routers whose
// routes gained or lost an atom, and those holding an address of a node
// whose own roles moved. An endpoint or Hostinfo write that leaves
// addresses, routes, tags and users reaches none.
type Sides struct {
	// sidesState moves only when a side reads a change; a write it does not
	// read keeps it, and the value boxed per commit stays small.
	*sidesState

	from *NodeMap

	// computed counts the side sets the update that built s computed,
	// total those every update up to it did.
	computed, total int
}

type sidesState struct {
	plan      *sidePlan
	roles     Roles
	posts     Postings
	approvals SubnetApprovals

	facts *graph.Map[types.NodeID, *sideFacts]
	sets  *graph.Map[types.NodeID, RoleSet]
	// held groups the nodes by atom.
	held graph.Grouped[types.NodeID, RoleSet, Role]

	// byAddr and routers index the nodes the state was last moved for;
	// since then only writes no index groups by have landed.
	byAddr       graph.Grouped[types.NodeID, *types.Node, netip.Addr]
	routers      graph.Grouped[types.NodeID, *types.Node, netip.Prefix]
	routerLens   prefixLens
	approvedLens prefixLens

	// cover counts, per subnet route a node serves, the atoms of the nodes
	// inside; targeted lists the via routers, whose router atoms it leaves
	// out.
	cover    *graph.Map[netip.Prefix, coverAtoms]
	targeted []types.NodeID

	rules *ruleCache

	// scanned counts the index entries the update that built the state
	// visited counting a route or an approval afresh. It sits here, not in
	// the header boxed at every commit, to keep that box small.
	scanned int
}

// Same reports whether a and b give every node the same side facts and
// sets, from the same templates and approvals.
func (s Sides) Same(o Sides) bool { return s.sidesState == o.sidesState }

// Of returns node id's side set.
func (s Sides) Of(id types.NodeID) (RoleSet, bool) { return s.sets.Get(id) }

// Holders returns the nodes holding atom r, sorted. It is shared.
func (s Sides) Holders(r Role) []types.NodeID {
	ids, _ := s.held.Groups.Get(r)

	return ids
}

// Computed returns how many side sets the update that built s computed,
// and how many every update up to it did: a cell that did not recompute
// keeps both.
func (s Sides) Computed() (int, int) { return s.computed, s.total }

// RouteCover is the cover of every subnet route a node serves, what route
// access and via steering read of the nodes inside a peer's routes. A
// reader keeps it to ask later sides whose routes' cover moved.
type RouteCover struct {
	m *graph.Map[netip.Prefix, coverAtoms]
}

// RouteCover returns the cover of s's routes.
func (s Sides) RouteCover() RouteCover {
	if s.sidesState == nil {
		return RouteCover{}
	}

	return RouteCover{m: s.cover}
}

// RoutersMovedSince returns, sorted, the nodes serving a subnet route whose
// cover gained or lost an atom since c: the routes they offer a viewer can
// differ though neither changed. A count that moved alone moves nothing.
func (s Sides) RoutersMovedSince(c RouteCover) []types.NodeID {
	if s.sidesState == nil || c.m == s.cover {
		return nil
	}

	// TODO(kradalby): overwake/routers-cover: a router whose route's cover
	// gained or lost an atom is named, and every viewer of it woken and its
	// routes rendered again, though route access reads only the atoms a
	// rule's other side names (a node joining a subnet under a policy whose
	// rules never mention what it brings). Safe: a wake and a render that
	// send nothing. Fixing it takes keeping, per route, only the atoms route
	// access reads. TestSinceSoundOverAnyPair counts it ("Routers named, no
	// route moved"). No upstream reference: headscale's own route access.

	var out []types.NodeID

	for _, p := range graph.Changes(c.m, s.cover) {
		was, _ := c.m.Get(p)
		if is, ok := s.cover.Get(p); ok && samePresence(was, is) {
			continue
		}

		ids, _ := s.routers.Groups.Get(p)
		out = append(out, ids...)
	}

	slices.Sort(out)

	return slices.Compact(out)
}

// samePresence reports whether a and b hold the same atoms, whatever their
// counts.
func samePresence(a, b coverAtoms) bool {
	return slices.EqualFunc(a, b, func(x, y atomCount) bool { return x.r == y.r })
}

// ViewerFacts is what route access reads of a viewer beyond its side set
// and its node's addresses and routes: the user it owns a node of, and the
// via grants it routes for. A node without addresses holds neither in its
// side set.
type ViewerFacts struct {
	owner   uint
	owned   bool
	targets string
}

func viewerFacts(f *sideFacts) ViewerFacts {
	if f == nil {
		return ViewerFacts{}
	}

	vf := ViewerFacts{owner: f.owner, owned: f.owned}

	if len(f.targets) > 0 {
		b := make([]byte, 0, 4*len(f.targets))
		for _, g := range f.targets {
			b = binary.BigEndian.AppendUint32(b, uint32(g)) //nolint:gosec // a grant index
		}

		vf.targets = string(b)
	}

	return vf
}

// ViewerFacts returns id's.
func (s Sides) ViewerFacts(id types.NodeID) ViewerFacts {
	if s.sidesState == nil {
		return ViewerFacts{}
	}

	f, _ := s.facts.Get(id)

	return viewerFacts(f)
}

// ViewersMovedSince returns, sorted, the nodes whose side set or
// [ViewerFacts] differ between old and s: the routes every peer offers them
// can.
func (s Sides) ViewersMovedSince(old Sides) []types.NodeID {
	if s.sidesState == nil || old.sidesState == nil || s.sidesState == old.sidesState {
		return nil
	}

	// TODO(kradalby): overwake/route-viewers: a node whose side set moved is
	// woken, and every routed peer rendered again for it, though a side set
	// moving rarely moves a route a peer offers it (a member joining a group
	// no rule reaching a route names). Safe: a wake and a render that send
	// nothing; it is most of the sessions woken for nothing between
	// neighbouring commits. Fixing it takes comparing the side atoms route
	// access reads, or route access itself, for the viewer. Counted by
	// TestSinceSoundOverAnyPair ("RouteViewers named, no route moved") and
	// by the woken-with-nothing-to-send ceiling of
	// TestSessionsFollowGeneratedScenarios. No upstream reference:
	// headscale's own route access.

	out := graph.Changes(old.sets, s.sets)

	for _, id := range graph.Changes(old.facts, s.facts) {
		was, _ := old.facts.Get(id)
		is, _ := s.facts.Get(id)

		if viewerFacts(was) != viewerFacts(is) {
			out = append(out, id)
		}
	}

	slices.Sort(out)

	return slices.Compact(out)
}

// RouteRules is what the routes a viewer is sent read besides the viewer,
// the peer and the cover of the peer's routes: the rules and the via plan.
// The rules are the templates' and read no membership; the cover and side
// sets are followed apart.
type RouteRules struct {
	plan *sidePlan
	via  *ViaPlan
}

// RouteRules returns s's, with via the plan steering reads.
func (s Sides) RouteRules(via *ViaPlan) RouteRules {
	if s.sidesState == nil {
		return RouteRules{via: via}
	}

	return RouteRules{plan: s.plan, via: via}
}

// Same reports whether r and o route every viewer alike, given the same
// viewer, peer and cover: the same rules, by content, as a document edit
// builds new ones even where it changes none.
func (r RouteRules) Same(o RouteRules) bool {
	return r.plan.sameRoutes(o.plan) && r.via.sameRoutes(o.via)
}

// sameRoutes reports whether p and o hold the same rules for route access
// and via steering: each grant's sides, the self and via grants, the
// steering grants and the literals.
func (p *sidePlan) sameRoutes(o *sidePlan) bool {
	if p == o {
		return true
	}

	if p == nil || o == nil || p.table != o.table {
		return false
	}

	return reflect.DeepEqual(p.grants, o.grants) && reflect.DeepEqual(p.selfPort, o.selfPort) &&
		reflect.DeepEqual(p.selfApp, o.selfApp) &&
		slices.Equal(p.vias, o.vias) && p.hasVia == o.hasVia && reflect.DeepEqual(p.steer, o.steer) &&
		slices.Equal(p.viaReads, o.viaReads) && slices.Equal(p.viaIdents, o.viaIdents) &&
		reflect.DeepEqual(p.lit, o.lit) && slices.Equal(p.litInet, o.litInet) &&
		reflect.DeepEqual(p.t.literals, o.t.literals)
}

// sameRoutes reports whether v and o steer alike: the same rules and the
// same scopes and destinations.
func (v *ViaPlan) sameRoutes(o *ViaPlan) bool {
	if v == o {
		return true
	}

	return v != nil && o != nil && v.plan.sameRoutes(o.plan) && v.sameContent(o)
}

// UpdateSides returns the sides of nodes under t, with roles and posts the
// membership of nodes and approvals their approved routes, recomputing from
// prev only what changed.
func UpdateSides(prev Sides, t *Templates, roles Roles, posts Postings, approvals SubnetApprovals, nodes *NodeMap) Sides {
	plan := t.sidePlan()

	if prev.sidesState == nil || prev.plan != plan || prev.from == nil || prev.roles.users == nil || prev.roles.users.table != roles.users.table {
		next := buildSides(plan, roles, posts, approvals, nodes)
		next.total += prev.total

		return next
	}

	dirty := sideChanges(prev, roles, nodes)
	approvalsMoved := !prev.approvals.Same(approvals)

	if len(dirty) == 0 && !approvalsMoved {
		// Roles, postings and approvals that moved without moving a side
		// read nothing new: the state keeps the ones it was built from.
		return Sides{sidesState: prev.sidesState, from: nodes, total: prev.total}
	}

	st := *prev.sidesState
	st.roles, st.posts, st.approvals, st.scanned = roles, posts, approvals, 0

	u := &sidesUpdate{prev: prev, next: Sides{sidesState: &st, from: nodes, total: prev.total}}

	u.reindex(approvalsMoved)

	l1 := u.reached(dirty, approvalsMoved)
	ids := slices.Sorted(maps.Keys(l1))
	u.refreshFacts(ids)
	moved := u.moveCounts(ids)
	retargeted, routerMoved := u.retarget(ids, moved)
	l3 := u.touchers(l1, slices.Concat(ids, retargeted), moved, routerMoved)

	u.refreshSets(l3)

	return u.next
}

// sidesUpdate is one incremental update of sides from prev.
type sidesUpdate struct {
	prev Sides
	next Sides
}

// sideChanges returns the nodes whose own facts or role sets moved since
// prev.
func sideChanges(prev Sides, roles Roles, nodes *NodeMap) []types.NodeID {
	var dirty []types.NodeID

	for _, id := range graph.Changes(prev.from, nodes) {
		old, had := prev.from.Get(id)
		cur, has := nodes.Get(id)

		if had && has && sameSideFacts(old, cur) {
			continue
		}

		dirty = append(dirty, id)
	}

	if !prev.roles.Same(roles) {
		dirty = append(dirty, graph.Changes(prev.roles.sets, roles.sets)...)
	}

	return dirty
}

func (u *sidesUpdate) reindex(approvalsMoved bool) {
	n := &u.next

	// The indexes' groups still describe prev.from: no write between moved
	// what they group by. Diffing from it keeps inside the edit log.
	byAddr, routers := u.prev.byAddr, u.prev.routers
	byAddr.In, routers.In = u.prev.from, u.prev.from

	n.byAddr = graph.GroupBy(byAddr, n.from, ipsOf, sameIPs)
	n.routers = graph.GroupBy(routers, n.from, routesOf, sameRoutes)

	if n.routers.Groups != u.prev.routers.Groups {
		n.routerLens = lensOf(n.routers.Groups)
	}

	if approvalsMoved {
		n.approvedLens = lensOf(n.approvals.byRoute.Groups)
	}
}

// sharing adds to set the nodes holding ip.
func (u *sidesUpdate) sharing(ip netip.Addr, set map[types.NodeID]struct{}) {
	ids, _ := u.next.byAddr.Groups.Get(ip)
	for _, id := range ids {
		set[id] = struct{}{}
	}
}

// serving adds to set the nodes routing over ip.
func (u *sidesUpdate) serving(ip netip.Addr, set map[types.NodeID]struct{}) {
	containing(u.next.routers.Groups, u.next.routerLens, ip, func(_ netip.Prefix, ids []types.NodeID) {
		for _, id := range ids {
			set[id] = struct{}{}
		}
	})
}

// reached returns the nodes whose facts dirty can move: the dirty nodes,
// those holding an address one of them held or holds, and those inside an
// approved route that came or went. A router over such an address keeps
// its facts: what it reads of the nodes inside is counted, see moveCounts.
func (u *sidesUpdate) reached(dirty []types.NodeID, approvalsMoved bool) map[types.NodeID]struct{} {
	l1 := map[types.NodeID]struct{}{}

	for _, id := range dirty {
		l1[id] = struct{}{}

		if f, ok := u.prev.facts.Get(id); ok {
			for _, ip := range f.ips {
				u.sharing(ip, l1)
			}
		}

		if n, ok := u.next.from.Get(id); ok {
			for _, ip := range n.IPs() {
				u.sharing(ip, l1)
			}
		}
	}

	if approvalsMoved {
		was, is := u.prev.approvals.byRoute.Groups, u.next.approvals.byRoute.Groups

		for _, p := range graph.Changes(was, is) {
			_, had := was.Get(p)
			if _, has := is.Get(p); had != has {
				u.next.scanned += u.next.nodesIn(p, func(id types.NodeID) { l1[id] = struct{}{} })
			}
		}
	}

	return l1
}

// refreshFacts recomputes the facts of l1. A router's targets read the
// cover counts, which moveCounts brings up to date after it: retarget
// computes them again.
func (u *sidesUpdate) refreshFacts(l1 []types.NodeID) {
	facts := u.prev.facts.Edit()

	for _, id := range l1 {
		n, ok := u.next.from.Get(id)
		if !ok {
			facts.Delete(id)

			continue
		}

		facts.Set(id, u.next.factsOf(id, n))
	}

	u.next.facts = facts.Done()
}

// moveCounts brings the cover counts up to date with the facts of l1 and
// counts afresh the routes that came. It returns the routes whose atoms
// came or went: the side sets of the routers serving them read those.
func (u *sidesUpdate) moveCounts(l1 []types.NodeID) map[netip.Prefix]struct{} {
	n := &u.next
	e := u.prev.cover.Edit()
	moved := map[netip.Prefix]struct{}{}

	var fresh map[netip.Prefix]struct{}

	if n.routers.Groups != u.prev.routers.Groups {
		fresh = map[netip.Prefix]struct{}{}

		for _, p := range graph.Changes(u.prev.routers.Groups, n.routers.Groups) {
			_, had := u.prev.cover.Get(p)
			_, has := n.routers.Groups.Get(p)

			switch {
			case had && !has:
				e.Delete(p)
			case has && !had:
				fresh[p] = struct{}{}
			}
		}
	}

	var deltas map[netip.Prefix]map[Role]int32

	bump := func(f *sideFacts, d int32) {
		for _, ip := range f.ips {
			containing(n.routers.Groups, n.routerLens, ip, func(p netip.Prefix, _ []types.NodeID) {
				if _, ok := fresh[p]; ok {
					return
				}

				if deltas == nil {
					deltas = map[netip.Prefix]map[Role]int32{}
				}

				dp := deltas[p]
				if dp == nil {
					dp = map[Role]int32{}
					deltas[p] = dp
				}

				for r := range f.touch.All() {
					if counted(r) {
						dp[r] += d
					}
				}
			})
		}
	}

	for _, id := range l1 {
		old, _ := u.prev.facts.Get(id)
		cur, _ := n.facts.Get(id)

		if old != nil && cur != nil && old.touch == cur.touch && slices.Equal(old.ips, cur.ips) {
			continue
		}

		if old != nil {
			bump(old, -1)
		}

		if cur != nil {
			bump(cur, 1)
		}
	}

	for p, d := range deltas {
		c, _ := e.Get(p)

		c, atomsMoved := c.plus(d)
		if atomsMoved {
			moved[p] = struct{}{}
		}

		e.Set(p, c)
	}

	for p := range fresh {
		c, visited := n.coverOf(p)
		n.scanned += visited

		e.Set(p, c)
		moved[p] = struct{}{}
	}

	n.cover = e.Done()

	return moved
}

// retarget recomputes the via targets of the routers in l1 and of those
// serving a route in moved, which read the counts. It returns those whose
// facts it moved, and the nodes whose router atom came, went or moved with
// their addresses.
func (u *sidesUpdate) retarget(l1 []types.NodeID, moved map[netip.Prefix]struct{}) ([]types.NodeID, []types.NodeID) {
	n := &u.next

	var retargeted []types.NodeID

	if len(n.plan.vias) > 0 {
		var ids []types.NodeID

		for _, id := range l1 {
			if f, ok := n.facts.Get(id); ok && f.routed() {
				ids = append(ids, id)
			}
		}

		for p := range moved {
			rs, _ := n.routers.Groups.Get(p)
			ids = append(ids, rs...)
		}

		slices.Sort(ids)

		e := n.facts.Edit()

		for _, id := range slices.Compact(ids) {
			f, ok := e.Get(id)
			if !ok {
				continue
			}

			if t := n.targetsOf(f); !slices.Equal(t, f.targets) {
				g := *f
				g.targets = t
				g.touch = n.touchOf(id, &g)
				e.Set(id, &g)

				retargeted = append(retargeted, id)
			}
		}

		n.facts = e.Done()
	}

	var routerMoved []types.NodeID

	for _, id := range slices.Concat(l1, retargeted) {
		old, _ := u.prev.facts.Get(id)
		cur, _ := n.facts.Get(id)

		was := old != nil && len(old.targets) > 0
		is := cur != nil && len(cur.targets) > 0

		if was != is || was && !slices.Equal(old.ips, cur.ips) {
			routerMoved = append(routerMoved, id)
		}
	}

	if len(routerMoved) > 0 {
		slices.Sort(routerMoved)
		routerMoved = slices.Compact(routerMoved)

		targeted := slices.DeleteFunc(slices.Clone(u.prev.targeted), func(id types.NodeID) bool {
			_, found := slices.BinarySearch(routerMoved, id)

			return found
		})

		for _, id := range routerMoved {
			if f, ok := n.facts.Get(id); ok && len(f.targets) > 0 {
				targeted = append(targeted, id)
			}
		}

		slices.Sort(targeted)
		n.targeted = targeted
	}

	return retargeted, routerMoved
}

// touchers returns l1 with the nodes whose side sets read what moved: those
// holding an address of a node of refreshed whose touch set moved, the
// routers serving a route whose atoms moved, and the routers over an
// address of a node whose router atom moved. A node that left an address is
// dirty, and those holding it are in l1 already.
func (u *sidesUpdate) touchers(l1 map[types.NodeID]struct{}, refreshed []types.NodeID, moved map[netip.Prefix]struct{}, routerMoved []types.NodeID) map[types.NodeID]struct{} {
	l3 := maps.Clone(l1)

	for _, id := range refreshed {
		old, _ := u.prev.facts.Get(id)

		cur, ok := u.next.facts.Get(id)
		if !ok || old != nil && old.touch == cur.touch {
			continue
		}

		l3[id] = struct{}{}

		for _, ip := range cur.ips {
			u.sharing(ip, l3)
		}
	}

	for p := range moved {
		ids, _ := u.next.routers.Groups.Get(p)
		for _, id := range ids {
			l3[id] = struct{}{}
		}
	}

	for _, id := range routerMoved {
		for _, f := range []*sideFacts{mustFacts(u.prev.facts, id), mustFacts(u.next.facts, id)} {
			if f == nil {
				continue
			}

			for _, ip := range f.ips {
				u.serving(ip, l3)
			}
		}
	}

	return l3
}

// refreshSets recomputes the side sets of l3 and the holders of what moved.
func (u *sidesUpdate) refreshSets(l3 map[types.NodeID]struct{}) {
	sets := u.prev.sets.Edit()

	for _, id := range slices.Sorted(maps.Keys(l3)) {
		f, ok := u.next.facts.Get(id)
		if !ok {
			sets.Delete(id)

			continue
		}

		sets.Set(id, u.next.setOf(id, f))
		u.next.computed++
	}

	u.next.sets = sets.Done()
	u.next.held = graph.GroupBy(u.prev.held, u.next.sets, rolesOfSet, graph.Same[RoleSet])
	u.next.total += u.next.computed
}

func mustFacts(m *graph.Map[types.NodeID, *sideFacts], id types.NodeID) *sideFacts {
	f, _ := m.Get(id)

	return f
}

// buildSides computes every node's sides from scratch.
func buildSides(plan *sidePlan, roles Roles, posts Postings, approvals SubnetApprovals, nodes *NodeMap) Sides {
	s := Sides{sidesState: &sidesState{plan: plan, roles: roles, posts: posts, approvals: approvals, rules: &ruleCache{}}, from: nodes}

	s.byAddr = graph.GroupBy(graph.Grouped[types.NodeID, *types.Node, netip.Addr]{}, nodes, ipsOf, sameIPs)
	s.routers = graph.GroupBy(graph.Grouped[types.NodeID, *types.Node, netip.Prefix]{}, nodes, routesOf, sameRoutes)
	s.routerLens = lensOf(s.routers.Groups)
	s.approvedLens = lensOf(approvals.byRoute.Groups)

	facts := make(map[types.NodeID]*sideFacts, nodes.Len())
	for id, n := range nodes.All() {
		facts[id] = s.factsOf(id, n)
	}

	s.facts = graph.NewMap(graph.Same[*sideFacts], facts)

	cover := make(map[netip.Prefix]coverAtoms, s.routers.Groups.Len())
	for p := range s.routers.Groups.All() {
		c, visited := s.coverOf(p)
		cover[p] = c
		s.scanned += visited
	}

	s.cover = graph.NewMap(slices.Equal[coverAtoms], cover)

	// The targets factsOf gave read no counts; the facts are not yet
	// published, so they are set in place.
	for id, f := range facts {
		if !f.routed() || len(plan.vias) == 0 {
			continue
		}

		if t := s.targetsOf(f); !slices.Equal(t, f.targets) {
			f.targets = t
			f.touch = s.touchOf(id, f)
		}
	}

	for id, f := range facts {
		if len(f.targets) > 0 {
			s.targeted = append(s.targeted, id)
		}
	}

	slices.Sort(s.targeted)

	sets := make(map[types.NodeID]RoleSet, len(facts))
	for id, f := range facts {
		sets[id] = s.setOf(id, f)
	}

	s.sets = graph.NewMap(graph.Same[RoleSet], sets)
	s.held = graph.GroupBy(graph.Grouped[types.NodeID, RoleSet, Role]{}, s.sets, rolesOfSet, graph.Same[RoleSet])
	s.computed = len(sets)
	s.total = s.computed

	return s
}

func rolesOfSet(_ types.NodeID, rs RoleSet) []Role { return rs.Roles() }

func ipsOf(_ types.NodeID, n *types.Node) []netip.Addr { return n.IPs() }

func sameIPs(a, b *types.Node) bool { return slices.Equal(a.IPs(), b.IPs()) }

func routesOf(_ types.NodeID, n *types.Node) []netip.Prefix { return n.SubnetRoutes() }

func sameRoutes(a, b *types.Node) bool {
	return a.SameRouteFacts(b) || slices.Equal(a.SubnetRoutes(), b.SubnetRoutes())
}

// sameSideFacts reports whether a and b give the same own facts to sides;
// their roles are compared apart, through the role sets. Routes are a set,
// as [types.NodeView.HasPolicyChange] compares them.
func sameSideFacts(a, b *types.Node) bool {
	if !sameAddr(a.IPv4, b.IPv4) || !sameAddr(a.IPv6, b.IPv6) || a.IsTagged() != b.IsTagged() ||
		(a.UserID == nil) != (b.UserID == nil) || a.UserID != nil && *a.UserID != *b.UserID {
		return false
	}

	if a.SameRouteFacts(b) {
		return true
	}

	return slices.Equal(sortedRoutes(a), sortedRoutes(b)) && slices.Equal(a.ExitRoutes(), b.ExitRoutes())
}

// sortedRoutes returns n's subnet routes, sorted and without repeats.
func sortedRoutes(n *types.Node) []netip.Prefix {
	routes := n.SubnetRoutes()
	slices.SortFunc(routes, netip.Prefix.Compare)

	return slices.Compact(routes)
}

// sameAddr compares two optional addresses without building IPs' slices,
// on the path every node write takes.
func sameAddr(a, b *netip.Addr) bool { return a == b || a != nil && b != nil && *a == *b }

// nodesIn calls fn with every node with an address inside p and returns
// how many index entries it visited. A small prefix is enumerated; a large
// one costs a pass over the addresses held, which a route that comes, an
// approval that comes or goes and the audit pay: a join inside a route
// moves its counts instead.
func (s Sides) nodesIn(p netip.Prefix, fn func(types.NodeID)) int {
	p = p.Masked()
	visited := 0

	if p.Addr().BitLen()-p.Bits() <= 12 {
		for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
			visited++

			ids, _ := s.byAddr.Groups.Get(a)
			for _, id := range ids {
				fn(id)
			}
		}

		return visited
	}

	for a, ids := range s.byAddr.Groups.All() {
		visited++

		if p.Contains(a) {
			for _, id := range ids {
				fn(id)
			}
		}
	}

	return visited
}

// coverOf counts the atoms of the nodes with an address inside p, and
// returns how many index entries it visited.
func (s Sides) coverOf(p netip.Prefix) (coverAtoms, int) {
	d := map[Role]int32{}

	visited := s.nodesIn(p, func(id types.NodeID) {
		if f, ok := s.facts.Get(id); ok {
			for r := range f.touch.All() {
				if counted(r) {
					d[r]++
				}
			}
		}
	})

	c, _ := coverAtoms(nil).plus(d)

	return c, visited
}

// coveredBy reports whether a node with an address inside route holds r,
// no router atom, in its touch set: counted for a route a node serves,
// scanned for another.
func (s Sides) coveredBy(route netip.Prefix, r Role) bool {
	if c, ok := s.cover.Get(route); ok {
		return c.has(r)
	}

	found := false

	s.nodesIn(route, func(id types.NodeID) {
		if f, ok := s.facts.Get(id); ok && f.touch.Has(r) {
			found = true
		}
	})

	return found
}

// factsOf computes n's facts against the indexes and roles of s. A
// router's targets read the cover counts as s holds them.
func (s Sides) factsOf(id types.NodeID, n *types.Node) *sideFacts {
	p := s.plan
	rs, _ := s.roles.Of(id)

	f := &sideFacts{roles: rs, ips: n.IPs(), routes: sortedRoutes(n), exit: n.IsExitNode(), exits: n.ExitRoutes()}

	if !n.IsTagged() && n.UserID != nil {
		f.clique, f.cliqued = uint64(*n.UserID), true
	}

	for r := range rs.All() {
		if uid, ok := r.Owner(); ok {
			f.owner, f.owned = uid, true
		}
	}

	for _, ip := range f.ips {
		ids, _ := s.byAddr.Groups.Get(ip)
		f.share = append(f.share, ids...)
		f.addrLit = p.lits.holding(ip, f.addrLit)

		if !f.approvedAddr {
			containing(s.approvals.byRoute.Groups, s.approvedLens, ip, func(netip.Prefix, []types.NodeID) { f.approvedAddr = true })
		}
	}

	slices.Sort(f.share)
	f.share = slices.Compact(f.share)

	for _, r := range f.routes {
		f.routeLit = p.lits.overlapping(r, f.routeLit)
	}

	slices.Sort(f.addrLit)
	f.addrLit = slices.Compact(f.addrLit)
	slices.Sort(f.routeLit)
	f.routeLit = slices.Compact(f.routeLit)

	if f.owned {
		f.namedPort = s.namedBy(f, p.selfPort)
		f.namedApp = s.namedBy(f, p.selfApp)
	}

	f.targets = s.targetsOf(f)
	f.touch = s.touchOf(id, f)

	return f
}

// touchOf is what the node with facts f puts on the sides of the nodes
// holding one of its addresses or routing over one.
func (s Sides) touchOf(id types.NodeID, f *sideFacts) RoleSet {
	touch := f.roles.Roles()

	if f.owned {
		if f.namedPort {
			touch = append(touch, Role{kind: roleNamedPort, value: uint64(f.owner)})
		}

		if f.namedApp {
			touch = append(touch, Role{kind: roleNamedApp, value: uint64(f.owner)})
		}
	}

	if len(f.targets) > 0 {
		touch = append(touch, Role{kind: roleRouter, value: uint64(id)})
	}

	return newRoleSet(s.plan.table.id, touch)
}

// namedBy reports whether a self grant with sources among grants names f's
// node by one of its own addresses, as the compile picks the owner's nodes
// a self rule's source holds.
func (s Sides) namedBy(f *sideFacts, grants [][]Role) bool {
	for _, srcs := range grants {
		for _, a := range srcs {
			switch a.kind { //nolint:exhaustive // only these atoms name an address
			case roleAll:
				return true
			case roleLiteral:
				if _, ok := slices.BinarySearch(f.addrLit, SelectorID(a.value)); ok { //nolint:gosec // a literal role holds a SelectorID
					return true
				}
			case roleSelector:
				for _, m := range f.share {
					if rs, ok := s.roles.Of(m); ok && rs.Has(a) {
						return true
					}
				}
			}
		}
	}

	return false
}

// targetsOf returns the via grants f's node routes for: it carries one of
// the via tags and a subnet route overlaps a destination, or it is an
// exit node and the grant names the internet or a public address.
func (s Sides) targetsOf(f *sideFacts) []int {
	var out []int

	for _, g := range s.plan.vias {
		gs := &s.plan.grants[g]

		if !slices.ContainsFunc(gs.viaTags, func(id SelectorID) bool { return f.roles.Has(SelectorRole(id)) }) {
			continue
		}

		if (gs.viaInternet || gs.viaPublic) && f.exit || s.routesOverlap(f, gs.viaDst) {
			out = append(out, g)
		}
	}

	return out
}

// routesOverlap reports whether one of f's subnet routes overlaps what one
// of dsts resolves to, as a via grant's destinations do.
func (s Sides) routesOverlap(f *sideFacts, dsts []SelectorID) bool {
	if !f.routed() {
		return false
	}

	for _, id := range dsts {
		sel := s.plan.table.Selector(id)

		switch {
		case sel.Kind.HoldsNodes():
			for _, r := range f.routes {
				if c, _ := s.cover.Get(r); c.has(SelectorRole(id)) {
					return true
				}
			}
		case s.plan.resolvesOK(id) && s.plan.lit[id] != nil:
			if _, ok := slices.BinarySearch(f.routeLit, id); ok {
				return true
			}
		}
	}

	return false
}

// touchedBy returns, sorted, the atoms of the touch sets of the nodes f's
// node holds an address of or routes over.
func (s Sides) touchedBy(f *sideFacts) []Role {
	shared := make([]*sideFacts, 0, len(f.share))
	size := 0

	for _, m := range f.share {
		if mf, ok := s.facts.Get(m); ok {
			shared = append(shared, mf)
			size += mf.touch.Len()
		}
	}

	roles := make([]Role, 0, size)
	for _, mf := range shared {
		roles = slices.AppendSeq(roles, mf.touch.All())
	}

	for _, r := range f.routes {
		c, _ := s.cover.Get(r)
		for _, a := range c {
			roles = append(roles, a.r)
		}

		for _, m := range s.targeted {
			if mf, ok := s.facts.Get(m); ok && slices.ContainsFunc(mf.ips, r.Contains) {
				roles = append(roles, Role{kind: roleRouter, value: uint64(m)})
			}
		}
	}

	slices.SortFunc(roles, compareRoles)

	return slices.Compact(roles)
}

// setOf returns node id's side set from its facts, those of the nodes it
// holds an address of, and the counts of the routes it serves.
func (s Sides) setOf(id types.NodeID, f *sideFacts) RoleSet {
	touch := s.touchedBy(f)
	// Room for the own and composite atoms below, so they need no regrowth.
	roles := append(make([]Role, 0, len(touch)+len(f.addrLit)+len(f.routeLit)+8), touch...)

	has := func(r Role) bool {
		_, ok := slices.BinarySearchFunc(touch, r, compareRoles)

		return ok
	}

	for _, lit := range slices.Concat(f.addrLit, f.routeLit) {
		roles = append(roles, literalRole(lit))
	}

	roles = append(roles, atomAll)

	if f.approvedAddr || f.routed() {
		roles = append(roles, atomApproved)
	}

	if f.exit {
		roles = append(roles, atomExit)
	}

	if f.cliqued {
		roles = append(roles, Role{kind: roleClique, value: f.clique})
	}

	if f.owned {
		u := uint64(f.owner)
		named := has(Role{kind: roleNamedPort, value: u})
		namedApp := has(Role{kind: roleNamedApp, value: u})
		owner := has(OwnerRole(f.owner))

		if named || namedApp {
			roles = append(roles, Role{kind: roleHeldNamed, value: u})
		}

		if owner {
			roles = append(roles, Role{kind: roleHeldOwner, value: u})
		}
	}

	if len(f.targets) > 0 {
		held := slices.Clone(roles)
		slices.SortFunc(held, compareRoles)

		onSrc := false

		for _, g := range f.targets {
			roles = append(roles, Role{kind: roleViaSeen, value: uint64(g)}) //nolint:gosec // a grant index

			onSrc = onSrc || slices.ContainsFunc(s.plan.grants[g].src, func(r Role) bool {
				_, ok := slices.BinarySearchFunc(held, r, compareRoles)

				return ok
			})
		}

		if onSrc {
			roles = append(roles, Role{kind: roleRouterOnSrc, value: uint64(id)})
		}
	}

	return newRoleSet(s.plan.table.id, roles)
}

// sideAdjacency says, for each atom, which atoms' holders its holders see:
// a rule links its two sides both ways, and a capability to the internet
// shows its sources to exit nodes. The per-user and per-router links of
// self and via rules hold between atoms of the same value.
type sideAdjacency struct {
	plan  *sidePlan
	links map[Role][]Role
	// readers is links inverted: whose view reads an atom's holders.
	readers map[Role][]Role
}

func newSideAdjacency(plan *sidePlan) *sideAdjacency {
	a := &sideAdjacency{plan: plan, links: map[Role][]Role{}, readers: map[Role][]Role{}}

	see := func(from, to []Role) {
		for _, f := range from {
			for _, t := range to {
				a.links[f] = append(a.links[f], t)
				a.readers[t] = append(a.readers[t], f)
			}
		}
	}

	both := func(x, y []Role) {
		see(x, y)
		see(y, x)
	}

	exit := []Role{atomExit}

	for g := range plan.grants {
		gs := &plan.grants[g]

		if gs.port {
			dst := gs.portDst
			if gs.portInet {
				dst = append(slices.Clone(dst), atomExit)
			}

			both(gs.src, dst)
		}

		if gs.capg {
			both(gs.src, gs.capDst)

			if gs.capInet {
				see(exit, gs.src)
			}
		}

		if gs.comp {
			both(gs.compSrc, gs.compDst)

			if gs.compInet {
				see(exit, gs.compSrc)
			}
		}
	}

	for _, g := range plan.vias {
		both(plan.grants[g].src, []Role{{kind: roleViaSeen, value: uint64(g)}}) //nolint:gosec // a grant index
	}

	for r, ls := range a.links {
		slices.SortFunc(ls, compareRoles)
		a.links[r] = slices.Compact(ls)
	}

	for r, ls := range a.readers {
		slices.SortFunc(ls, compareRoles)
		a.readers[r] = slices.Compact(ls)
	}

	return a
}

// pairs returns the atoms linked to r by value: a user's own atoms, a
// router's.
func pairs(r Role) []Role {
	v := r.value

	switch r.kind { //nolint:exhaustive // only per-user and per-router atoms pair by value
	case roleClique:
		return []Role{r}
	case roleOwner:
		return []Role{{kind: roleHeldNamed, value: v}}
	case roleHeldNamed:
		return []Role{{kind: roleOwner, value: v}}
	case roleHeldOwner:
		return []Role{{kind: roleNamedPort, value: v}, {kind: roleNamedApp, value: v}}
	case roleNamedPort:
		return []Role{{kind: roleHeldOwner, value: v}}
	case roleNamedApp:
		return []Role{{kind: roleHeldOwner, value: v}}
	case roleRouter:
		return []Role{{kind: roleRouterOnSrc, value: v}}
	case roleRouterOnSrc:
		return []Role{{kind: roleRouter, value: v}}
	}

	return nil
}

// linksOf returns the atoms whose holders r's holders see.
func (a *sideAdjacency) linksOf(r Role) []Role { return slices.Concat(a.links[r], pairs(r)) }

// readersOf returns the atoms whose holders see r's holders.
func (a *sideAdjacency) readersOf(r Role) []Role { return slices.Concat(a.readers[r], pairs(r)) }

// keyedClasses are peer classes keyed by side set: a class's view is the
// union, over its atoms, of what each atom's holders see.
type keyedClasses struct {
	sides Sides
	adj   *sideAdjacency

	members graph.Grouped[types.NodeID, RoleSet, RoleSet]
	// seen holds, per atom of some class, what its holders see.
	seen  *graph.Map[Role, []types.NodeID]
	views *graph.Map[RoleSet, []types.NodeID]

	// computed counts the views and atom views the update computed;
	// total and seenTotal those every update up to it did.
	computed, seenComputed int
	total, seenTotal       int
}

// RolePeers returns the peer classes of s, keyed by side set, reusing
// from prev, built by RolePeers, every view whose atoms' views did not
// move: a view keeps its identity while its peers stay.
func RolePeers(prev *PeerClasses, s Sides) *PeerClasses {
	var kc *keyedClasses
	if prev != nil {
		kc = prev.keyed
	}

	if kc == nil || kc.sides.plan != s.plan {
		next := buildKeyed(s, kc)
		if kc != nil {
			next.total += kc.total
			next.seenTotal += kc.seenTotal
		}

		return &PeerClasses{keyed: next}
	}

	if kc.sides.sets == s.sets && kc.sides.held.Groups == s.held.Groups {
		next := *kc
		next.sides, next.computed, next.seenComputed = s, 0, 0

		return &PeerClasses{keyed: &next}
	}

	next := &keyedClasses{sides: s, adj: kc.adj, total: kc.total, seenTotal: kc.seenTotal}
	next.members = graph.GroupBy(kc.members, s.sets, func(_ types.NodeID, rs RoleSet) []RoleSet { return []RoleSet{rs} }, graph.Same[RoleSet])

	// Atom views reading a moved atom move with it.
	moved := map[Role]struct{}{}

	seen := kc.seen.Edit()

	for _, b := range graph.Changes(kc.sides.held.Groups, s.held.Groups) {
		if _, held := s.held.Groups.Get(b); !held {
			seen.Delete(b)
		}

		for _, r := range kc.adj.readersOf(b) {
			old, ok := seen.Get(r)
			if !ok {
				continue
			}

			if _, held := s.held.Groups.Get(r); !held {
				seen.Delete(r)

				continue
			}

			v := next.atomView(r)
			next.seenComputed++

			if !slices.Equal(v, old) {
				seen.Set(r, v)

				moved[r] = struct{}{}
			}
		}
	}

	next.seen = seen.Done()

	views := kc.views.Edit()
	redo := map[RoleSet]struct{}{}

	for _, rs := range graph.Changes(kc.members.Groups, next.members.Groups) {
		_, had := kc.views.Get(rs)
		if _, has := next.members.Groups.Get(rs); !has {
			views.Delete(rs)
		} else if !had {
			redo[rs] = struct{}{}
		}
	}

	classes := next.members.Groups.Len()

	for r := range moved {
		holders := s.Holders(r)
		if len(holders) < classes {
			for _, id := range holders {
				if rs, ok := s.sets.Get(id); ok {
					redo[rs] = struct{}{}
				}
			}

			continue
		}

		for rs := range next.members.Groups.All() {
			if rs.Has(r) {
				redo[rs] = struct{}{}
			}
		}
	}

	next.seen = next.fill(redo)

	memo := map[string][]types.NodeID{}

	for rs := range redo {
		v := next.classView(rs, memo)
		next.computed++

		if old, ok := kc.views.Get(rs); ok && slices.Equal(old, v) {
			continue
		}

		views.Set(rs, v)
	}

	next.views = views.Done()
	next.total += next.computed
	next.seenTotal += next.seenComputed

	return &PeerClasses{keyed: next}
}

// buildKeyed builds every class of s. A view equal to prev's for the same
// side set keeps prev's identity: an edit that names the same selectors
// keeps the side sets.
func buildKeyed(s Sides, prev *keyedClasses) *keyedClasses {
	kc := &keyedClasses{sides: s, adj: newSideAdjacency(s.plan)}
	kc.members = graph.GroupBy(graph.Grouped[types.NodeID, RoleSet, RoleSet]{}, s.sets,
		func(_ types.NodeID, rs RoleSet) []RoleSet { return []RoleSet{rs} }, graph.Same[RoleSet])
	kc.seen = graph.NewMap[Role, []types.NodeID](slices.Equal[[]types.NodeID], nil)

	redo := map[RoleSet]struct{}{}
	for rs := range kc.members.Groups.All() {
		redo[rs] = struct{}{}
	}

	kc.seen = kc.fill(redo)

	views := make(map[RoleSet][]types.NodeID, len(redo))
	memo := map[string][]types.NodeID{}

	for rs := range redo {
		views[rs] = kc.classView(rs, memo)
		kc.computed++

		if prev != nil {
			if old, ok := prev.views.Get(rs); ok && slices.Equal(old, views[rs]) {
				views[rs] = old
			}
		}
	}

	kc.views = graph.NewMap(slices.Equal[[]types.NodeID], views)
	kc.total, kc.seenTotal = kc.computed, kc.seenComputed

	return kc
}

// fill returns the atom views with those of the atoms of classes added.
func (kc *keyedClasses) fill(classes map[RoleSet]struct{}) *graph.Map[Role, []types.NodeID] {
	var e *graph.MapEdit[Role, []types.NodeID]

	for rs := range classes {
		for r := range rs.All() {
			if _, ok := kc.seen.Get(r); ok {
				continue
			}

			if e == nil {
				e = kc.seen.Edit()
			}

			if _, ok := e.Get(r); ok {
				continue
			}

			e.Set(r, kc.atomView(r))
			kc.seenComputed++
		}
	}

	if e == nil {
		return kc.seen
	}

	return e.Done()
}

// atomView is what r's holders see.
func (kc *keyedClasses) atomView(r Role) []types.NodeID {
	links := kc.adj.linksOf(r)
	lists := make([][]types.NodeID, 0, len(links))

	for _, l := range links {
		lists = append(lists, kc.sides.Holders(l))
	}

	return unionSorted(lists)
}

// classView is the view of the nodes with side set rs. Classes whose
// atoms see the same slices share one union, kept in memo for the pass.
func (kc *keyedClasses) classView(rs RoleSet, memo map[string][]types.NodeID) []types.NodeID {
	lists := make([][]types.NodeID, 0, rs.Len())

	var key []byte

	for r := range rs.All() {
		v, _ := kc.seen.Get(r)
		if len(v) == 0 {
			continue
		}

		lists = append(lists, v)
		key = strconv.AppendUint(key, uint64(reflect.ValueOf(v).Pointer()), 36)
		key = strconv.AppendInt(append(key, ':'), int64(len(v)), 36)
		key = append(key, ',')
	}

	if v, ok := memo[string(key)]; ok {
		return v
	}

	v := unionSorted(lists)
	memo[string(key)] = v

	return v
}

// unionSorted returns the union of sorted, duplicate-free lists. When the
// others are all inside the longest, it is the longest itself: views
// reading the same atom then share its slice.
func unionSorted(lists [][]types.NodeID) []types.NodeID {
	var longest []types.NodeID
	for _, l := range lists {
		if len(l) > len(longest) {
			longest = l
		}
	}

	var extra int

	for _, l := range lists {
		if len(l) == 0 || sameSlice(l, longest) {
			continue
		}

		for _, id := range l {
			if _, ok := slices.BinarySearch(longest, id); !ok {
				extra++

				break
			}
		}
	}

	if extra == 0 {
		return longest
	}

	n := 0
	for _, l := range lists {
		n += len(l)
	}

	out := make([]types.NodeID, 0, n)
	for _, l := range lists {
		out = append(out, l...)
	}

	slices.Sort(out)

	return slices.Clip(slices.Compact(out))
}

// readers returns the holders of every atom whose holders see one of id's
// atoms: a view is the union of its atoms' views, each the holders of the
// atoms they link to, so these are exactly the nodes whose view holds id.
func (kc *keyedClasses) readers(id types.NodeID) [][]types.NodeID {
	rs, ok := kc.sides.sets.Get(id)
	if !ok {
		return nil
	}

	var out [][]types.NodeID

	for l := range rs.All() {
		for _, r := range kc.adj.readersOf(l) {
			if h := kc.sides.Holders(r); len(h) > 0 {
				out = append(out, h)
			}
		}
	}

	return out
}

// view returns id's view.
func (kc *keyedClasses) view(id types.NodeID) []types.NodeID {
	v, _ := kc.viewOf(id)

	return v
}

// viewOf returns id's view and the side set it is keyed by.
func (kc *keyedClasses) viewOf(id types.NodeID) ([]types.NodeID, RoleSet) {
	rs, ok := kc.sides.sets.Get(id)
	if !ok {
		return nil, RoleSet{}
	}

	v, _ := kc.views.Get(rs)

	return v, rs
}

// ViewAndSideSet is [PeerClasses.View] with the side set id's class is
// keyed by, the one [Sides.Of] gives: classes keyed otherwise have none.
func (c *PeerClasses) ViewAndSideSet(id types.NodeID) ([]types.NodeID, RoleSet) {
	if c == nil || c.keyed == nil {
		return c.View(id), RoleSet{}
	}

	return c.keyed.viewOf(id)
}

// ViewsComputed returns how many class views and atom views every update
// up to the one that built c computed; zero for classes not keyed by side
// set. Compare two values across a change.
func (c *PeerClasses) ViewsComputed() (int, int) {
	if c == nil || c.keyed == nil {
		return 0, 0
	}

	return c.keyed.total, c.keyed.seenTotal
}

// SameKeyed reports whether classes keyed by side set hold the same views
// for the same side sets, by identity: an update that moved no view keeps
// both. It is a cheap cutoff, not [PeerClasses.Same].
func (c *PeerClasses) SameKeyed(o *PeerClasses) bool {
	if c == nil || o == nil || c.keyed == nil || o.keyed == nil {
		return c == o
	}

	return c.keyed.views == o.keyed.views && c.keyed.sides.sets == o.keyed.sides.sets
}

// changedSince returns the nodes whose view differs between old and kc: a
// node keeping its side set sees what its class does, so only nodes that
// moved class and the members of classes whose view moved are compared,
// not every node.
func (kc *keyedClasses) changedSince(old *keyedClasses) []types.NodeID {
	var out []types.NodeID

	differs := func(id types.NodeID) bool {
		_, had := old.sides.sets.Get(id)
		_, has := kc.sides.sets.Get(id)
		was, is := old.view(id), kc.view(id)

		return had != has || !sameSlice(was, is) && !slices.Equal(was, is)
	}

	for _, id := range graph.Changes(old.sides.sets, kc.sides.sets) {
		if differs(id) {
			out = append(out, id)
		}
	}

	for _, rs := range graph.Changes(old.views, kc.views) {
		members, _ := kc.members.Groups.Get(rs)
		for _, id := range members {
			// A member that moved class was compared above.
			if was, _ := old.sides.sets.Get(id); was == rs {
				out = append(out, id)
			}
		}
	}

	slices.Sort(out)

	return slices.Compact(out)
}

// RouteAccess returns the routes among routes viewer may use, in input
// order: what [types.NodeView.CanAccessRoutes] keeps with the viewer's
// matchers. An exit route needs a rule from the viewer to the internet; a
// subnet route a rule with the viewer on one side and the route
// overlapping the other side's addresses.
func (s Sides) RouteAccess(viewer types.NodeID, routes []netip.Prefix) []netip.Prefix {
	vs, ok := s.sets.Get(viewer)
	if !ok || len(routes) == 0 {
		return nil
	}

	vf, _ := s.facts.Get(viewer)

	key := accessKey{set: vs}

	if vf != nil && vf.owned {
		key.owner, key.owned = vf.owner, true
	}

	rules := s.rules.of(s, key)
	via := s.viaRules(vs, vf)

	if len(rules)+len(via) == 0 {
		return nil
	}

	some := func(match func(accessRule) bool) bool {
		return slices.ContainsFunc(rules, match) || slices.ContainsFunc(via, match)
	}

	var out []netip.Prefix

	for _, route := range routes {
		if tsaddr.IsExitRoute(route) {
			if some(func(r accessRule) bool { return r.isSrc && r.inet }) {
				out = append(out, route)
			}

			continue
		}

		if some(func(r accessRule) bool {
			return r.isSrc && s.overlaps(r.dst, r.dstPrefixes, route) ||
				r.isDst && s.overlaps(r.src, nil, route)
		}) {
			out = append(out, route)
		}
	}

	return out
}

// accessRule is one rule of a viewer's matchers as route access reads it.
type accessRule struct {
	src, dst     []Role
	dstPrefixes  []netip.Prefix
	isSrc, isDst bool
	inet         bool
}

// accessKey is what a viewer's shared and self rules depend on beyond the
// templates: its side set, and the user it owns a node of.
type accessKey struct {
	set   RoleSet
	owner uint
	owned bool
}

// ruleCache holds the rules each accessKey reads routes by. They follow the
// templates otherwise, so a state that keeps them keeps the cache.
type ruleCache struct {
	mu     sync.Mutex
	rules  map[accessKey][]accessRule
	builds int
}

// of returns the shared and self rules of the viewers with key k, built
// once per key.
func (c *ruleCache) of(s Sides, k accessKey) []accessRule {
	c.mu.Lock()
	defer c.mu.Unlock()

	if r, ok := c.rules[k]; ok {
		return r
	}

	// ponytail: keys that come and go stay until the cache is renewed or
	// outgrows the side sets held; prune by holders if churn makes it matter.
	if c.rules == nil || len(c.rules) > 2*s.sets.Len()+64 {
		c.rules = map[accessKey][]accessRule{}
	}

	r := s.sharedRules(k.set)
	r = s.selfRules(r, k)
	c.rules[k] = r
	c.builds++

	return r
}

func addRule(out []accessRule, vs RoleSet, r accessRule) []accessRule {
	hit := func(atoms []Role) bool { return slices.ContainsFunc(atoms, vs.Has) }

	r.isSrc = r.isSrc || hit(r.src)
	// An exit node serves a rule's internet destinations, so it is on that
	// side too, as visibility has it.
	r.isDst = r.isDst || hit(r.dst) || r.inet && vs.Has(atomExit)

	if r.isSrc || r.isDst {
		out = append(out, r)
	}

	return out
}

// sharedRules returns the rules every node's matchers hold that the viewer
// with side set vs is on a side of.
func (s Sides) sharedRules(vs RoleSet) []accessRule {
	var out []accessRule

	for g := range s.plan.grants {
		gs := &s.plan.grants[g]

		if gs.port {
			out = addRule(out, vs, accessRule{src: gs.src, dst: gs.portDst, inet: gs.portInet})
		}

		if gs.capg {
			out = addRule(out, vs, accessRule{src: gs.src, dst: gs.capDst})
		}

		if gs.comp {
			out = addRule(out, vs, accessRule{src: gs.compSrc, dst: gs.compDst})
		}
	}

	return out
}

// selfRules appends to out the self rules of k's user the viewer is on a
// side of.
func (s Sides) selfRules(out []accessRule, k accessKey) []accessRule {
	if !k.owned {
		return out
	}

	u := uint64(k.owner)
	owner := []Role{OwnerRole(k.owner)}

	if len(s.plan.selfPort) > 0 {
		out = addRule(out, k.set, accessRule{src: []Role{{kind: roleNamedPort, value: u}}, dst: owner})
	}

	// The companion rule runs the other way between the same sides, which
	// route access reads both ways: this one decides for both.
	if len(s.plan.selfApp) > 0 {
		out = addRule(out, k.set, accessRule{src: []Role{{kind: roleNamedApp, value: u}}, dst: owner})
	}

	return out
}

// viaRules returns the rules of the via grants the viewer routes for.
func (s Sides) viaRules(vs RoleSet, vf *sideFacts) []accessRule {
	if vf == nil {
		return nil
	}

	p := s.plan

	var out []accessRule

	for _, g := range vf.targets {
		gs := &p.grants[g]
		if !gs.viaPorts {
			continue
		}

		dsts := s.viaDstsFor(vf, gs)
		if gs.viaInternet && vf.exit {
			dsts = append(dsts, util.TheInternet().Prefixes()...)
		}

		if len(dsts) == 0 {
			continue
		}

		var b netipx.IPSetBuilder
		for _, d := range dsts {
			b.AddPrefix(d)
		}

		set, _ := b.IPSet()

		// The router forwards for the grant: it reads the rule from the
		// destination side alone, whether or not it is among the sources.
		if slices.ContainsFunc(vf.ips, set.Contains) || slices.ContainsFunc(vf.routes, set.OverlapsPrefix) ||
			util.HasInternetDestination(set) && vs.Has(atomExit) {
			out = append(out, accessRule{src: gs.src, dstPrefixes: dsts, isDst: true})
		}
	}

	return out
}

// viaDstsFor returns the destinations of via grant gs that f's routes
// overlap, as the via router's rules write them.
func (s Sides) viaDstsFor(f *sideFacts, gs *grantSides) []netip.Prefix {
	var out []netip.Prefix

	for _, d := range s.resolvePrefixes(gs.viaDst) {
		if slices.ContainsFunc(f.routes, d.Overlaps) || slices.ContainsFunc(f.exits, d.Overlaps) {
			out = append(out, d)
		}
	}

	return out
}

// resolvePrefixes returns what each of ids resolves to, as prefixes, in
// order, skipping a resolution with an error: an identity selector its
// members' addresses, an address selector its literal.
func (s Sides) resolvePrefixes(ids []SelectorID) []netip.Prefix {
	var out []netip.Prefix

	for _, id := range ids {
		sel := s.plan.table.Selector(id)

		switch {
		case sel.Kind.HoldsNodes():
			var b netipx.IPSetBuilder

			for _, m := range s.posts.Nodes(SelectorRole(id)) {
				if f, ok := s.facts.Get(m); ok {
					for _, ip := range f.ips {
						b.Add(ip)
					}
				}
			}

			set, _ := b.IPSet()
			out = append(out, set.Prefixes()...)
		case s.plan.resolvesOK(id):
			if l := s.plan.t.literals[id]; l.res != nil {
				out = append(out, l.res.Prefixes()...)
			}
		}
	}

	return out
}

// overlaps reports whether the addresses of atoms, or prefixes, overlap
// route.
func (s Sides) overlaps(atoms []Role, prefixes []netip.Prefix, route netip.Prefix) bool {
	if slices.ContainsFunc(prefixes, route.Overlaps) {
		return true
	}

	for _, a := range atoms {
		switch a.kind { //nolint:exhaustive // the rest are held by nodes, see default
		case roleAll:
			return true
		case roleLiteral:
			if set := s.plan.lit[a.value]; set != nil && set.OverlapsPrefix(route) {
				return true
			}
		case roleApproved:
			if s.approvedOverlaps(route) {
				return true
			}
		default:
			if s.coveredBy(route, a) {
				return true
			}
		}
	}

	return false
}

// approvedOverlaps reports whether an approved subnet route overlaps route.
func (s Sides) approvedOverlaps(route netip.Prefix) bool {
	route = route.Masked()

	for _, l := range s.approvedLens[family(route.Addr())] {
		if l > route.Bits() {
			continue
		}

		if p, _ := route.Addr().Prefix(l); func() bool { _, ok := s.approvals.byRoute.Groups.Get(p); return ok }() {
			return true
		}
	}

	for p := range s.approvals.byRoute.Groups.All() {
		if p.Bits() > route.Bits() && route.Contains(p.Addr()) {
			return true
		}
	}

	return false
}

// ViaPlan is via as the templates and membership decide it: each via
// grant's elections — the scopes, the routers carrying one of its tags
// that serve a route overlapping its destinations — and the via grants'
// destinations as prefixes. [UpdateViaPlans] keeps it by identity while
// its content stays, so an election comparing it by identity sees every
// move of candidates, whatever the compile does.
type ViaPlan struct {
	plan   *sidePlan
	scopes map[netip.Prefix][]viaScope
	// dsts holds, per via grant steering reads, its destinations as
	// prefixes in the compile's order, which steered routes follow; nil
	// for the other grants, whose destinations steering asks the roles.
	dsts [][]netip.Prefix
}

// ViaPlans is the via plan with what it was built from, so an update tells
// what it can skip.
type ViaPlans struct {
	Plan *ViaPlan

	facts   *graph.Map[types.NodeID, *sideFacts]
	routers *graph.Map[netip.Prefix, []types.NodeID]
	posts   *graph.Map[Role, []types.NodeID]
	// Builds counts the plans every update up to this one built, kept or
	// not.
	Builds int
}

// Same reports whether a and b hold the same plan.
func (v ViaPlans) Same(o ViaPlans) bool { return v.Plan == o.Plan }

// UpdateViaPlans returns the via plan of s, prev's while nothing it reads
// moved or what it builds equals prev's.
func UpdateViaPlans(prev ViaPlans, s Sides) ViaPlans {
	next := ViaPlans{Plan: prev.Plan, facts: s.facts, routers: s.routers.Groups, posts: s.posts.byRole.Groups, Builds: prev.Builds}

	if prev.Plan != nil && prev.Plan.plan == s.plan && (!s.plan.hasVia || !prev.readsMoved(s)) {
		return next
	}

	built := buildViaPlan(s)
	next.Builds++

	if prev.Plan == nil || prev.Plan.plan != s.plan || !prev.Plan.sameContent(built) {
		next.Plan = built
	}

	return next
}

// readsMoved reports whether s moved anything the plan reads: routes, the
// members of the via grants' tags and destinations, or the addresses of
// those destinations' members.
func (v ViaPlans) readsMoved(s Sides) bool {
	if v.routers != s.routers.Groups {
		return true
	}

	p := v.Plan.plan
	relevant := func(r Role) bool {
		id, ok := r.Selector()
		if !ok {
			return false
		}

		_, found := slices.BinarySearch(p.viaReads, id)

		return found
	}

	if v.posts != s.posts.byRole.Groups && slices.ContainsFunc(graph.Changes(v.posts, s.posts.byRole.Groups), relevant) {
		return true
	}

	if v.facts == s.facts || len(p.viaIdents) == 0 {
		return false
	}

	member := func(f *sideFacts) bool {
		return f != nil && slices.ContainsFunc(p.viaIdents, func(id SelectorID) bool { return f.roles.Has(SelectorRole(id)) })
	}

	for _, id := range graph.Changes(v.facts, s.facts) {
		was, is := mustFacts(v.facts, id), mustFacts(s.facts, id)
		if was != nil && is != nil && slices.Equal(was.ips, is.ips) {
			continue
		}

		if member(was) || member(is) {
			return true
		}
	}

	return false
}

func buildViaPlan(s Sides) *ViaPlan {
	v := &ViaPlan{plan: s.plan, scopes: map[netip.Prefix][]viaScope{}}

	if !s.plan.hasVia {
		return v
	}

	v.dsts = make([][]netip.Prefix, len(s.plan.steer))

	scoped := map[viaKey]struct{}{}

	for i, st := range s.plan.steer {
		if !st.via {
			continue
		}

		v.dsts[i] = s.resolvePrefixes(st.dsts)

		var b netipx.IPSetBuilder
		for _, p := range v.dsts[i] {
			b.AddPrefix(p)
		}

		set, _ := b.IPSet()

		var routes []netip.Prefix

		for p := range s.routers.Groups.All() {
			if set.OverlapsPrefix(p) {
				routes = append(routes, p)
			}
		}

		slices.SortFunc(routes, netip.Prefix.Compare)

		for _, p := range routes {
			k := viaKey{st.key, p}
			if _, ok := scoped[k]; ok {
				continue
			}

			ids, _ := s.routers.Groups.Get(p)

			var candidates []types.NodeID

			for _, id := range ids {
				rs, _ := s.roles.Of(id)
				if slices.ContainsFunc(st.tags, func(t SelectorID) bool { return rs.Has(SelectorRole(t)) }) {
					candidates = append(candidates, id)
				}
			}

			if len(candidates) == 0 {
				continue
			}

			scoped[k] = struct{}{}

			v.scopes[p] = append(v.scopes[p], viaScope{via: st.key, candidates: views.SliceOf(candidates)})
		}
	}

	return v
}

func (v *ViaPlan) sameContent(o *ViaPlan) bool {
	if len(v.scopes) != len(o.scopes) || !slices.EqualFunc(v.dsts, o.dsts, slices.Equal[[]netip.Prefix]) {
		return false
	}

	for p, scopes := range v.scopes {
		other, ok := o.scopes[p]
		if !ok || !slices.EqualFunc(scopes, other, func(a, b viaScope) bool {
			return a.via == b.via && sameNodeIDSlice(a.candidates, b.candidates)
		}) {
			return false
		}
	}

	return true
}

// candidates returns the scope of key's candidates.
func (v *ViaPlan) candidates(k viaKey) (views.Slice[types.NodeID], bool) {
	for _, scope := range v.scopes[k.prefix] {
		if scope.via == k.via {
			return scope.candidates, true
		}
	}

	return views.Slice[types.NodeID]{}, false
}

// Steer returns the via steering of peer's routes for viewer, as
// [PolicyManager.ViaRoutesForPeer] decides it, reading the viewer's side
// set where the compile tests its addresses against the grants' sources;
// primary names the router elected for a grant's key and route, zero for
// none. UsePrimary follows Include's order, not the compile's: its readers
// ask whether it holds a route.
func (v *ViaPlan) Steer(s Sides, viewer, peer types.NodeView, primary func(key string, prefix netip.Prefix) types.NodeID) types.ViaRouteResult {
	var result types.ViaRouteResult

	if v == nil || !v.plan.hasVia || viewer.ID() == peer.ID() {
		return result
	}

	vs, ok := s.sets.Get(viewer.ID())
	if !ok {
		return result
	}

	steer := v.plan.steer
	matches := func(i int) bool { return slices.ContainsFunc(steer[i].src, vs.Has) }

	peerRoles, _ := s.roles.Of(peer.ID())
	peerRoutes := peer.SubnetRoutes()

	for i, st := range steer {
		if !st.via || !matches(i) {
			continue
		}

		var routes []netip.Prefix

		for _, d := range v.dsts[i] {
			for _, r := range peerRoutes {
				if d.Overlaps(r) && !slices.Contains(routes, r) {
					routes = append(routes, r)
				}
			}
		}

		if st.inetLit {
			routes = append(routes, peer.OfferedExitRoutes()...)
		}

		tagged := slices.ContainsFunc(st.tags, func(t SelectorID) bool { return peerRoles.Has(SelectorRole(t)) })

		for _, r := range routes {
			if tagged && (tsaddr.IsExitRoute(r) || primary(st.key, r) == peer.ID()) {
				result.Include = append(result.Include, r)
			} else {
				result.Exclude = append(result.Exclude, r)
			}
		}
	}

	if len(result.Include) == 0 && len(result.Exclude) == 0 {
		return result
	}

	for i, st := range steer {
		if !st.via && matches(i) {
			st.regular(s, &result)
		}
	}

	result.Include = uniquePrefixes(result.Include)
	result.Exclude = uniquePrefixes(result.Exclude)

	return result
}

// regular applies a regular grant the viewer is a source of to steering:
// an included route it covers falls to the primary election, an excluded
// one is no longer excluded, and a grant to the internet frees the exits.
func (st *steerGrant) regular(s Sides, result *types.ViaRouteResult) {
	// A subnet route overlaps the destinations when a literal does or a
	// member has an address inside: what the members resolve to.
	covers := func(p netip.Prefix) bool {
		return !tsaddr.IsExitRoute(p) && (st.lits.OverlapsPrefix(p) ||
			slices.ContainsFunc(st.idents, func(id SelectorID) bool { return s.coveredBy(p, SelectorRole(id)) }))
	}

	for _, p := range result.Include {
		if covers(p) && !slices.Contains(result.UsePrimary, p) {
			result.UsePrimary = append(result.UsePrimary, p)
		}
	}

	result.Exclude = slices.DeleteFunc(result.Exclude, covers)

	if st.inetLit {
		result.Exclude = slices.DeleteFunc(result.Exclude, tsaddr.IsExitRoute)
	}
}

// StaticPrimary is the router policy inspection names for a scope: the
// lowest candidate ID.
func (v *ViaPlan) StaticPrimary(key string, prefix netip.Prefix) types.NodeID {
	ids, ok := v.candidates(viaKey{key, prefix})
	if !ok || ids.Len() == 0 {
		return 0
	}

	return ids.At(0)
}

// ViaWinners are the elections of a via plan: the winner of each scope.
type ViaWinners struct {
	plan    *ViaPlan
	winners *graph.Map[viaKey, types.NodeID]
}

// Primary returns the winner of key's scope for prefix, zero for none.
func (w *ViaWinners) Primary(key string, prefix netip.Prefix) types.NodeID {
	if w == nil {
		return 0
	}

	id, _ := w.winners.Get(viaKey{key, prefix})

	return id
}

// ElectVia elects plan's scopes from previous: only touched prefixes while
// the plan is the one previous was elected from; otherwise every scope
// whose prefix is touched or whose candidates moved, and the winners of
// scopes the plan dropped go. elect is as in [PolicyManager.ElectViaAfresh].
func ElectVia(previous *ViaWinners, plan *ViaPlan, touched map[netip.Prefix]struct{}, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) *ViaWinners {
	var winners *graph.Map[viaKey, types.NodeID]
	if previous != nil {
		winners = previous.winners
	}

	if winners == nil {
		winners = graph.NewMap[viaKey](func(a, b types.NodeID) bool { return a == b }, nil)
	}

	e := winners.Edit()

	electScope := func(k viaKey, candidates views.Slice[types.NodeID]) {
		incumbent, _ := e.Get(k)
		if id, ok := elect(candidates, incumbent); ok {
			e.Set(k, id)
		} else {
			e.Delete(k)
		}
	}

	switch {
	case previous != nil && previous.plan == plan:
		for p := range touched {
			for _, scope := range plan.scopes[p] {
				electScope(viaKey{scope.via, p}, scope.candidates)
			}
		}
	default:
		seen := map[viaKey]struct{}{}

		for p, scopes := range plan.scopes {
			for _, scope := range scopes {
				k := viaKey{scope.via, p}
				seen[k] = struct{}{}

				if previous != nil && previous.plan != nil {
					if _, ok := touched[p]; !ok {
						if old, had := previous.plan.candidates(k); had && sameNodeIDSlice(old, scope.candidates) {
							continue
						}
					}
				}

				electScope(k, scope.candidates)
			}
		}

		for k := range winners.All() {
			if _, ok := seen[k]; !ok {
				e.Delete(k)
			}
		}
	}

	return &ViaWinners{plan: plan, winners: e.Done()}
}

// ElectViaPlan is [ElectVia] over previous's winners, bound to plan and
// sides for steering: the via elections the world serves. It reports
// whether a winner moved.
func ElectViaPlan(
	previous *ViaRoutes,
	plan *ViaPlan,
	sides Sides,
	touched map[netip.Prefix]struct{},
	elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool),
) (*ViaRoutes, bool) {
	var (
		prev *ViaWinners
		was  *graph.Map[viaKey, types.NodeID]
	)

	if previous != nil {
		prev, was = &ViaWinners{plan: previous.plan, winners: previous.winners}, previous.winners
	}

	won := ElectVia(prev, plan, touched, elect)

	// A first election that elects nobody moves nothing.
	moved := won.winners != was && (was != nil || won.winners.Len() > 0)

	// An unmoved election keeps its binding, so sessions see no new one.
	if previous != nil && won.winners == was && previous.plan == plan && previous.sides.Same(sides) {
		return previous, false
	}

	return &ViaRoutes{plan: plan, sides: sides, winners: won.winners}, moved
}

// WithSides returns v steering by sides, v itself when they are the sides
// it steers by.
func (v *ViaRoutes) WithSides(sides Sides) *ViaRoutes {
	if v == nil || v.plan == nil || v.sides.Same(sides) {
		return v
	}

	return &ViaRoutes{plan: v.plan, sides: sides, winners: v.winners}
}

// Plan returns the via plan v is bound to, nil for a compiled policy's.
func (v *ViaRoutes) Plan() *ViaPlan {
	if v == nil {
		return nil
	}

	return v.plan
}

// Elects reports whether r holds exactly the winners elect gives v's
// scopes, each seeded with r's own winner. It allocates nothing while they
// agree, so an audit can run it at every election.
func (v *ViaPlan) Elects(r *ViaRoutes, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) bool {
	return electsScopes(v.scopes, r, elect)
}

// ElectsVia is [ViaPlan.Elects] over the via scopes of pm's compile: the
// policy audit's check that the elections served are the compile's.
func (pm *PolicyManager) ElectsVia(r *ViaRoutes, elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool)) bool {
	var scopes map[netip.Prefix][]viaScope
	if prep := pm.viaPrep(); prep != nil {
		scopes = prep.scopes
	}

	return electsScopes(scopes, r, elect)
}

func electsScopes(
	scopes map[netip.Prefix][]viaScope,
	r *ViaRoutes,
	elect func(views.Slice[types.NodeID], types.NodeID) (types.NodeID, bool),
) bool {
	var winners *graph.Map[viaKey, types.NodeID]
	if r != nil {
		winners = r.winners
	}

	for p, ss := range scopes {
		for _, scope := range ss {
			k := viaKey{scope.via, p}
			incumbent, had := winners.Get(k)

			id, ok := elect(scope.candidates, incumbent)
			if ok != had || ok && id != incumbent {
				return false
			}
		}
	}

	for k := range winners.All() {
		scoped := false

		for _, s := range scopes[k.prefix] {
			scoped = scoped || s.via == k.via
		}

		if !scoped {
			return false
		}
	}

	return true
}

// SameWinners reports whether w and r elected the same winners.
func (w *ViaWinners) SameWinners(r *ViaRoutes) bool {
	var a, b *graph.Map[viaKey, types.NodeID]
	if w != nil {
		a = w.winners
	}

	if r != nil {
		b = r.winners
	}

	return sameViaWinners(a, b)
}

var errSidesAudit = errors.New("sides differ")

// SidesAudit is one snapshot's sides, role-keyed classes and via plan, with
// what [AuditSides] holds them against.
type SidesAudit struct {
	Templates *Templates
	Roles     Roles
	Postings  Postings
	Approvals SubnetApprovals
	Nodes     *NodeMap
	Sides     Sides
	Peers     *PeerClasses
	Via       *ViaPlan

	// List is the node list the policy compiles against, sorted by ID;
	// Users the users.
	List  views.Slice[types.NodeView]
	Users []types.User

	// Policy is the compile in force; Current reports that it compiled
	// List and Users. Otherwise the oracle is its document compiled afresh.
	Policy  *PolicyManager
	Current bool
}

// SidesReport counts what an audit compared and the shapes it met, so a
// test can tell its inputs reached each.
type SidesReport struct {
	Nodes, PeerPairs, RoutePairs, ViaPairs int
	// Fresh counts audits whose oracle was compiled afresh.
	Fresh int

	Covering, Covered                          int
	SingleFamily, ExitOneFamily, Exit          int
	PublicRoute                                int
	TaggedWithUser, ViaTargets, ViaRouterOnSrc int
	Steered, RoutesKept                        int
	AsymmetricPeers                            int
}

// Add adds o's counts to r.
func (r *SidesReport) Add(o SidesReport) {
	r.Nodes += o.Nodes
	r.PeerPairs += o.PeerPairs
	r.RoutePairs += o.RoutePairs
	r.ViaPairs += o.ViaPairs
	r.Fresh += o.Fresh
	r.Covering += o.Covering
	r.Covered += o.Covered
	r.SingleFamily += o.SingleFamily
	r.ExitOneFamily += o.ExitOneFamily
	r.Exit += o.Exit
	r.PublicRoute += o.PublicRoute
	r.TaggedWithUser += o.TaggedWithUser
	r.ViaTargets += o.ViaTargets
	r.ViaRouterOnSrc += o.ViaRouterOnSrc
	r.Steered += o.Steered
	r.RoutesKept += o.RoutesKept
	r.AsymmetricPeers += o.AsymmetricPeers
}

// AuditSides checks a's sides, classes and via plan against builds from
// scratch, and against the compile: every node's peers equal
// [PolicyManager.BuildPeerMap]'s;
// for every viewer and every route a node announces or approves, route
// access equals [types.NodeView.CanAccessRoutes] with the viewer's
// matchers; for every viewer and peer, via steering equals
// [PolicyManager.ViaRoutesForPeer]. It is for debugging and tests: the
// pairs are quadratic.
func AuditSides(a SidesAudit) (SidesReport, error) {
	var rep SidesReport

	if a.Policy == nil {
		return rep, nil
	}

	if !a.Templates.sel.Describes(a.Policy) {
		return rep, fmt.Errorf("%w: templates describe another policy than the compile in force", errSidesAudit)
	}

	fresh := buildSides(a.Templates.sidePlan(), a.Roles, a.Postings, a.Approvals, a.Nodes)

	err := sameSides(a.Sides, fresh)
	if err != nil {
		return rep, err
	}

	freshPeers := &PeerClasses{keyed: buildKeyed(fresh, nil)}

	for id := range a.Nodes.All() {
		got := a.Peers.keyed.view(id)
		want := freshPeers.keyed.view(id)

		if !slices.Equal(got, want) {
			return rep, fmt.Errorf("%w: classes of node %d: %v, built from scratch %v", errSidesAudit, id, got, want)
		}
	}

	if fv := buildViaPlan(fresh); !a.Via.sameContent(fv) {
		return rep, fmt.Errorf("%w: via plan differs from one built from scratch", errSidesAudit)
	}

	oracle := a.Policy
	if !a.Current {
		oracle, err = NewPolicyManagerFrom(nil, a.Policy.src, a.Users, a.List)
		if err != nil {
			return rep, fmt.Errorf("compiling the policy in force afresh: %w", err)
		}

		rep.Fresh = 1
	}

	err = auditPeerPairs(a, oracle, &rep)
	if err != nil {
		return rep, err
	}

	err = auditRouteAccess(a, oracle, &rep)
	if err != nil {
		return rep, err
	}

	err = auditSteering(a, oracle, &rep)
	if err != nil {
		return rep, err
	}

	countShapes(a, &rep)

	return rep, nil
}

func sameSides(got, want Sides) error {
	if d := mapDiff(want.sets, got.sets, graph.Same[RoleSet]); len(d) > 0 {
		id := d[0]
		g, _ := got.sets.Get(id)
		w, _ := want.sets.Get(id)

		return fmt.Errorf("%w: side sets of nodes %v (node %d: %v, built from scratch %v)", errSidesAudit, d, id, g, w)
	}

	sameFacts := func(a, b *sideFacts) bool { return reflect.DeepEqual(a, b) }

	if d := mapDiff(want.facts, got.facts, sameFacts); len(d) > 0 {
		return fmt.Errorf("%w: side facts of nodes %v", errSidesAudit, d)
	}

	if d := mapDiff(want.cover, got.cover, slices.Equal[coverAtoms]); len(d) > 0 {
		c, _ := got.cover.Get(d[0])
		w, _ := want.cover.Get(d[0])

		return fmt.Errorf("%w: cover counts of routes %v (%v: %v, from scratch %v)", errSidesAudit, d, d[0], c, w)
	}

	if !slices.Equal(got.targeted, want.targeted) {
		return fmt.Errorf("%w: via routers %v, from scratch %v", errSidesAudit, got.targeted, want.targeted)
	}

	if d := mapDiff(want.held.Groups, got.held.Groups, slices.Equal[[]types.NodeID]); len(d) > 0 {
		return fmt.Errorf("%w: holders of atoms %v", errSidesAudit, d)
	}

	return nil
}

func auditPeerPairs(a SidesAudit, oracle *PolicyManager, rep *SidesReport) error {
	byMap := oracle.BuildPeerMap(a.List)

	for _, n := range a.List.All() {
		got := a.Peers.Peers(n.ID())

		want := slices.Clone(byMap[n.ID()])
		slices.Sort(want)

		if !slices.Equal(got, want) && (len(got) > 0 || len(want) > 0) {
			return fmt.Errorf("%w: peers of node %d: %v, the compile's pair scan %v", errSidesAudit, n.ID(), got, want)
		}

		rep.Nodes++
		rep.PeerPairs += len(got)

		for _, p := range got {
			if !slices.Contains(a.Peers.Peers(p), n.ID()) {
				rep.AsymmetricPeers++
			}
		}
	}

	return nil
}

// auditRoutes are every route a node announces or approves.
func auditRoutes(list views.Slice[types.NodeView]) []netip.Prefix {
	var out []netip.Prefix

	for _, n := range list.All() {
		out = append(out, n.AnnouncedRoutes()...)
		out = append(out, n.ApprovedRoutes().AsSlice()...)
	}

	slices.SortFunc(out, netip.Prefix.Compare)

	return slices.Compact(out)
}

func auditRouteAccess(a SidesAudit, oracle *PolicyManager, rep *SidesReport) error {
	all := auditRoutes(a.List)

	for _, viewer := range a.List.All() {
		matchers, err := oracle.MatchersForNode(viewer)
		if err != nil {
			return err
		}

		for _, peer := range a.List.All() {
			routes := slices.Concat(peer.SubnetRoutes(), peer.ExitRoutes())
			if peer.ID() == a.List.At(0).ID() {
				routes = all
			}

			if len(routes) == 0 {
				continue
			}

			want := viewer.CanAccessRoutes(matchers, routes)
			got := a.Sides.RouteAccess(viewer.ID(), routes)

			if !slices.Equal(got, want) {
				return fmt.Errorf("%w: routes node %d may use through %d of %v: %v, the compile's matchers %v",
					errSidesAudit, viewer.ID(), peer.ID(), routes, got, want)
			}

			rep.RoutePairs++
			rep.RoutesKept += len(got)
		}
	}

	return nil
}

func auditSteering(a SidesAudit, oracle *PolicyManager, rep *SidesReport) error {
	for _, viewer := range a.List.All() {
		for _, peer := range a.List.All() {
			want := oracle.ViaRoutesForPeer(viewer, peer)
			got := a.Via.Steer(a.Sides, viewer, peer, a.Via.StaticPrimary)

			if !sameSteering(got, want) {
				return fmt.Errorf("%w: via routes node %d gets from %d: %+v, the compile's %+v", errSidesAudit, viewer.ID(), peer.ID(), got, want)
			}

			rep.ViaPairs++

			if len(got.Include)+len(got.Exclude) > 0 {
				rep.Steered++
			}
		}
	}

	return nil
}

// sameSteering compares steering results: Include and Exclude in order,
// UsePrimary as a set, which is all its readers ask of it.
func sameSteering(got, want types.ViaRouteResult) bool {
	sorted := func(p []netip.Prefix) []netip.Prefix {
		return slices.SortedFunc(slices.Values(p), netip.Prefix.Compare)
	}

	return slices.Equal(got.Include, want.Include) && slices.Equal(got.Exclude, want.Exclude) &&
		slices.Equal(sorted(got.UsePrimary), sorted(want.UsePrimary))
}

func countShapes(a SidesAudit, rep *SidesReport) {
	s := a.Sides

	for id, f := range s.facts.All() {
		n, _ := a.Nodes.Get(id)

		if len(f.ips) == 1 {
			rep.SingleFamily++
		}

		// Routing over another node's address, as D4 decides it.
		covering := false

		for _, r := range f.routes {
			s.nodesIn(r, func(m types.NodeID) {
				if m == id {
					return
				}

				covering = true
				rep.Covered++
			})
		}

		if covering {
			rep.Covering++
		}

		if f.exit {
			rep.Exit++

			if len(n.ExitRoutes()) == 1 {
				rep.ExitOneFamily++
			}
		}

		if slices.ContainsFunc(f.routes, func(p netip.Prefix) bool { return util.HasInternetDestination(prefixSet(p)) }) {
			rep.PublicRoute++
		}

		if n.IsTagged() && (n.User != nil || n.UserID != nil) {
			rep.TaggedWithUser++
		}

		rep.ViaTargets += len(f.targets)

		rs, _ := s.sets.Get(id)
		if rs.Has(Role{kind: roleRouterOnSrc, value: uint64(id)}) {
			rep.ViaRouterOnSrc++
		}
	}
}

func prefixSet(p netip.Prefix) *netipx.IPSet {
	var b netipx.IPSetBuilder
	b.AddPrefix(p)

	set, _ := b.IPSet()

	return set
}
