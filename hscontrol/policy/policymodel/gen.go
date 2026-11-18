package policymodel

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// Every draw is shaped so that shrinking it towards zero gives the plain
// case: the first alternative, false flags, the smallest counts, a node
// on its own addresses. A rare shape sits behind a [chance], which is
// false at zero, so a minimised case shows only the coincidences the
// failure needs.

// Policies draws a policy headscale accepts: at least one rule.
func Policies() *rapid.Generator[Policy] { return policies }

// Topologies draws users and nodes: at least one of each, the first user
// always alice.
func Topologies() *rapid.Generator[Topology] { return topologies }

// Worlds draws a policy and a topology, independently: the vocabulary is
// small enough that they name each other often.
func Worlds() *rapid.Generator[World] { return worlds }

// Scenarios draws a world and up to maxSteps steps from it, fewer on
// average. Each step is drawn against the world the earlier ones produce,
// so every edit is valid where it lands, and the policy stays one
// headscale accepts.
func Scenarios(maxSteps int) *rapid.Generator[Scenario] {
	return rapid.Custom(func(t *rapid.T) Scenario {
		s := Scenario{Start: worlds.Draw(t, "start")}
		w := s.Start

		step := rapid.Custom(func(t *rapid.T) Step {
			st := Steps(w).Draw(t, "step")
			w = w.Apply(st...)

			return st
		})

		// Steps come in runs of a few: rapid's lists average five
		// elements, and each step and each run is a group the shrinker
		// can delete whole.
		runs := rapid.SliceOfN(rapid.SliceOfN(step, 1, 5), 0, (maxSteps+2)/3).Draw(t, "steps")
		for _, run := range runs {
			s.Steps = append(s.Steps, run...)
		}

		if len(s.Steps) > maxSteps {
			s.Steps = s.Steps[:maxSteps]
		}

		return s
	})
}

// Steps draws one step valid against w, for a state machine that takes
// its steps as it goes: one edit mostly; sometimes several committed
// together, a node deleted and another registered with its address or
// ID, or a route announced and approved in one write.
func Steps(w World) *rapid.Generator[Step] {
	return rapid.Custom(func(t *rapid.T) Step { return drawStep(t, w) })
}

var (
	policies = rapid.Custom(func(t *rapid.T) Policy {
		return canonPolicy(drawPolicy(t))
	})
	topologies = rapid.Custom(func(t *rapid.T) Topology {
		return canonTopology(drawTopology(t))
	})
	worlds = rapid.Custom(func(t *rapid.T) World {
		return World{Policy: policies.Draw(t, "policy"), Topology: topologies.Draw(t, "topology")}
	})
)

// chance is true about once in k draws, and false when shrunk.
func chance(t *rapid.T, k int, label string) bool {
	return rapid.IntRange(0, k-1).Draw(t, label) == k-1
}

func index(t *rapid.T, n int, label string) int { return rapid.IntRange(0, n-1).Draw(t, label) }

func pick[E any](t *rapid.T, from []E, label string) E { return from[index(t, len(from), label)] }

// other is an index into n items that is not i.
func other(t *rapid.T, n, i int, label string) int { return (i + 1 + index(t, n-1, label)) % n }

// The selector kinds each place takes, simplest first.
var (
	srcKinds     = []SelKind{SelAll, SelUser, SelGroup, SelTag, SelMember, SelTagged, SelDangerAll, SelHost, SelPrefix}
	dstKinds     = []SelKind{SelAll, SelUser, SelGroup, SelTag, SelMember, SelTagged, SelInternet, SelHost, SelPrefix}
	appDstKinds  = []SelKind{SelAll, SelUser, SelGroup, SelTag, SelMember, SelTagged, SelHost, SelPrefix}
	selfSrcACL   = []SelKind{SelAll, SelUser, SelGroup, SelMember}
	selfSrcGrant = []SelKind{SelUser, SelGroup, SelMember}
	targetKinds  = appDstKinds
	ownerKinds   = []SelKind{SelUser, SelGroup, SelTag}
	sshSrcKinds  = []SelKind{SelUser, SelGroup, SelTag, SelMember, SelTagged}
	sshDstKinds  = []SelKind{SelSelf, SelTag, SelTagged}
	sshTaggedDst = []SelKind{SelTag, SelTagged}
)

func selGen(kinds []SelKind) *rapid.Generator[Sel] {
	return rapid.Custom(func(t *rapid.T) Sel { return drawSel(t, kinds) })
}

func drawSel(t *rapid.T, kinds []SelKind) Sel {
	s := Sel{Kind: pick(t, kinds, "kind")}

	switch s.Kind { //nolint:exhaustive // only these kinds index a pool
	case SelUser:
		s.I = index(t, len(UserRefs), "user")
	case SelGroup:
		s.I = index(t, numGroups, "group")
	case SelTag:
		s.I = index(t, numTags, "tag")
	case SelHost:
		s.I = index(t, numHosts, "host")
	case SelPrefix:
		s.I = index(t, numRulePrefixes, "prefix")
	}

	return s
}

var (
	srcs         = rapid.SliceOfN(selGen(srcKinds), 1, 3)
	selfSrcsACL  = rapid.SliceOfN(selGen(selfSrcACL), 1, 2)
	selfSrcsGr   = rapid.SliceOfN(selGen(selfSrcGrant), 1, 2)
	dsts         = rapid.SliceOfN(selGen(dstKinds), 1, 3)
	appDsts      = rapid.SliceOfN(selGen(appDstKinds), 1, 3)
	targets      = rapid.SliceOfN(selGen(targetKinds), 1, 2)
	owners       = rapid.SliceOfN(selGen(ownerKinds), 1, 2)
	sshSrcs      = rapid.SliceOfN(selGen(sshSrcKinds), 1, 2)
	sshDsts      = rapid.SliceOfN(selGen(sshDstKinds), 1, 2)
	sshTagDsts   = rapid.SliceOfN(selGen(sshTaggedDst), 1, 2)
	sshLogins    = rapid.SliceOfN(rapid.IntRange(0, len(SSHUsers)-1), 1, 2)
	attrLists    = rapid.SliceOfN(rapid.IntRange(0, len(Attrs)-1), 1, 2)
	sshRuleLists = rapid.SliceOfN(rapid.Custom(drawSSH), 1, 2)
	attrRules    = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) NodeAttr {
		return NodeAttr{Targets: targets.Draw(t, "target"), Attrs: attrLists.Draw(t, "attr")}
	}), 1, 2)
	ips = rapid.SliceOfN(rapid.Custom(drawIP), 1, 2)
)

func drawPolicy(t *rapid.T) Policy {
	var p Policy

	for g := range numGroups {
		p.Groups[g] = drawMembers(t)
	}

	for i := range numTags {
		if chance(t, 3, "owned") {
			p.TagOwners[i] = owners.Draw(t, "owners")
		}
	}

	for h := range numHosts {
		if chance(t, 6, "host-moved") {
			p.Hosts[h] = 1 + index(t, numRulePrefixes-1, "shift")
		}
	}

	// Lists are drawn as rapid lists, each element seeing those before
	// it, so the shrinker deletes an element whole.
	rapid.SliceOfN(rapid.Custom(func(t *rapid.T) bool {
		grant := chance(t, 2, "grant")
		r := drawRule(t, grant, p)

		l := ruleList(&p, grant)
		*l = append(*l, r)

		return grant
	}), 1, 4).Draw(t, "rules")

	// A capability to public space: the grant that makes exit nodes see
	// its sources one way.
	if chance(t, 8, "one-way") {
		p.Grants = append(p.Grants, Rule{
			Src: []Sel{drawSel(t, []SelKind{SelMember, SelUser, SelGroup, SelTag})},
			Dst: []Dest{{Sel: Sel{Kind: SelPrefix, I: 4}}},
			App: drawApps(t),
		})
	}

	if chance(t, 3, "ssh") {
		p.SSH = sshRuleLists.Draw(t, "ssh")
	}

	if chance(t, 3, "nodeAttrs") {
		p.NodeAttrs = attrRules.Draw(t, "nodeAttrs")
	}

	if chance(t, 4, "autoApprovers") {
		p.AutoApprovers = drawAutoApprovers(t)
	}

	return p
}

func drawMembers(t *rapid.T) []int {
	var out []int

	for i := range UserRefs {
		if chance(t, 3, "member") {
			out = append(out, i)
		}
	}

	return out
}

// drawRule draws an ACL or a grant to add to p. One in four takes the
// sources of a rule p has, so that two rules share a merge key.
func drawRule(t *rapid.T, grant bool, p Policy) Rule {
	var r Rule

	self := chance(t, 4, "self")
	app := grant && chance(t, 4, "app")

	selfSrc := selfSrcACL
	if grant {
		selfSrc = selfSrcGrant
	}

	copied := false

	if refs := p.Refs(); len(refs) > 0 && chance(t, 4, "same-sources") {
		ref := pick(t, refs, "from")
		if from := p.Rule(ref); !self || kindsAll(from.Src, selfSrc) {
			r.Src, copied = slices.Clone(from.Src), true
			if !grant && !ref.Grant {
				r.Proto = from.Proto
			}
		}
	}

	switch {
	case copied:
	case self && grant:
		r.Src = selfSrcsGr.Draw(t, "src")
	case self:
		r.Src = selfSrcsACL.Draw(t, "src")
	default:
		r.Src = srcs.Draw(t, "src")
	}

	var ds []Sel

	switch {
	case self:
		ds = []Sel{{Kind: SelSelf}}
		if chance(t, 4, "more-dst") {
			kinds := dstKinds
			if app {
				kinds = appDstKinds
			}

			ds = append(ds, drawSel(t, kinds))
		}
	case app:
		ds = appDsts.Draw(t, "dst")

		// Capabilities to public space make exit nodes see their
		// sources one way.
		if chance(t, 4, "public-dst") {
			ds = append(ds, Sel{Kind: SelPrefix, I: 4})
		}
	default:
		ds = dsts.Draw(t, "dst")
	}

	for _, d := range ds {
		r.Dst = append(r.Dst, Dest{Sel: d})
	}

	if !grant {
		if !copied && chance(t, 3, "proto") {
			r.Proto = 1 + index(t, len(Protos)-1, "proto")
		}

		if r.Proto < portedProtos {
			for i := range r.Dst {
				if chance(t, 2, "ports") {
					r.Dst[i].Ports = 1 + index(t, len(Ports)-1, "ports")
				}
			}
		}

		return r
	}

	if app {
		r.App = drawApps(t)
		if chance(t, 3, "app-and-ip") {
			r.IP = ips.Draw(t, "ip")
		}
	} else {
		r.IP = ips.Draw(t, "ip")
	}

	if !self && len(r.IP) > 0 && chance(t, 4, "via") {
		r.Via = []int{index(t, numTags, "via")}
	}

	return r
}

func kindsAll(sels []Sel, kinds []SelKind) bool {
	return !slices.ContainsFunc(sels, func(s Sel) bool { return !slices.Contains(kinds, s.Kind) })
}

func drawIP(t *rapid.T) IP {
	var ip IP

	if chance(t, 3, "proto") {
		ip.Proto = 1 + index(t, len(Protos)-1, "proto")
	}

	if ip.Proto < portedProtos && chance(t, 2, "ports") {
		ip.Ports = 1 + index(t, grantPorts-1, "ports")
	}

	return ip
}

func drawApps(t *rapid.T) []App {
	first := index(t, len(Apps), "cap")
	out := []App{{Cap: first, Value: index(t, len(AppValues), "value")}}

	if chance(t, 4, "second-cap") {
		out = append(out, App{Cap: other(t, len(Apps), first, "cap"), Value: index(t, len(AppValues), "value")})
	}

	return out
}

// drawSSH draws an SSH rule: a user to itself, or sources to their own
// nodes or tagged ones; a tagged source reaches only tagged nodes and
// cannot be checked.
func drawSSH(t *rapid.T) SSHRule {
	var r SSHRule

	if chance(t, 6, "to-user") {
		u := Sel{Kind: SelUser, I: index(t, refUsers, "user")}
		r.Src, r.Dst = []Sel{u}, []Sel{u}
	} else {
		r.Src = sshSrcs.Draw(t, "src")
		if slices.ContainsFunc(r.Src, func(s Sel) bool { return s.Kind == SelTag || s.Kind == SelTagged }) {
			r.Dst = sshTagDsts.Draw(t, "dst")
			r.Users = sshLogins.Draw(t, "users")

			return r
		}

		r.Dst = sshDsts.Draw(t, "dst")
	}

	r.Check = chance(t, 4, "check")
	r.Users = sshLogins.Draw(t, "users")

	return r
}

func drawAutoApprovers(t *rapid.T) AutoApprovers {
	var aa AutoApprovers

	if chance(t, 2, "routes") {
		first := index(t, numRulePrefixes, "route")
		aa.Routes = []RouteApproval{{Route: first, By: owners.Draw(t, "by")}}

		if chance(t, 4, "second-route") {
			aa.Routes = append(aa.Routes, RouteApproval{Route: other(t, numRulePrefixes, first, "route"), By: owners.Draw(t, "by")})
		}
	}

	if len(aa.Routes) == 0 || chance(t, 2, "exit") {
		aa.Exit = owners.Draw(t, "exit")
	}

	return aa
}

func drawTopology(t *rapid.T) Topology {
	var (
		users []User
		nodes []Node
	)

	rapid.SliceOfN(rapid.Custom(func(t *rapid.T) User {
		u := defaultUsers[len(users)]
		if len(users) > 0 && chance(t, 8, "same-name") {
			u.Name = pick(t, users, "as").Name
		}

		if chance(t, 8, "email") {
			u.Email = pick(t, userEmails, "email")
		}

		users = append(users, u)

		return u
	}), 1, len(defaultUsers)).Draw(t, "users")

	rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Node {
		n := drawNode(t, types.NodeID(len(nodes)+1), users, nodes) //nolint:gosec // small
		nodes = append(nodes, n)

		return n
	}), 1, 8).Draw(t, "nodes")

	n := len(nodes)

	// Exit nodes come up as often as the shapes pairing them need.
	if chance(t, 5, "exit") {
		x := &nodes[index(t, n, "exit-node")]
		rs := []int{exit4, exit6}

		if chance(t, 4, "one-family") {
			rs = []int{pick(t, rs, "family")}
		}

		x.Announced, x.Approved = addRoutes(x.Announced, rs), addRoutes(x.Approved, rs)
	}

	return Topology{Users: users, Nodes: nodes, NextID: types.NodeID(n + 1)} //nolint:gosec // small
}

// drawNode draws node id joining others.
func drawNode(t *rapid.T, id types.NodeID, users []User, others []Node) Node {
	n := Node{ID: id}

	if len(users) == 0 || chance(t, 5, "tagged") {
		n.Tags = drawTags(t)
		if len(users) > 0 && chance(t, 3, "carries-user") {
			n.User = pick(t, users, "user").ID
		}
	} else {
		n.User = pick(t, users, "owner").ID
	}

	// A tagged node goes without addresses more often, so that a tag all
	// of whose members lack them comes up.
	unaddressed := 12
	if n.Tagged() {
		unaddressed = 6
	}

	if !chance(t, unaddressed, "unaddressed") {
		n.V4 = drawAddr(t, 4, id, others)
		n.V6 = drawAddr(t, 6, id, others)
	}

	if chance(t, 3, "routes") {
		drawRoutes(t, &n)
	}

	if chance(t, 6, "client") {
		n.Client = Client(1 + index(t, numClients-1, "client")) //nolint:gosec // a few clients
	}

	n.Expired = chance(t, 10, "expired")
	n.Offline = chance(t, 8, "offline")

	return n
}

func drawTags(t *rapid.T) []int {
	first := index(t, numTags, "tag")
	tags := []int{first}

	if chance(t, 4, "second-tag") {
		tags = append(tags, other(t, numTags, first, "tag"))
		slices.Sort(tags)
	}

	return tags
}

// drawAddr draws node id's address in family: its own, or rarely none,
// another node's, or one outside the tailnet.
func drawAddr(t *rapid.T, family int, id types.NodeID, others []Node) netip.Addr {
	if chance(t, 8, "no-addr") {
		return netip.Addr{}
	}

	if chance(t, 6, "shared") {
		if held := heldAddrs(family, others, netip.Addr{}); len(held) > 0 {
			return pick(t, held, "of")
		}
	}

	if chance(t, 12, "outside") {
		return pick(t, outsidePool(family), "outside")
	}

	return ownAddr(family, uint64(id))
}

func outsidePool(family int) []netip.Addr {
	if family == 4 {
		return outsideV4
	}

	return outsideV6
}

// heldAddrs is the addresses nodes hold in family, but not.
func heldAddrs(family int, nodes []Node, not netip.Addr) []netip.Addr {
	var out []netip.Addr

	for _, n := range nodes {
		if a := n.Addr(family); a.IsValid() && a != not && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}

	return out
}

// routeChoices is what a node may route: every rule prefix, then an exit
// route, both halves together.
const routeChoices = numRulePrefixes + 1

// drawRouteChoice draws routes to announce or approve together.
func drawRouteChoice(t *rapid.T) []int {
	c := index(t, routeChoices, "route")
	if c < numRulePrefixes {
		return []int{c}
	}

	if chance(t, 4, "one-family") {
		return []int{pick(t, []int{exit4, exit6}, "family")}
	}

	return []int{exit4, exit6}
}

func drawRoutes(t *rapid.T, n *Node) {
	for range rapid.IntRange(1, 2).Draw(t, "routes") {
		rs := drawRouteChoice(t)

		switch {
		case chance(t, 4, "unapproved"):
			n.Announced = addRoutes(n.Announced, rs)
		case chance(t, 5, "unannounced"):
			n.Approved = addRoutes(n.Approved, rs)
		default:
			n.Announced = addRoutes(n.Announced, rs)
			n.Approved = addRoutes(n.Approved, rs)
		}
	}
}

func drawStep(t *rapid.T, w World) Step {
	nodes := w.Topology.Nodes

	switch {
	case len(nodes) > 0 && chance(t, 12, "reuse"):
		return drawReuse(t, w)
	case len(nodes) > 0 && chance(t, 12, "announce-approve"):
		return drawAnnounceApprove(t, w)
	case chance(t, 5, "several"):
		var st Step

		for range rapid.IntRange(2, 3).Draw(t, "edits") {
			e := drawEdit(t, w)
			st = append(st, e)
			w = w.Apply(e)
		}

		return st
	}

	return Step{drawEdit(t, w)}
}

func drawReuse(t *rapid.T, w World) Step {
	nodes := w.Topology.Nodes
	x := pick(t, nodes, "leaves")
	rest := slices.DeleteFunc(slices.Clone(nodes), func(n Node) bool { return n.ID == x.ID })

	id := w.Topology.nextID()
	if len(x.Addrs()) == 0 || chance(t, 3, "same-id") {
		id = x.ID
	}

	n := drawNode(t, id, w.Topology.Users, rest)

	switch {
	case len(x.Addrs()) == 0:
	case !x.V6.IsValid() || x.V4.IsValid() && !chance(t, 3, "v6"):
		n.V4 = x.V4
	default:
		n.V6 = x.V6
	}

	return Step{Leave{x.ID}, Join{n}}
}

// drawAnnounceApprove announces and approves, on one node, mostly a route
// another node already serves.
func drawAnnounceApprove(t *rapid.T, w World) Step {
	n := pick(t, w.Topology.Nodes, "node")

	var served []int

	for _, o := range w.Topology.Nodes {
		if o.ID == n.ID {
			continue
		}

		for _, r := range o.Approved {
			if slices.Contains(o.Announced, r) && !slices.Contains(served, r) && !slices.Contains(n.Announced, r) {
				served = append(served, r)
			}
		}
	}

	slices.Sort(served)

	rs := drawRouteChoice(t)
	if len(served) > 0 && !chance(t, 4, "unserved") {
		rs = []int{pick(t, served, "served")}
	}

	var st Step

	if ann := dropRoutes(rs, n.Announced); len(ann) > 0 {
		st = append(st, Announce{n.ID, ann})
	}

	if app := dropRoutes(rs, n.Approved); len(app) > 0 {
		st = append(st, Approve{n.ID, app})
	}

	if len(st) == 0 {
		return Step{drawEdit(t, w)}
	}

	return st
}

func drawEdit(t *rapid.T, w World) Edit {
	switch index(t, 5, "area") {
	case 0, 1:
		return drawNodeEdit(t, w)
	case 2, 3:
		return drawPolicyEdit(t, w)
	default:
		return drawUserEdit(t, w)
	}
}

// The node edits drawNodeEdit picks from.
const (
	editJoin = iota
	editLeave
	editRetag
	editOwner
	editAnnounce
	editApprove
	editWithdraw
	editUnapprove
	editSwap
	editClient
	editExpire
	editOnline
	editAddr
	numNodeEdits
)

func drawNodeEdit(t *rapid.T, w World) Edit {
	tp := w.Topology
	if len(tp.Nodes) == 0 {
		return Join{drawNode(t, tp.nextID(), tp.Users, tp.Nodes)}
	}

	kind := index(t, numNodeEdits, "node-edit")
	if kind == editJoin {
		return Join{drawNode(t, tp.nextID(), tp.Users, tp.Nodes)}
	}

	if kind == editSwap && len(tp.Nodes) >= 2 {
		a := index(t, len(tp.Nodes), "a")
		b := other(t, len(tp.Nodes), a, "b")

		return SwapAddrs{min(tp.Nodes[a].ID, tp.Nodes[b].ID), max(tp.Nodes[a].ID, tp.Nodes[b].ID), drawFamily(t)}
	}

	n := pick(t, tp.Nodes, "node")

	switch kind {
	case editLeave:
		return Leave{n.ID}
	case editRetag:
		if n.Tagged() && len(tp.Users) > 0 && chance(t, 2, "untag") {
			u := n.User
			if u == 0 {
				u = pick(t, tp.Users, "owner").ID
			}

			return Retag{n.ID, nil, u}
		}

		return Retag{n.ID, drawTags(t), n.User}
	case editOwner:
		var ids []uint

		for _, u := range tp.Users {
			if u.ID != n.User {
				ids = append(ids, u.ID)
			}
		}

		if n.Tagged() && n.User != 0 {
			ids = append(ids, 0)
		}

		if len(ids) > 0 {
			return SetOwner{n.ID, pick(t, ids, "user")}
		}
	case editAnnounce, editWithdraw:
		if kind == editWithdraw && len(n.Announced) > 0 {
			return Withdraw{n.ID, drawHeld(t, n.Announced)}
		}

		if rs := dropRoutes(drawRouteChoice(t), n.Announced); len(rs) > 0 {
			return Announce{n.ID, rs}
		}

		return Withdraw{n.ID, drawHeld(t, n.Announced)}
	case editApprove, editUnapprove:
		if kind == editUnapprove && len(n.Approved) > 0 {
			return Unapprove{n.ID, drawHeld(t, n.Approved)}
		}

		// Mostly what the node announces and is not approved for.
		if pending := dropRoutes(n.Announced, n.Approved); len(pending) > 0 && !chance(t, 3, "unannounced") {
			return Approve{n.ID, drawHeld(t, pending)}
		}

		if rs := dropRoutes(drawRouteChoice(t), n.Approved); len(rs) > 0 {
			return Approve{n.ID, rs}
		}

		return Unapprove{n.ID, drawHeld(t, n.Approved)}
	case editExpire:
		return SetExpired{n.ID, !n.Expired}
	case editOnline:
		return SetOnline{n.ID, n.Offline}
	case editAddr, editSwap:
		return drawSetAddr(t, n, tp.Nodes)
	}

	return SetClient{n.ID, Client(other(t, numClients, int(n.Client), "client"))} //nolint:gosec // a few clients
}

func drawFamily(t *rapid.T) int {
	if rapid.Bool().Draw(t, "v6") {
		return 6
	}

	return 4
}

// drawHeld draws routes from held, both halves of an exit route mostly
// together.
func drawHeld(t *rapid.T, held []int) []int {
	r := pick(t, held, "route")

	if r == exit4 || r == exit6 {
		both := exit4 + exit6 - r
		if slices.Contains(held, both) && !chance(t, 4, "one-family") {
			return []int{exit4, exit6}
		}
	}

	return []int{r}
}

// drawSetAddr moves n in one family: back to its own address, to none,
// to a tailnet address nobody owns, outside the tailnet, or onto an
// address another node holds.
func drawSetAddr(t *rapid.T, n Node, nodes []Node) Edit {
	family := drawFamily(t)
	cur := n.Addr(family)

	to := []netip.Addr{ownAddr(family, uint64(n.ID)), {}, movedAddr(family, uint64(n.ID))}
	to = append(to, outsidePool(family)...)
	to = append(to, heldAddrs(family, nodes, cur)...)
	to = slices.DeleteFunc(to, func(a netip.Addr) bool { return a == cur })

	return SetAddr{n.ID, family, pick(t, to, "to")}
}

func drawUserEdit(t *rapid.T, w World) Edit {
	users := w.Topology.Users

	kind := index(t, 4, "user-edit")
	if len(users) == 0 {
		kind = 0
	}

	switch kind {
	case 1:
		u := pick(t, users, "user")
		names := slices.DeleteFunc(slices.Clone(userNames), func(n string) bool { return n == u.Name })

		return RenameUser{u.ID, pick(t, names, "name")}
	case 2:
		u := pick(t, users, "user")
		emails := slices.DeleteFunc(slices.Clone(userEmails), func(e string) bool { return e == u.Email })

		return SetEmail{u.ID, pick(t, emails, "email")}
	case 3:
		var free []uint

		for _, u := range users {
			if !slices.ContainsFunc(w.Topology.Nodes, func(n Node) bool { return n.User == u.ID }) {
				free = append(free, u.ID)
			}
		}

		if len(free) > 0 {
			return DeleteUser{pick(t, free, "user")}
		}
	}

	var id uint
	for _, u := range users {
		id = max(id, u.ID)
	}

	return AddUser{User{ID: id + 1, Name: pick(t, userNames, "name"), Email: pick(t, userEmails, "email")}}
}

// The policy edits drawPolicyEdit picks from; the first seven keep the
// selector set when they can.
const (
	editPorts = iota
	editProto
	editSwapRules
	editSel
	editGroup
	editHost
	editTagOwners
	editAddRule
	editRemoveRule
	editSSH
	editNodeAttrs
	editAutoApprovers
	numPolicyEdits
)

func drawPolicyEdit(t *rapid.T, w World) Edit {
	p := w.Policy
	refs := p.Refs()

	kind := index(t, numPolicyEdits, "policy-edit")

	switch kind {
	case editPorts:
		if e, ok := drawSetPorts(t, p); ok {
			return e
		}
	case editProto:
		if e, ok := drawSetProto(t, p); ok {
			return e
		}
	case editSwapRules:
		var lists []bool

		for _, grant := range []bool{false, true} {
			if len(p.List(grant)) >= 2 {
				lists = append(lists, grant)
			}
		}

		if len(lists) > 0 {
			grant := pick(t, lists, "list")
			n := len(p.List(grant))
			i := index(t, n, "i")
			j := other(t, n, i, "j")

			return SwapRules{grant, min(i, j), max(i, j)}
		}
	case editSel:
		if len(refs) > 0 {
			return drawSetSel(t, p, pick(t, refs, "rule"))
		}
	case editGroup:
		return SetGroup{index(t, numGroups, "group"), drawMembers(t)}
	case editHost:
		// Mostly a host the policy names.
		h := index(t, numHosts, "host")
		if named := p.referenced().hosts; !chance(t, 4, "unnamed") {
			var hs []int

			for i, ok := range named {
				if ok {
					hs = append(hs, i)
				}
			}

			if len(hs) > 0 {
				h = pick(t, hs, "named")
			}
		}

		return SetHost{h, other(t, numRulePrefixes, p.Hosts[h], "shift")}
	case editTagOwners:
		e := SetTagOwners{Tag: index(t, numTags, "tag")}
		if !chance(t, 3, "no-owners") {
			e.Owners = owners.Draw(t, "owners")
		}

		return e
	case editRemoveRule:
		if len(refs) > 0 {
			return RemoveRule{pick(t, refs, "rule")}
		}
	case editSSH:
		if chance(t, 4, "none") {
			return SetSSH{}
		}

		return SetSSH{sshRuleLists.Draw(t, "ssh")}
	case editNodeAttrs:
		if chance(t, 4, "none") {
			return SetNodeAttrs{}
		}

		return SetNodeAttrs{attrRules.Draw(t, "nodeAttrs")}
	case editAutoApprovers:
		if chance(t, 4, "none") {
			return SetAutoApprovers{}
		}

		return SetAutoApprovers{drawAutoApprovers(t)}
	}

	grant := chance(t, 2, "grant")

	return AddRule{RuleRef{grant, rapid.IntRange(0, len(p.List(grant))).Draw(t, "at")}, drawRule(t, grant, p)}
}

func drawSetPorts(t *rapid.T, p Policy) (Edit, bool) {
	type place struct {
		ref RuleRef
		at  int
	}

	var places []place

	for _, ref := range p.Refs() {
		r := p.Rule(ref)
		if ref.Grant {
			for i, ip := range r.IP {
				if ip.Proto < portedProtos {
					places = append(places, place{ref, i})
				}
			}
		} else if r.Proto < portedProtos {
			for i := range r.Dst {
				places = append(places, place{ref, i})
			}
		}
	}

	if len(places) == 0 {
		return nil, false
	}

	pl := pick(t, places, "place")
	r := p.Rule(pl.ref)

	n, cur := len(Ports), 0
	if pl.ref.Grant {
		n, cur = grantPorts, r.IP[pl.at].Ports
	} else {
		cur = r.Dst[pl.at].Ports
	}

	return SetPorts{pl.ref, pl.at, other(t, n, cur, "ports")}, true
}

// drawSetProto changes a protocol to one the ports allow.
func drawSetProto(t *rapid.T, p Policy) (Edit, bool) {
	refs := slices.DeleteFunc(p.Refs(), func(ref RuleRef) bool { return ref.Grant && len(p.Rule(ref).IP) == 0 })
	if len(refs) == 0 {
		return nil, false
	}

	ref := pick(t, refs, "rule")
	r := p.Rule(ref)

	at, cur, ported := 0, r.Proto, slices.ContainsFunc(r.Dst, func(d Dest) bool { return d.Ports != 0 })
	if ref.Grant {
		at = index(t, len(r.IP), "ip")
		cur, ported = r.IP[at].Proto, r.IP[at].Ports != 0
	}

	n := len(Protos)
	if ported {
		n = portedProtos
	}

	if n == 1 {
		return nil, false
	}

	proto := index(t, n-1, "proto")
	if proto >= cur {
		proto++
	}

	return SetProto{ref, at, proto}, true
}

// drawSetSel replaces one selector of rule ref: half the time with one
// the policy names elsewhere, which keeps its selector set if the old one
// is named elsewhere too. autogroup:self is neither replaced nor added.
func drawSetSel(t *rapid.T, p Policy, ref RuleRef) Edit {
	r := p.Rule(ref)

	var dstAt []int

	for i, d := range r.Dst {
		if d.Sel.Kind != SelSelf {
			dstAt = append(dstAt, i)
		}
	}

	dst := len(dstAt) > 0 && rapid.Bool().Draw(t, "dst")

	var (
		at    int
		kinds []SelKind
	)

	switch {
	case dst:
		at = pick(t, dstAt, "at")

		kinds = dstKinds
		if len(r.App) > 0 {
			kinds = appDstKinds
		}
	default:
		at = index(t, len(r.Src), "at")

		kinds = srcKinds

		switch {
		case r.selfRule() && ref.Grant:
			kinds = selfSrcGrant
		case r.selfRule():
			kinds = selfSrcACL
		}
	}

	if chance(t, 2, "named") {
		named := slices.DeleteFunc(p.Selectors(), func(s Sel) bool { return !slices.Contains(kinds, s.Kind) })
		if len(named) > 0 {
			return SetSel{ref, dst, at, pick(t, named, "sel")}
		}
	}

	return SetSel{ref, dst, at, drawSel(t, kinds)}
}

func canonPolicy(p Policy) Policy {
	w := World{Policy: p}
	canon(&w)

	return w.Policy
}

func canonTopology(tp Topology) Topology {
	w := World{Topology: tp}
	canon(&w)

	return w.Topology
}
