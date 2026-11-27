package policymodel

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
)

// Scripts for change routing: steps after which one part of what a
// session is sent moves while nothing else that would wake it does, so a
// routing that forgets that part leaves the session stale with nothing
// else to cover for it. Each builds its own nodes and rules beside
// whatever the world holds, and is nothing when no policy write would be
// accepted or no user token names one user alone. What the drawn rules
// already give the script's nodes can cover for the part a script moves;
// the routing properties count how often it stood alone.

// scriptTag and routerTag are the tags the scripts put their own nodes
// under.
const (
	scriptTag = 2
	routerTag = 0
)

// scriptOwner returns a user token naming one user alone, and that user,
// in a world whose document a policy write would accept.
func scriptOwner(w World) (int, uint, bool) {
	v := NewView(w)

	// A user added since the document was written can make a token it
	// holds name two users: a policy write is refused then.
	if len(v.AmbiguousRefs()) > 0 {
		return 0, 0, false
	}

	for i := range UserRefs {
		if users := v.RefUsers(i); len(users) == 1 && !v.Ambiguous(i) {
			return i, users[0], true
		}
	}

	return 0, 0, false
}

// scriptNode is a node registering into w at its own addresses: owner's,
// or tagged when tags are given.
func scriptNode(w World, owner uint, tags ...int) Node {
	id := w.Topology.nextID()
	n := Node{ID: id, User: owner, V4: ownAddr(4, uint64(id)), V6: ownAddr(6, uint64(id))}

	if len(tags) > 0 {
		n.User, n.Tags = 0, slices.Clone(tags)
	}

	return n
}

// script applies steps to w as they are added.
type script struct {
	w     World
	steps []Step
}

func (s *script) add(edits ...Edit) {
	s.w = s.w.Apply(edits...)
	s.steps = append(s.steps, Step{Edits: edits})
}

// join adds n, and approves what it announces unless auto-approval did.
func (s *script) join(nodes ...Node) {
	edits := make([]Edit, 0, len(nodes))

	for _, n := range nodes {
		edits = append(edits, Join{Node: n})
	}

	s.add(edits...)

	for _, n := range nodes {
		if j, _ := s.w.Topology.Node(n.ID); len(dropRoutes(n.Announced, j.Approved)) > 0 {
			s.add(Approve{ID: n.ID, Routes: n.Announced})
		}
	}
}

// define makes tags definable, keeping their owners.
func (s *script) define(tags ...int) {
	edits := make([]Edit, 0, len(tags))

	for _, t := range tags {
		edits = append(edits, SetTagOwners{Tag: t, Owners: s.w.Policy.TagOwners[t], Defined: true})
	}

	s.add(edits...)
}

// rules adds rules at the end of the ACLs, in one step.
func (s *script) rules(rs ...Rule) {
	n := len(s.w.Policy.ACLs)
	edits := make([]Edit, len(rs))

	for i, r := range rs {
		edits[i] = AddRule{Ref: RuleRef{I: n + i}, Rule: r}
	}

	s.add(edits...)
}

func rule(src Sel, dst Sel, ports int) Rule {
	return Rule{Src: []Sel{src}, Dst: []Dest{{Sel: dst, Ports: ports}}}
}

// toggle has group i take ref in and let it go, twice, then go back to
// what it held: each move one step.
func (s *script) toggle(i, ref int) {
	group := s.w.Policy.Groups[i]

	for range 2 {
		s.add(SetGroup{Group: i, Members: withRef(group, ref, false)})
		s.add(SetGroup{Group: i, Members: withRef(group, ref, true)})
	}

	s.add(SetGroup{Group: i, Members: group})
}

// withRef is members with ref in it or out of it, in place.
func withRef(members []int, ref int, in bool) []int {
	out := slices.DeleteFunc(slices.Clone(members), func(m int) bool { return m == ref })
	if in {
		out = append(out, ref)
	}

	return out
}

// RouteViewScript is steps from w that move a viewer's side set and
// nothing else the renderer keys its routed peers by: a router of tag:a
// serving 10.0.0.0/24 that every member sees, a node of a user one token
// names alone, and group:a, which alone reaches the route, taking that
// token in and letting it go, twice. What moves for the viewer is the
// routes it is given (RouteViewers): its peers and filter stay.
func RouteViewScript(w World) []Step {
	ref, owner, ok := scriptOwner(w)
	if !ok {
		return nil
	}

	s := &script{w: w}
	s.define(routerTag)

	router := scriptNode(s.w, 0, routerTag)
	router.Announced = []int{0}

	s.rules(
		Rule{Src: []Sel{{Kind: SelMember}}, Dst: []Dest{{Sel: Sel{Kind: SelTag}}}},
		Rule{Src: []Sel{{Kind: SelGroup}}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix}}}},
	)
	s.join(router)
	s.join(scriptNode(s.w, owner))

	s.toggle(0, ref)

	return s.steps
}

// PeerSetScript is steps from w after which a node of tag:c, the source
// of a rule to group:b, gains the nodes of a user one token names alone as
// peers and loses them, twice, as the user joins group:b and leaves: its
// own filter stays, its peers move (PeerSets). What the user's nodes are
// sent moves too, by their filters, and in capability form by their
// stamps.
func PeerSetScript(w World) []Step {
	ref, owner, ok := scriptOwner(w)
	if !ok {
		return nil
	}

	s := &script{w: w}
	s.define(scriptTag)
	s.join(scriptNode(s.w, 0, scriptTag))
	s.join(scriptNode(s.w, owner))
	s.rules(rule(Sel{Kind: SelTag, I: scriptTag}, Sel{Kind: SelGroup, I: 1}, 1))
	s.toggle(1, ref)

	return s.steps
}

// StampScript is steps from w after which a user one token names alone
// leaves group:b and comes back, twice, while a node of tag:c it already sees
// takes rules from group:b. In capability form the node's filter names
// the group and stays: only the user's stamps move (Caps). In address
// form its filter moves, and nothing else of it does (Filters).
func StampScript(w World) []Step {
	ref, owner, ok := scriptOwner(w)
	if !ok {
		return nil
	}

	s := &script{w: w}
	s.define(scriptTag)
	s.join(scriptNode(s.w, 0, scriptTag))
	s.join(scriptNode(s.w, owner))

	tagged := Sel{Kind: SelTag, I: scriptTag}
	s.rules(rule(Sel{Kind: SelUser, I: ref}, tagged, 2), rule(Sel{Kind: SelGroup, I: 1}, tagged, 1))
	s.toggle(1, ref)

	return s.steps
}

// CoverScript is steps from w after which a router of tag:a serving every
// node's IPv6 (fd7a:115c:a1e0::/120) gains, in what its route covers, the
// nodes of a user a viewer of tag:c reaches through group:b, and loses
// them, twice. The router and a node of the user are exit nodes, which the
// viewer sees through the internet, so no rule of the viewer's names an
// address the route covers until the user joins group:b: its peers and
// filter stay, what it is given of the router's route moves with the
// route's cover alone (Routers). In capability form the user's stamps move
// as well. The user is one a token names alone, a new one when a token
// names nobody, so that no other node of theirs joins the viewer's peers.
func CoverScript(w World) []Step {
	const cover = 5

	v := NewView(w)
	if len(v.AmbiguousRefs()) > 0 {
		return nil
	}

	s := &script{w: w}
	s.define(routerTag, scriptTag)

	ref := -1

	for i := range refUsers {
		if len(v.RefUsers(i)) == 0 && !v.Ambiguous(i) {
			ref = i

			// An identity provider's user, whose name need not be unique.
			token := strings.TrimSuffix(UserRefs[i], "@")
			name, _, isEmail := strings.Cut(token, "@")
			u := User{ID: s.w.Topology.nextUserID(), Name: name}
			u.Provider = providerPrefix + strconv.FormatUint(uint64(u.ID), 10)

			if isEmail {
				u.Email = token
			}

			s.add(AddUser{User: u})

			break
		}
	}

	if ref < 0 {
		r, _, ok := scriptOwner(w)
		if !ok {
			return nil
		}

		ref = r
	}

	owner := NewView(s.w).RefUsers(ref)
	if len(owner) != 1 {
		return nil
	}

	group := s.w.Policy.Groups[1]
	tagged := Sel{Kind: SelTag, I: scriptTag}

	s.add(SetGroup{Group: 1, Members: nil})
	s.rules(rule(tagged, Sel{Kind: SelInternet}, 0), rule(tagged, Sel{Kind: SelGroup, I: 1}, 1))

	router := scriptNode(s.w, 0, routerTag)
	router.Announced = []int{cover, exit4, exit6}
	s.join(router)
	s.join(scriptNode(s.w, 0, scriptTag))

	exit := scriptNode(s.w, owner[0])
	exit.Announced = []int{exit4, exit6}
	s.join(exit)

	for range 2 {
		s.add(SetGroup{Group: 1, Members: []int{ref}})
		s.add(SetGroup{Group: 1, Members: nil})
	}

	s.add(SetGroup{Group: 1, Members: group})

	return s.steps
}

// Failover is two routers of tag:a serving 10.0.1.0/24 and a node of a
// user one token names alone reaching it: what a session's history and
// the HA prober decide, once the steps are taken. Routers are in ID
// order.
type Failover struct {
	Steps   []Step
	Routers [2]types.NodeID
	Viewer  types.NodeID
}

// FailoverScript is the steps that set a [Failover] up in w, or false.
func FailoverScript(w World) (Failover, bool) {
	ref, owner, ok := scriptOwner(w)
	if !ok {
		return Failover{}, false
	}

	const subnet = 7

	s := &script{w: w}
	s.define(routerTag)
	s.rules(rule(Sel{Kind: SelUser, I: ref}, Sel{Kind: SelPrefix, I: subnet}, 0))

	var f Failover

	for i := range f.Routers {
		r := scriptNode(s.w, 0, routerTag)
		r.Announced = []int{subnet}
		s.join(r)
		f.Routers[i] = r.ID
	}

	viewer := scriptNode(s.w, owner)
	s.join(viewer)

	f.Steps, f.Viewer = s.steps, viewer.ID

	return f, true
}

// Elections is what the documented election reads beyond a world: when
// each node's current run of sessions began, the routers the HA prober
// holds unhealthy, and who served each subnet route last. A world that
// connected all at once and has no prober holds none of it, and elects
// the lowest available ID; the route of a router none can take over is
// then history's to say, and left unjudged.
type Elections struct {
	// Started orders the runs of sessions: lower began earlier.
	Started map[types.NodeID]uint64
	// Unhealthy are the routers the prober failed.
	Unhealthy map[types.NodeID]bool
	// Held is who served each subnet route at the last commit.
	Held map[netip.Prefix]types.NodeID
}

// NewElections is a history in which nothing has happened.
func NewElections() *Elections {
	return &Elections{Started: map[types.NodeID]uint64{}, Unhealthy: map[types.NodeID]bool{}, Held: map[netip.Prefix]types.NodeID{}}
}

// WithElections returns r electing with e's history.
func (r *Ref) WithElections(e *Elections) *Ref {
	out := *r
	out.elections = e

	return &out
}

// available reports whether n can take a route: online, unexpired and
// not failed by the prober.
func (e *Elections) available(n RefNode) bool {
	return !n.Unavailable && (e == nil || !e.Unhealthy[n.ID])
}

// elect is the documented session ordering among candidates, in ID
// order: of those online, healthy and unexpired, the one connected
// longest, ties to the lowest ID; false when none is available.
func (e *Elections) elect(candidates []RefNode) (types.NodeID, bool) {
	var (
		best  RefNode
		found bool
	)

	for _, n := range candidates {
		if !e.available(n) {
			continue
		}

		if !found || e != nil && e.Started[n.ID] < e.Started[best.ID] {
			best, found = n, true
		}
	}

	return best.ID, found
}

// primary is the tailnet-wide election of subnet route q among its
// routers, in ID order: the session ordering's choice; with none
// available, the router that held it while it still approves it, else
// the lowest-ID healthy one. Without a history, only the first is the
// world's to say.
func (e *Elections) primary(routers []RefNode, q netip.Prefix) (types.NodeID, bool) {
	if id, ok := e.elect(routers); ok {
		return id, true
	}

	if e == nil {
		return 0, false
	}

	if held, ok := e.Held[q]; ok && slices.ContainsFunc(routers, func(n RefNode) bool { return n.ID == held }) {
		return held, true
	}

	for _, n := range routers {
		if !e.Unhealthy[n.ID] {
			return n.ID, true
		}
	}

	return 0, false
}

// Commit records who holds each subnet route once nodes are as given and
// the prober holds unhealthy those it does, as every commit re-elects.
func (e *Elections) Commit(nodes []RefNode, unhealthy map[types.NodeID]bool) {
	e.Unhealthy = unhealthy

	nodes = slices.SortedFunc(slices.Values(nodes), func(a, b RefNode) int { return cmp.Compare(a.ID, b.ID) })
	routers := map[netip.Prefix][]RefNode{}

	for _, n := range nodes {
		for _, q := range n.subnets() {
			routers[q] = append(routers[q], n)
		}
	}

	held := make(map[netip.Prefix]types.NodeID, len(routers))

	for q, rs := range routers {
		if id, ok := e.primary(rs, q); ok {
			held[q] = id
		}
	}

	e.Held = held
}
