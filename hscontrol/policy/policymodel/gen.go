package policymodel

import (
	"net/netip"
	"reflect"
	"slices"
	"strconv"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// Every draw is shaped so that shrinking it towards zero gives the plain
// case: the first alternative, false flags, the smallest counts, a node
// on its own addresses. A rare shape sits behind a [chance], which is
// false at zero, and both sides of a chance make the same draws, so that
// lowering it is all rapid needs to take the rare shape out. Lists are
// rapid lists of whole elements, which the shrinker deletes one by one.
//
// What is drawn is what headscale's own writes produce, with two
// exceptions it reaches only through its database: addresses outside the
// tailnet, or changed after registration. They stay, rarely, because
// headscale starts on them. A node without addresses, or two holding one,
// it refuses at startup, so neither is drawn.

// Policies draws a policy: at least one rule, or rarely none, allowing
// everything.
func Policies() *rapid.Generator[Policy] { return policies }

// Topologies draws users and nodes: at least one of each, the first user
// always alice.
func Topologies() *rapid.Generator[Topology] { return topologies }

// Worlds draws a policy and a topology, as headscale holds them once its
// users are created, its policy is written and its nodes registered: the
// policy names no token two users answer to and defines every tag a node
// carries, and registration auto-approved what nodes announce.
func Worlds() *rapid.Generator[World] { return worlds }

// Scenarios draws a world and steps from it: up to maxSteps, and in one
// scenario in longScenarios up to longScenarioTimes as many; rarely none.
// Each step is drawn against the world the earlier ones produce, so every
// edit is a write headscale accepts where it lands.
func Scenarios(maxSteps int) *rapid.Generator[Scenario] {
	return rapid.Custom(func(t *rapid.T) Scenario {
		s := Scenario{Start: worlds.Draw(t, "start")}

		// Scripts begin some scenarios with sequences no run of single
		// draws reaches: an anchor's key moving, where the start holds
		// one; a node's form flipping, its address moving and its form
		// flipping back, unread until the end; and the same with a source
		// of its rules moving instead; and, last, a node moving onto an
		// identity that auto-approves a route it announces.
		move := chance(t, 2, "anchor-move")
		script := chance(t, 8, "flip-script")
		elsewhere := chance(t, 8, "flip-elsewhere")
		down := chance(t, 4, "primary-down")
		who := rapid.IntRange(0, anyOf).Draw(t, "flipper")
		tour := chance(t, 3, "form-tour")
		stops := tourStops.Draw(t, "tour-stops")
		approver := chance(t, approverScripts, "approver-script")
		way := index(t, numApproverWays, "approver-way")
		// Drawn after the other scripts' draws, so it moves none of them.
		twice := chance(t, doubleGrants, "double-grant")

		var scripted []Step

		w := s.Start

		if move {
			scripted = anchorMove(w)
		}

		for _, st := range scripted {
			w = w.Apply(st.Edits...)
			s.Steps = append(s.Steps, st)
		}

		if script {
			for _, st := range flipScript(w, who) {
				w = w.Apply(st.Edits...)
				s.Steps = append(s.Steps, st)
			}
		}

		if elsewhere {
			for _, st := range flipElsewhereScript(w, who+1) {
				w = w.Apply(st.Edits...)
				s.Steps = append(s.Steps, st)
			}
		}

		if tour {
			for _, st := range formTour(w, who, stops) {
				w = w.Apply(st.Edits...)
				s.Steps = append(s.Steps, st)
			}
		}

		if twice {
			for _, st := range doubleGrant(w, who) {
				w = w.Apply(st.Edits...)
				s.Steps = append(s.Steps, st)
			}
		}

		bounds, total := stepRuns(t, maxSteps, w)

		// Steps come in runs of a few, each run keeping to a focus, and
		// each step and each run is a group the shrinker can delete whole.
		run := rapid.Custom(func(t *rapid.T) []Step {
			f := drawFocus(t)

			return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Step {
				st := drawStep(t, w, f)
				w = w.Apply(st.Edits...)

				return st
			}), 1, bounds.each).Draw(t, "run")
		})

		for _, r := range rapid.SliceOfN(run, bounds.least, bounds.most).Draw(t, "steps") {
			s.Steps = append(s.Steps, r...)
		}

		if len(s.Steps) > total {
			s.Steps = s.Steps[:total]
		}

		// A node moving onto an approver comes after the drawn steps,
		// which make room for it: cut short, it would not move.
		if approver {
			if as := approverScript(s.end(), who, way); len(as) > 0 {
				if over := len(s.Steps) + len(as) - total; over > 0 {
					s.Steps = s.Steps[:max(0, len(s.Steps)-over)]
					as = approverScript(s.end(), who, way)
				}

				s.Steps = append(s.Steps, as...)
			}
		}

		// A primary goes down last, so that no drawn step after it needs
		// its offline router: a failure that needs a node gone offline
		// shrinks to a drawn one, not to the script and the routers it
		// takes.
		if down {
			if pd := primaryDown(s.end()); len(pd) > 0 {
				if over := len(s.Steps) + len(pd) - total; over > 0 {
					s.Steps = s.Steps[:max(0, len(s.Steps)-over)]
					pd = primaryDown(s.end())
				}

				s.Steps = append(s.Steps, pd...)
			}
		}

		return s
	})
}

// flipScript is three steps on an eligible node of w: its client stops
// being official, its address moves, its client is official again, and
// then it reads.
func flipScript(w World, who int) []Step {
	v := NewView(w)

	var eligible []Node

	for _, n := range w.Topology.Nodes {
		if v.Eligible(n) {
			eligible = append(eligible, n)
		}
	}

	if len(eligible) == 0 {
		return nil
	}

	n := eligible[who%len(eligible)]

	to := movedAddr(4, uint64(n.ID))
	if n.V4 == to {
		to = ownAddr(4, uint64(n.ID))
	}

	return []Step{
		{Edits: []Edit{SetClient{n.ID, Unknown}}},
		{Edits: []Edit{SetAddr{n.ID, 4, to}}},
		{Edits: []Edit{SetClient{n.ID, Official}}, Reads: []types.NodeID{n.ID}},
	}
}

// flipElsewhereScript is four steps on an eligible node of w, which
// cut its address form and carry it across a change only that form sees:
// its client stops being official and it reads; it is official again;
// a node joins a source of its rules; its client stops being official
// again and it reads. None when no eligible node's rules have another
// node in such a source.
func flipElsewhereScript(w World, who int) []Step {
	v := NewView(w)

	var eligible []Node

	for _, n := range w.Topology.Nodes {
		if v.Eligible(n) {
			eligible = append(eligible, n)
		}
	}

	// The joiner is like a member of an identity source of n's rules, so
	// it joins that source.
	like := func(n Node) (Node, bool) {
		for _, ref := range w.Policy.Refs() {
			r := w.Policy.Rule(ref)
			if !slices.ContainsFunc(r.Dst, func(d Dest) bool { return v.names(d.Sel, n) }) {
				continue
			}

			for _, s := range r.Src {
				if s.Kind != SelUser && s.Kind != SelGroup && s.Kind != SelTag && s.Kind != SelMember && s.Kind != SelTagged {
					continue
				}

				if i := slices.IndexFunc(v.MembersOf(s), func(m Node) bool { return m.ID != n.ID }); i >= 0 {
					return v.MembersOf(s)[i], true
				}
			}
		}

		return Node{}, false
	}

	for k := range eligible {
		n := eligible[(who+k)%len(eligible)]

		m, ok := like(n)
		if !ok {
			continue
		}

		id := w.Topology.nextID()
		joiner := Node{ID: id, User: m.User, Tags: m.Tags, V4: ownAddr(4, uint64(id)), V6: ownAddr(6, uint64(id))}

		return []Step{
			{Edits: []Edit{SetClient{n.ID, Unknown}}, Reads: []types.NodeID{n.ID}},
			{Edits: []Edit{SetClient{n.ID, Official}}},
			{Edits: []Edit{Join{joiner}}},
			{Edits: []Edit{SetClient{n.ID, Unknown}}, Reads: []types.NodeID{n.ID}},
		}
	}

	return nil
}

// primaryDown takes offline the lowest-ID available router of the first
// route w has two routers for, which every session then reads, and brings
// it back: the election moves the route and moves it back. None when no
// route has two routers, one of them available.
func primaryDown(w World) []Step {
	byRoute := map[int][]Node{}

	for _, n := range w.Topology.Nodes {
		for _, r := range served(n) {
			if r != exit4 && r != exit6 {
				byRoute[r] = append(byRoute[r], n)
			}
		}
	}

	all := make([]types.NodeID, 0, len(w.Topology.Nodes))
	for _, n := range w.Topology.Nodes {
		all = append(all, n.ID)
	}

	for r := range Prefixes {
		routers := byRoute[r]

		i := slices.IndexFunc(routers, func(n Node) bool { return !n.Offline && !n.Expired })
		if len(routers) < 2 || i < 0 {
			continue
		}

		id := routers[i].ID

		return []Step{
			{Edits: []Edit{SetOnline{id, false}}, Reads: all},
			{Edits: []Edit{SetOnline{id, true}}, Reads: all},
		}
	}

	return nil
}

// anchorMove moves the key of the first anchor w's document holds by its
// first rule's protocol, which keeps the selector table, and every
// session reads. None when w holds no anchor.
func anchorMove(w World) []Step {
	ans := NewView(w).anchors()
	if len(ans) == 0 {
		return nil
	}

	ref, then := ans[0].first, w.Policy.Rule(ans[0].then)
	r := w.Policy.Rule(ref)

	// The ip entry sharing then's protocol, for a grant.
	at, cur := 0, r.Proto
	if ref.Grant {
		at = slices.IndexFunc(r.IP, func(ip IP) bool { return slices.Contains(protos(then, ans[0].then.Grant), ip.Proto) })
		cur = r.IP[at].Proto
	}

	// TCP takes the ports every protocol before it does.
	proto := slices.Index(Protos, "tcp")
	if cur == proto {
		proto = 0
	}

	st := Step{Edits: []Edit{SetProto{ref, at, proto}}}
	for _, n := range w.Topology.Nodes {
		st.Reads = append(st.Reads, n.ID)
	}

	return []Step{st}
}

// Steps draws one step valid against w, for a state machine that takes
// its steps as it goes: one edit mostly; sometimes several committed
// together, a node deleted and another registered at its address, or a
// route announced and approved in one go; then which sessions read.
func Steps(w World) *rapid.Generator[Step] {
	return rapid.Custom(func(t *rapid.T) Step {
		st := Step{Edits: drawEdits(t, w)}
		st.Reads = drawReads(t, w.Apply(st.Edits...))

		return st
	})
}

var (
	policies = rapid.Custom(func(t *rapid.T) Policy {
		return canonPolicy(drawPolicy(t))
	})
	topologies = rapid.Custom(func(t *rapid.T) Topology {
		return canonTopology(drawTopology(t))
	})
	worlds = rapid.Custom(func(t *rapid.T) World {
		w := World{Policy: policies.Draw(t, "policy"), Topology: topologies.Draw(t, "topology")}

		// Shapes a policy and a topology make only together, each in one
		// world in eight to sixteen: an own rule that reaches nothing on
		// its receiver yet places a merged rule; an app grant to public space
		// that exits see one way; three rules merging into one; a merged
		// rule placed by an earlier rule its receiver does not get; a via
		// grant to autogroup:internet at an exit node among its sources,
		// beside public routes; a router meeting three contested clauses.
		// The merges go in last, as the first of them takes every ACL
		// away.
		merge := chance(t, 14, "merge-anchor")
		anchor := chance(t, 8, "own-anchor")
		oneWay := chance(t, 8, "one-way-world")
		via := chance(t, 5, "via-routers")
		down := chance(t, 2, "via-router-down")
		cover := chance(t, 2, "via-router-covered")
		fan := chance(t, mergeFans, "merge-fan")
		who := rapid.IntRange(0, anyOf).Draw(t, "who")
		viaNet := chance(t, viaInternetWorlds, "via-internet")
		viaNetShape := viaInternets.Draw(t, "via-internet-shape")
		stacked := chance(t, stackedRouters, "stacked-router")

		if via {
			viaRouters(&w, who, down, cover)
		}

		if viaNet {
			viaInternetWorld(&w, who+1, viaNetShape)
		}

		if stacked {
			stackedRouter(&w, who+2)
		}

		if anchor {
			ownAnchor(&w, who)
		}

		if oneWay {
			oneWayWorld(&w, who)
		}

		if fan {
			mergeFan(&w, who)
		}

		if merge {
			mergeAnchor(&w, who+1)
		}

		return settle(w)
	})
)

// ownAnchor puts in front of w's ACLs a self rule and a shared rule of one
// key, alice's to port 22, with a rule of another key between; makes a
// node of w, not alice's, a router of 10.0.0.0/24 and an IPv6 exit node;
// and leaves alice's nodes IPv4 only. An exit node takes every owner's
// self rules, and alice's reaches nothing on it, yet places where the
// shared rule, which reaches its route, merges. A world of one node, or
// without a tag or a second user to give the router, gets the rules alone.
func ownAnchor(w *World, who int) {
	alice := Sel{Kind: SelUser}
	ssh := slices.Index(Ports, "22")
	rules := []Rule{
		{Src: []Sel{alice}, Dst: []Dest{{Sel: Sel{Kind: SelSelf}, Ports: ssh}}},
		{Src: []Sel{{Kind: SelAll}}, Dst: []Dest{{Sel: Sel{Kind: SelAll}}}},
		{Src: []Sel{alice}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix}, Ports: ssh}}},
	}
	w.Policy.ACLs, w.Policy.AllowAll = append(rules, w.Policy.ACLs...), false

	nodes, users := w.Topology.Nodes, w.Topology.Users
	if len(nodes) < 2 {
		return
	}

	n := &nodes[1+who%(len(nodes)-1)]

	switch tag := ownedTag(w.Policy); {
	case tag >= 0:
		n.User, n.Tags = 0, []int{tag}
	case len(users) > 1:
		n.User, n.Tags = users[1].ID, nil
	default:
		return
	}

	n.Announced, n.Approved = addRoutes(n.Announced, []int{0, exit6}), addRoutes(n.Approved, []int{0, exit6})

	// The rules' sources: alice's nodes, which the exit route misses.
	nodes[0].User, nodes[0].Tags = 1, nil

	for i := range nodes {
		if a := &nodes[i]; a.User == 1 && !a.Tagged() {
			a.V4, a.V6 = ownAddr(4, uint64(a.ID)), netip.Addr{}
		}
	}
}

// mergeAnchor puts in front of w's ACLs two UDP rules from the members,
// one to themselves and one to tag:c, with a rule from * to tag:c
// between; and makes a node of w a tag:c node whose client looks no
// capability up, so its filter goes as addresses. There the second
// member rule merges at the first's place, which the node does not
// receive: moving the first's key moves where the merged rule sits.
func mergeAnchor(w *World, who int) {
	members, tag := Sel{Kind: SelMember}, Sel{Kind: SelTag, I: 2}
	udp := slices.Index(Protos, "udp")
	rules := []Rule{
		{Src: []Sel{members}, Dst: []Dest{{Sel: members}}, Proto: udp},
		{Src: []Sel{{Kind: SelAll}}, Dst: []Dest{{Sel: tag}}},
		{Src: []Sel{members}, Dst: []Dest{{Sel: tag}}, Proto: udp},
	}
	w.Policy.ACLs, w.Policy.AllowAll = append(rules, w.Policy.ACLs...), false

	// A node to receive them, joining a world of one.
	if t := &w.Topology; len(t.Nodes) == 1 {
		id := t.nextID()
		t.Nodes, t.NextID = append(t.Nodes, Node{ID: id, V4: ownAddr(4, uint64(id)), V6: ownAddr(6, uint64(id))}), id+1
	}

	nodes := w.Topology.Nodes

	// The members' rules reach a member.
	m := &nodes[0]
	m.User, m.Tags = 1, nil

	// Not a router: those are recut whenever any rule moves.
	r := &nodes[1+who%(len(nodes)-1)]
	r.User, r.Tags, r.Client = 0, []int{tag.I}, Unknown
	r.Announced, r.Approved, r.AutoApproved = nil, nil, nil
}

// oneWayWorld leaves w one rule, alice's app grant to public space, and
// makes a node of w an exit: the exit sees alice's nodes, which do not see
// it. Not alice's, since her own nodes see each other both ways: an
// alice node is tagged with a tag tagOwners defines, and with none the
// exit stays alice's.
func oneWayWorld(w *World, who int) {
	w.Policy.ACLs, w.Policy.AllowAll = nil, false
	w.Policy.Grants = []Rule{{Src: []Sel{{Kind: SelUser}}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix, I: publicPrefix}}}, App: []App{{}}}}

	if nodes := w.Topology.Nodes; len(nodes) > 0 {
		n := &nodes[who%len(nodes)]
		if tag := ownedTag(w.Policy); n.User == 1 && tag >= 0 {
			n.Tags, n.User = []int{tag}, 0
		}

		n.Announced, n.Approved = addRoutes(n.Announced, []int{exit4, exit6}), addRoutes(n.Approved, []int{exit4, exit6})
	}
}

// ownedTag is the first tag p's tagOwners defines, or -1. Injections tag
// nodes only with it: a tag they defined themselves would hold up the
// shrinker, which cannot drop the injection from a failure that needs a
// tag and nothing else of it.
func ownedTag(p Policy) int {
	for i := range numTags {
		if p.Defined[i] || len(p.TagOwners[i]) > 0 {
			return i
		}
	}

	return -1
}

// viaRouters leaves w one rule, alice's grant to 10.0.0.0/24 via the
// first tag w's tagOwners defines ([ownedTag]), and makes two nodes of w
// routers of that tag serving that route, so the via election has a
// choice; when down, the lower ID of them is one drawn offline. Nothing
// else gives alice the route, so steering alone decides who carries it.
// When covered, the first router also serves a route over alice's node,
// which puts it on its own grant's sources, and a node not alice's a
// route over the router: what headscale links with a covered via router,
// which drawn routes meet only among the first few nodes. A world of
// fewer than three nodes is left as it is: nodes added here would be
// ones the shrinker cannot take away.
func viaRouters(w *World, who int, down, covered bool) {
	t := &w.Topology

	tag := ownedTag(w.Policy)
	if len(t.Nodes) < 3 || tag < 0 {
		return
	}

	w.Policy.ACLs, w.Policy.AllowAll = nil, false
	w.Policy.Grants = []Rule{{Src: []Sel{{Kind: SelUser}}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix}}}, IP: []IP{{}}, Via: []int{tag}}}

	nodes := t.Nodes

	// The source: an alice node.
	a := &nodes[0]
	a.User, a.Tags = 1, nil

	first := 1 + who%(len(nodes)-1)
	second := 1 + (first % (len(nodes) - 1))

	// Down makes the lower router a node drawn offline, and none when no
	// node is: an offline router made here would hold up the shrinker as
	// a tag would.
	if i := slices.IndexFunc(nodes[1:len(nodes)-1], func(n Node) bool { return n.Offline }); down && i >= 0 {
		first, second = 1+i, 2+i
	}

	for _, i := range []int{first, second} {
		r := &nodes[i]
		r.User, r.Tags, r.Offline, r.Expired = 0, []int{tag}, down && i == first && r.Offline && first < second, false
		r.Announced, r.Approved = addRoutes(r.Announced, []int{0}), addRoutes(r.Approved, []int{0})
	}

	r := &nodes[first]
	for i := range nodes {
		c := &nodes[i]
		if !covered || i == 0 || i == first || i == second || c.User == 1 && !c.Tagged() {
			continue
		}

		if src, ok := coverOf(*a); ok {
			r.Announced, r.Approved = addRoutes(r.Announced, []int{src}), addRoutes(r.Approved, []int{src})
		}

		if over, ok := coverOf(*r); ok {
			c.Announced, c.Approved = addRoutes(c.Announced, []int{over}), addRoutes(c.Approved, []int{over})
		}

		break
	}
}

// coverOf is the narrowest prefix a rule or route may name that holds one
// of n's addresses.
func coverOf(n Node) (int, bool) {
	best := -1

	for i, p := range Prefixes[:numRulePrefixes] {
		if slices.ContainsFunc(n.Addrs(), p.Contains) && (best < 0 || p.Bits() > Prefixes[best].Bits()) {
			best = i
		}
	}

	return best, best >= 0
}

// settle makes w a world headscale can hold: its policy accepted for its
// users, every tag a node carries defined, every node registered with what
// it announces auto-approved.
func settle(w World) World {
	v := NewView(w)
	w.Policy = w.Policy.mapRefs(func(r int) int { return unambiguous(v, r) })

	for _, n := range w.Topology.Nodes {
		for _, tag := range n.Tags {
			if !w.Policy.DefinesTag(tag) {
				w.Policy.Defined[tag] = true
			}
		}
	}

	// Registration approved what the auto-approvers approve of what each
	// node announces; an admin approved the rest.
	v = NewView(w)

	for i, n := range w.Topology.Nodes {
		for _, r := range n.Announced {
			if v.Approvable(n, r) {
				w.Topology.Nodes[i].Approved = addRoutes(w.Topology.Nodes[i].Approved, []int{r})
				w.Topology.Nodes[i].AutoApproved = addRoutes(w.Topology.Nodes[i].AutoApproved, []int{r})
			}
		}
	}

	canon(&w)

	return w
}

// unambiguous is ref if it names at most one user in v, else the next
// token that does: the domain and the provider identifier always do.
func unambiguous(v *View, ref int) int {
	for i := range UserRefs {
		if r := (ref + i) % len(UserRefs); !v.Ambiguous(r) {
			return r
		}
	}

	return ref
}

// chance is true about once in k draws, and false when shrunk.
func chance(t *rapid.T, k int, label string) bool {
	return rapid.IntRange(0, k-1).Draw(t, label) == k-1
}

func index(t *rapid.T, n int, label string) int { return rapid.IntRange(0, n-1).Draw(t, label) }

func pick[E any](t *rapid.T, from []E, label string) E { return from[index(t, len(from), label)] }

// pickAny picks from a list whose length the world decides, with a draw
// that does not: what it reads stays aligned when shrinking changes the
// list.
func pickAny[E any](t *rapid.T, from []E, label string) E {
	return from[rapid.IntRange(0, anyOf).Draw(t, label)%len(from)]
}

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

// as is s turned into one of kinds, keeping its index where it can, for a
// rule whose shape narrows what a selector drawn for the general case may
// be.
func as(s Sel, kinds []SelKind) Sel {
	if slices.Contains(kinds, s.Kind) {
		return s
	}

	switch {
	case s.Kind == SelInternet && slices.Contains(kinds, SelPrefix):
		return Sel{Kind: SelPrefix, I: publicPrefix}
	case s.Kind == SelAll && slices.Contains(kinds, SelMember):
		return Sel{Kind: SelMember}
	case slices.Contains(kinds, SelUser):
		return Sel{Kind: SelUser, I: s.I % len(UserRefs)}
	}

	return Sel{Kind: kinds[0], I: s.I % numTags}
}

func asAll(sels []Sel, kinds []SelKind) []Sel {
	out := make([]Sel, len(sels))
	for i, s := range sels {
		out[i] = as(s, kinds)
	}

	return out
}

var (
	srcs         = rapid.SliceOfN(selGen(srcKinds), 1, 3)
	dsts         = rapid.SliceOfN(selGen(dstKinds), 1, 3)
	targets      = rapid.SliceOfN(selGen(targetKinds), 1, 2)
	owners       = rapid.SliceOfN(selGen(ownerKinds), 1, 2)
	sshSrcs      = rapid.SliceOfN(selGen(sshSrcKinds), 1, 2)
	sshDsts      = rapid.SliceOfN(selGen(sshDstKinds), 1, 2)
	sshLogins    = rapid.SliceOfN(rapid.IntRange(0, len(SSHUsers)-1), 1, 2)
	attrLists    = rapid.SliceOfN(rapid.IntRange(0, len(Attrs)-1), 1, 2)
	sshRuleLists = rapid.SliceOfN(rapid.Custom(drawSSH), 1, 2)
	attrRules    = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) NodeAttr {
		return NodeAttr{Targets: targets.Draw(t, "target"), Attrs: attrLists.Draw(t, "attr")}
	}), 1, 2)
	ips       = rapid.SliceOfN(rapid.Custom(drawIP), 1, 2)
	portDraws = rapid.SliceOfN(rapid.Custom(drawPorts), 3, 3)
)

func drawPolicy(t *rapid.T) Policy {
	var p Policy

	rules := ruleRuns(t)

	for g := range numGroups {
		p.Groups[g] = drawMembers(t)
	}

	for i := range numTags {
		owned := chance(t, 3, "owned")
		os := owners.Draw(t, "owners")

		if owned {
			p.TagOwners[i] = os
		}

		p.Defined[i] = chance(t, 3, "defined")
	}

	for h := range numHosts {
		moved := chance(t, 6, "host-moved")
		shift := 1 + index(t, numRulePrefixes-1, "shift")

		if moved {
			p.Hosts[h] = shift
		}
	}

	// Each rule sees those before it, so it can take one's sources.
	runsOf(t, rapid.Custom(func(t *rapid.T) bool {
		grant := chance(t, 2, "grant")
		r := drawRule(t, grant, p)

		l := ruleList(&p, grant)
		*l = append(*l, r)

		return grant
	}), rules, "rules")

	// A capability to public space: the grant that makes exit nodes see
	// its sources one way.
	oneWay := chance(t, 8, "one-way")
	src := drawSel(t, []SelKind{SelMember, SelUser, SelGroup, SelTag})
	apps := drawApps(t)

	if oneWay {
		p.Grants = append(p.Grants, Rule{Src: []Sel{src}, Dst: []Dest{{Sel: Sel{Kind: SelPrefix, I: publicPrefix}}}, App: apps})
	}

	if chance(t, 12, "allow-all") {
		p.ACLs, p.Grants, p.AllowAll = nil, nil, true
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

	// Approvers alice's nodes hold, for the routes and exits they draw
	// most: so that auto-approval comes up.
	if chance(t, 6, "approvers-aligned") {
		alice := Sel{Kind: SelUser}

		i := slices.IndexFunc(p.AutoApprovers.Routes, func(ra RouteApproval) bool { return ra.Route == 1 })
		if i < 0 {
			p.AutoApprovers.Routes = append(p.AutoApprovers.Routes, RouteApproval{Route: 1})
			i = len(p.AutoApprovers.Routes) - 1
		}

		p.AutoApprovers.Routes[i].By = append(p.AutoApprovers.Routes[i].By, alice)
		p.AutoApprovers.Exit = append(p.AutoApprovers.Exit, alice)
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

// drawRule draws an ACL or a grant to add to p. Every rule draws general
// sources and destinations, protocols and capabilities, then takes what
// its shape allows of them: a self rule, an app grant, one taking the
// sources of a rule p has so that they share a merge key.
func drawRule(t *rapid.T, grant bool, p Policy) Rule {
	self := chance(t, 4, "self")
	app := grant && chance(t, 4, "app")
	same := chance(t, 3, "same-sources")
	from := rapid.IntRange(0, 15).Draw(t, "from")
	src := srcs.Draw(t, "src")
	ident := chance(t, 3, "identity-src")
	idSrc := identitySrcs.Draw(t, "identity-src")
	mixed := chance(t, 2, "mixed-src")
	dst := dsts.Draw(t, "dst")
	more := chance(t, 4, "more-dst")
	public := chance(t, 4, "public-dst")
	public6 := chance(t, 2, "public-v6")
	proto := chance(t, 3, "proto")
	protoIdx := 1 + index(t, len(Protos)-1, "proto")
	ports := portDraws.Draw(t, "ports")
	apps := drawApps(t)
	ipList := ips.Draw(t, "ip")
	appAndIP := chance(t, 3, "app-and-ip")
	via := chance(t, 4, "via")
	viaTag := index(t, numTags, "via-tag")

	selfSrc := selfSrcACL
	if grant {
		selfSrc = selfSrcGrant
	}

	kinds := dstKinds
	if app {
		kinds = appDstKinds
	}

	var r Rule

	// Self rules take single-user sources most: those are what an
	// owner's narrowed sources can share a merge key with.
	if refs := p.Refs(); same && len(refs) > 0 {
		ref := refs[from%len(refs)]
		r.Src = slices.Clone(p.Rule(ref).Src)

		if !grant && !ref.Grant {
			r.Proto = p.Rule(ref).Proto
			proto = false
		}
	} else {
		// Self rules keep their sources as drawn: * names owners by range.
		r.Src = identitySources(ident && !self, mixed, idSrc, src)
	}

	if self {
		r.Src = asAll(r.Src, selfSrc)
	}

	switch {
	case self:
		r.Dst = []Dest{{Sel: Sel{Kind: SelSelf}}}
		if more {
			r.Dst = append(r.Dst, Dest{Sel: as(dst[0], kinds)})
		}
	default:
		for _, d := range asAll(dst, kinds) {
			r.Dst = append(r.Dst, Dest{Sel: d})
		}

		// Capabilities to public space make exit nodes see their
		// sources one way.
		if app && public {
			pub := publicPrefix
			if public6 {
				pub = publicPrefix6
			}

			r.Dst = append(r.Dst, Dest{Sel: Sel{Kind: SelPrefix, I: pub}})
		}
	}

	if !grant {
		if proto {
			r.Proto = protoIdx
		}

		if r.Proto < portedProtos {
			for i := range r.Dst {
				r.Dst[i].Ports = ports[i%len(ports)]
			}
		}

		return r
	}

	if app {
		r.App = apps
		if appAndIP {
			r.IP = ipList
		}
	} else {
		r.IP = ipList
	}

	if !self && len(r.IP) > 0 && via {
		r.Via = []int{viaTag}
	}

	return r
}

func kindsAll(sels []Sel, kinds []SelKind) bool {
	return !slices.ContainsFunc(sels, func(s Sel) bool { return !slices.Contains(kinds, s.Kind) })
}

// drawPorts draws an ACL destination's ports: any, mostly.
func drawPorts(t *rapid.T) int {
	set := chance(t, 2, "ports")
	ports := 1 + index(t, len(Ports)-1, "ports")

	if set {
		return ports
	}

	return 0
}

func drawIP(t *rapid.T) IP {
	var ip IP

	proto := chance(t, 3, "proto")
	protoIdx := 1 + index(t, len(Protos)-1, "proto")
	set := chance(t, 2, "ports")
	ports := 1 + index(t, grantPorts-1, "ports")

	if proto {
		ip.Proto = protoIdx
	}

	if ip.Proto < portedProtos && set {
		ip.Ports = ports
	}

	return ip
}

func drawApps(t *rapid.T) []App {
	first := index(t, len(Apps), "cap")
	out := []App{{Cap: first, Value: index(t, len(AppValues), "value")}}

	second := chance(t, 4, "second-cap")
	cap2, value2 := other(t, len(Apps), first, "cap"), index(t, len(AppValues), "value")

	if second {
		out = append(out, App{Cap: cap2, Value: value2})
	}

	return out
}

// drawSSH draws an SSH rule: a user to itself, or sources to their own
// nodes or tagged ones; a tagged source reaches only tagged nodes and
// cannot be checked.
func drawSSH(t *rapid.T) SSHRule {
	var r SSHRule

	toUser := chance(t, 6, "to-user")
	u := Sel{Kind: SelUser, I: index(t, refUsers, "user")}
	src := sshSrcs.Draw(t, "src")
	dst := sshDsts.Draw(t, "dst")
	check := chance(t, 4, "check")
	r.Users = sshLogins.Draw(t, "users")

	tagged := slices.ContainsFunc(src, func(s Sel) bool { return s.Kind == SelTag || s.Kind == SelTagged })

	switch {
	case toUser:
		r.Src, r.Dst, r.Check = []Sel{u}, []Sel{u}, check
	case tagged:
		r.Src, r.Dst = src, asAll(dst, sshTaggedDst)
	default:
		r.Src, r.Dst, r.Check = src, dst, check
	}

	return r
}

func drawAutoApprovers(t *rapid.T) AutoApprovers {
	var aa AutoApprovers

	routes := chance(t, 2, "routes")
	first := index(t, numRulePrefixes, "route")
	by := owners.Draw(t, "by")
	second := chance(t, 4, "second-route")
	route2, by2 := other(t, numRulePrefixes, first, "route"), owners.Draw(t, "by")
	exit := chance(t, 2, "exit")
	exitBy := owners.Draw(t, "exit")

	if routes {
		aa.Routes = []RouteApproval{{Route: first, By: by}}
		if second {
			aa.Routes = append(aa.Routes, RouteApproval{Route: route2, By: by2})
		}
	}

	if !routes || exit {
		aa.Exit = exitBy
	}

	return aa
}

func drawTopology(t *rapid.T) Topology {
	var (
		users []User
		nodes []Node
	)

	sz := drawTopologySize(t)

	rapid.SliceOfN(rapid.Custom(func(t *rapid.T) User {
		u := identities[len(users)]

		// Only an OIDC user shares a name with another user, and API
		// users' names stay unique among them.
		same := chance(t, 8, "same-name")
		as := rapid.IntRange(0, anyOf).Draw(t, "as")
		email := chance(t, 8, "email")
		e := pick(t, userEmails, "email")

		if same && len(users) > 0 {
			o := users[as%len(users)]
			taken := slices.ContainsFunc(users, func(x User) bool { return !x.OIDC() && x.Name == o.Name })

			if u.OIDC() || o.OIDC() && !taken {
				u.Name = o.Name
			}
		}

		if email {
			u.Email = e
		}

		users = append(users, u)

		return u
	}), 1, sz.users).Draw(t, "users")

	// A world holds addresses outside the tailnet rarely and then
	// several; most worlds are what headscale hands out. A large one
	// never: a reference property skips it whole.
	outside := chance(t, outsideWorlds, "outside-world") && !sz.large

	// Nodes come in runs, so that a large topology grows to dozens.
	runsOf(t, rapid.Custom(func(t *rapid.T) Node {
		n := drawNode(t, types.NodeID(len(nodes)+1), users, allTags, outside) //nolint:gosec // small
		nodes = append(nodes, n)

		return n
	}), sz.nodes, "nodes")

	n := len(nodes)

	// Exit nodes come up as often as the shapes pairing them need.
	exit := chance(t, 5, "exit")
	x := index(t, n, "exit-node")
	oneFamily := chance(t, 4, "one-family")
	family := index(t, 2, "family")

	if exit {
		rs := []int{exit4, exit6}
		if oneFamily {
			rs = rs[family : family+1]
		}

		nodes[x].Announced, nodes[x].Approved = addRoutes(nodes[x].Announced, rs), addRoutes(nodes[x].Approved, rs)
	}

	// A route that begins where 10.0.0.0/24, a frequent destination, ends.
	touch := chance(t, 6, "touching-route")
	y := index(t, n, "toucher")

	if touch {
		nodes[y].Announced, nodes[y].Approved = addRoutes(nodes[y].Announced, []int{touching}), addRoutes(nodes[y].Approved, []int{touching})
	}

	return Topology{Users: users, Nodes: nodes, NextID: types.NodeID(n + 1), NextUserID: uint(len(users) + 1)} //nolint:gosec // small
}

var allTags = []int{0, 1, 2}

// drawNode draws node id: owned by a user, or by tags from tags. With
// outside, its addresses may be outside the tailnet, which registration
// never hands out.
func drawNode(t *rapid.T, id types.NodeID, users []User, tags []int, outside bool) Node {
	n := Node{ID: id}

	tagged := chance(t, 5, "tagged")
	ts := drawTags(t, tags)
	owner := rapid.IntRange(0, anyOf).Draw(t, "owner")

	switch {
	case len(tags) > 0 && (tagged || len(users) == 0):
		n.Tags = ts
	case len(users) > 0:
		n.User = users[owner%len(users)].ID
	}

	// One family may be missing, not both: the server refuses a node
	// without addresses at startup.
	n.V4, n.V6 = drawAddr(t, 4, id, outside), drawAddr(t, 6, id, outside)
	if !n.V4.IsValid() && !n.V6.IsValid() {
		n.V4 = ownAddr(4, uint64(id))
	}

	if chance(t, 3, "routes") {
		for _, rt := range routeLists.Draw(t, "routes") {
			n.Announced = addRoutes(n.Announced, rt.announce)
			n.Approved = addRoutes(n.Approved, rt.approve)
		}
	}

	client := chance(t, 6, "client")
	c := Client(1 + index(t, numClients-1, "client")) //nolint:gosec // a few clients

	if client {
		n.Client = c
	}

	n.Expired = chance(t, 10, "expired")
	n.Offline = chance(t, 8, "offline")

	return n
}

// drawTags draws one or two tags from tags.
func drawTags(t *rapid.T, tags []int) []int {
	first := rapid.IntRange(0, 15).Draw(t, "tag")
	second := chance(t, 4, "second-tag")
	next := rapid.IntRange(0, 15).Draw(t, "tag")

	if len(tags) == 0 {
		return nil
	}

	out := []int{tags[first%len(tags)]}
	if o := tags[next%len(tags)]; second && o != out[0] {
		out = append(out, o)
		slices.Sort(out)
	}

	return out
}

// drawAddr draws node id's address in family: its own, or rarely none;
// in a world that has them, one outside the tailnet.
func drawAddr(t *rapid.T, family int, id types.NodeID, outside bool) netip.Addr {
	none := chance(t, 8, "no-addr")
	away := chance(t, 2, "outside")
	where := rapid.IntRange(0, 15).Draw(t, "where")

	switch {
	case none:
		return netip.Addr{}
	case outside && away:
		pool := outsideAddrs(family, uint64(id))

		return pool[where%len(pool)]
	}

	return ownAddr(family, uint64(id))
}

// routeChoices is what a node may route: every rule prefix, then an exit
// route, both halves together.
const routeChoices = numRulePrefixes + 1

// drawRouteChoice draws routes to announce or approve together.
func drawRouteChoice(t *rapid.T) []int {
	c := index(t, routeChoices, "route")
	oneFamily := chance(t, 4, "one-family")
	family := index(t, 2, "family")

	switch {
	case c < numRulePrefixes:
		return []int{c}
	case oneFamily:
		return []int{exit4 + family}
	}

	return []int{exit4, exit6}
}

// routeEntry is routes a node announces, has approved, or both.
type routeEntry struct{ announce, approve []int }

var routeLists = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) routeEntry {
	rs := drawRouteChoice(t)
	unapproved := chance(t, 4, "unapproved")
	unannounced := chance(t, 5, "unannounced")

	switch {
	case unapproved:
		return routeEntry{announce: rs}
	case unannounced:
		return routeEntry{approve: rs}
	}

	return routeEntry{announce: rs, approve: rs}
}), 1, 2)

func drawEdits(t *rapid.T, w World) []Edit {
	nodes := w.Topology.Nodes

	var auto []Node

	for _, n := range nodes {
		if len(n.AutoApproved) > 0 {
			auto = append(auto, n)
		}
	}

	// The gates are drawn whatever the world, so that a step reads the
	// same draws after the shrinker deletes a node an earlier step made.
	reuse := chance(t, 12, "reuse")
	announce := chance(t, 12, "announce-approve")
	withdraw := chance(t, 12, "withdraw-auto")

	switch {
	case len(nodes) > 0 && reuse:
		return drawReuse(t, w)
	case len(nodes) > 0 && announce:
		return drawAnnounceApprove(t, w)
	case len(auto) > 0 && withdraw:
		n := pickAny(t, auto, "withdrawer")

		return []Edit{Withdraw{n.ID, drawHeld(t, n.AutoApproved)}}
	}

	// The gate sets only how long the list may grow: one edit or the
	// whole list stays aligned when the shrinker lowers it or deletes an
	// edit, which a list of at least two would not let it.
	most := 1
	if chance(t, 3, "several") {
		most = 3
	}

	cur := w

	return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Edit {
		e := drawEdit(t, cur)
		cur = cur.Apply(e)

		return e
	}), 1, most).Draw(t, "edits")
}

// drawReuse deletes a node and registers another, which the address
// allocator hands the freed address.
func drawReuse(t *rapid.T, w World) []Edit {
	x := pick(t, w.Topology.Nodes, "leaves")

	v6 := chance(t, 3, "v6")
	n, ok := drawJoiner(t, w)

	if !ok {
		return []Edit{Leave{x.ID}}
	}

	// The step is for the freed address. Whatever else the newcomer held
	// the shrinker could not split from it, and a plain Join draws anyway.
	n.Announced, n.Client, n.Offline = nil, Official, false

	switch {
	case !x.V6.IsValid() || x.V4.IsValid() && !v6:
		n.V4 = x.V4
	default:
		n.V6 = x.V6
	}

	return []Edit{Leave{x.ID}, Join{n}}
}

// drawJoiner draws a node registering into w: a user's, with its own
// fresh addresses, or tagged with tags the policy defines, which leaves
// it without a user; nothing approved but what auto-approval approves.
// False when nobody could register it.
func drawJoiner(t *rapid.T, w World) (Node, bool) {
	var defined []int

	for i := range numTags {
		if w.Policy.DefinesTag(i) {
			defined = append(defined, i)
		}
	}

	n := drawNode(t, w.Topology.nextID(), w.Topology.Users, defined, false)
	n.Approved, n.AutoApproved, n.Expired = nil, nil, false

	return n, len(w.Topology.Users) > 0 || len(defined) > 0
}

// drawAnnounceApprove announces and approves, on one node, mostly a route
// another node already serves.
func drawAnnounceApprove(t *rapid.T, w World) []Edit {
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
	unserved := chance(t, 4, "unserved")
	s := rapid.IntRange(0, 15).Draw(t, "served")

	if len(served) > 0 && !unserved {
		rs = []int{served[s%len(served)]}
	}

	var edits []Edit

	if ann := dropRoutes(rs, n.Announced); len(ann) > 0 {
		edits = append(edits, Announce{n.ID, ann})
	}

	if app := dropRoutes(rs, w.Apply(edits...).mustNode(n.ID).Approved); len(app) > 0 {
		edits = append(edits, Approve{n.ID, app})
	}

	if len(edits) == 0 {
		return []Edit{drawEdit(t, w)}
	}

	return edits
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

	kind := index(t, numNodeEdits, "node-edit")
	if len(tp.Nodes) == 0 {
		kind = editJoin
	}

	if kind == editJoin {
		n, ok := drawJoiner(t, w)
		if !ok {
			return drawUserEdit(t, w)
		}

		return Join{n}
	}

	if kind == editSwap && len(tp.Nodes) >= 2 {
		a := index(t, len(tp.Nodes), "a")
		b := other(t, len(tp.Nodes), a, "b")
		e := SwapAddrs{min(tp.Nodes[a].ID, tp.Nodes[b].ID), max(tp.Nodes[a].ID, tp.Nodes[b].ID), drawFamily(t)}

		// Swapped with a node lacking the family, an address moves over,
		// which must not leave its holder without one.
		if after := w.Apply(e); len(after.mustNode(e.A).Addrs()) > 0 && len(after.mustNode(e.B).Addrs()) > 0 {
			return e
		}
	}

	// Newest first: the simplest draw keeps naming the node a join made
	// when the shrinker deletes a node before it.
	n := tp.Nodes[len(tp.Nodes)-1-index(t, len(tp.Nodes), "node")]

	return drawNodeEditOn(t, w, kind, n)
}

// drawNodeEditOn draws an edit of kind, other than a join, of node n of w.
func drawNodeEditOn(t *rapid.T, w World, kind int, n Node) Edit {
	switch kind {
	case editLeave:
		return Leave{n.ID}
	case editRetag:
		if e, ok := drawRetag(t, w, n); ok {
			return e
		}
	case editAnnounce, editWithdraw:
		// Mostly what the auto-approvers approved, when there is any.
		if kind == editWithdraw && len(n.AutoApproved) > 0 && !chance(t, 3, "manual") {
			return Withdraw{n.ID, drawHeld(t, n.AutoApproved)}
		}

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
		return drawSetAddr(t, n)
	}

	return SetClient{n.ID, Client(other(t, numClients, int(n.Client), "client"))} //nolint:gosec // a few clients
}

// drawRetag tags n with tags the policy defines, as an admin does; or,
// for a tagged node, mostly, logs it in as a user, which untags it.
func drawRetag(t *rapid.T, w World, n Node) (Edit, bool) {
	var defined []int

	for i := range numTags {
		if w.Policy.DefinesTag(i) {
			defined = append(defined, i)
		}
	}

	untag := chance(t, 2, "untag")
	tags := drawTags(t, defined)

	// A retag onto a tag that auto-approves a route the node announces
	// unapproved, which the drawn tags rarely are.
	if approve := chance(t, 3, "onto-approver"); approve && !untag {
		if tag, ok := approvingTag(w, n); ok {
			tags = []int{tag}
		}
	}

	switch {
	case n.Tagged() && untag && len(w.Topology.Users) > 0:
		return Retag{n.ID, nil, pickAny(t, w.Topology.Users, "login").ID}, true
	case len(tags) > 0:
		return Retag{n.ID, tags, 0}, true
	}

	return nil, false
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
// to a tailnet address nobody owns; rarely outside the tailnet.
func drawSetAddr(t *rapid.T, n Node) Edit {
	family := drawFamily(t)
	cur := n.Addr(family)

	rare := chance(t, strayAddrs, "outside-addr")

	to := []netip.Addr{ownAddr(family, uint64(n.ID)), {}, movedAddr(family, uint64(n.ID))}
	if rare {
		to = append(to, outsideAddrs(family, uint64(n.ID))...)
	}

	to = slices.DeleteFunc(to, func(a netip.Addr) bool { return a == cur })
	e := SetAddr{n.ID, family, pickAny(t, to, "to")}

	// None in its only family would leave n without addresses, which the
	// server refuses at startup: it gains the other family instead.
	if !e.Addr.IsValid() && len(n.Addrs()) == 1 {
		e.Family = 4
		if family == 4 {
			e.Family = 6
		}

		e.Addr = ownAddr(e.Family, uint64(n.ID))
	}

	return e
}

func drawUserEdit(t *rapid.T, w World) Edit {
	kind := index(t, 4, "user-edit")
	u := User{}

	if users := w.Topology.Users; len(users) > 0 {
		u = pickAny(t, users, "user")
	}

	return drawUserEditOn(t, w, kind, u)
}

// drawUserEditOn draws a user edit of kind: one of user u of w, or a new
// user.
func drawUserEditOn(t *rapid.T, w World, kind int, u User) Edit {
	users := w.Topology.Users

	switch {
	case kind == 1 && len(users) > 0:
		if names := renames(users, u); len(names) > 0 {
			return RenameUser{u.ID, pickAny(t, names, "name")}
		}
	case kind == 2 && len(users) > 0:
		var oidc []User

		for _, o := range users {
			if o.OIDC() {
				oidc = append(oidc, o)
			}
		}

		if len(oidc) > 0 {
			o := pickAny(t, oidc, "oidc")
			emails := slices.DeleteFunc(slices.Clone(userEmails), func(e string) bool { return e == o.Email })

			return SetEmail{o.ID, pickAny(t, emails, "email")}
		}
	case kind == 3:
		var free []uint

		for _, o := range users {
			if !slices.ContainsFunc(w.Topology.Nodes, func(n Node) bool { return n.User == o.ID }) {
				free = append(free, o.ID)
			}
		}

		if len(free) > 0 {
			return DeleteUser{pickAny(t, free, "user")}
		}
	}

	id := w.Topology.nextUserID()
	oidc := chance(t, 2, "oidc")
	name, email := pick(t, userNames, "name"), pick(t, userEmails, "email")
	nu := User{ID: id, Name: name, Email: email}

	if oidc || slices.ContainsFunc(users, func(o User) bool { return !o.OIDC() && o.Name == name }) {
		nu.Provider = providerPrefix + strconv.FormatUint(uint64(id), 10)
	}

	return AddUser{nu}
}

// renames is what u can be renamed to: for an API user, a name no other
// API user has; for an OIDC user, whatever the provider says.
func renames(users []User, u User) []string {
	return slices.DeleteFunc(slices.Clone(userNames), func(n string) bool {
		return n == u.Name || !u.OIDC() && slices.ContainsFunc(users, func(o User) bool { return !o.OIDC() && o.ID != u.ID && o.Name == n })
	})
}

// The policy edits drawPolicyEdit picks from: half the time one that
// changes a rule in place, else one of the rest.
const (
	editSel = iota
	editPorts
	editProto
	editIP
	editVia
	editAddSel
	editRemoveSel
	editApp
	numRuleEdits

	editSwapRules = iota - 1
	editGroup
	editHost
	editTagOwners
	editAddRule
	editRemoveRule
	editAllowAll
	editSSH
	editNodeAttrs
	editAutoApprovers
	numPolicyEdits
)

// drawPolicyEdit draws a policy write headscale accepts. While the
// document holds a token users have since made ambiguous, the only one
// is replacing it; otherwise a token a draw makes ambiguous is moved to
// the next one that is not.
func drawPolicyEdit(t *rapid.T, w World) Edit {
	v := NewView(w)

	if amb := v.AmbiguousRefs(); len(amb) > 0 {
		e := ReplaceUserRefs{From: amb}
		for range amb {
			e.To = append(e.To, unambiguous(v, rapid.IntRange(0, len(UserRefs)-1).Draw(t, "to")))
		}

		return e
	}

	return remapRefs(drawPolicyEditKind(t, w), func(r int) int { return unambiguous(v, r) })
}

func drawPolicyEditKind(t *rapid.T, w World) Edit {
	p := w.Policy
	refs := p.Refs()

	var grants []RuleRef

	for _, ref := range refs {
		if ref.Grant {
			grants = append(grants, ref)
		}
	}

	inPlace := chance(t, 2, "rule-edit")
	kind := numRuleEdits + index(t, numPolicyEdits-numRuleEdits, "policy-edit")
	ruleKind := index(t, numRuleEdits, "rule-edit-kind")

	if inPlace {
		kind = ruleKind
	}

	switch kind {
	case editPorts:
		if e, ok := drawSetPorts(t, p, refs); ok {
			return e
		}
	case editProto:
		if e, ok := drawSetProto(t, p, refs); ok {
			return e
		}
	case editSwapRules:
		if e, ok := drawSwapRules(t, p); ok {
			return e
		}
	case editSel:
		if len(refs) > 0 {
			return drawSetSel(t, p, pick(t, refs, "rule"))
		}
	case editGroup:
		return SetGroup{index(t, numGroups, "group"), drawMembers(t)}
	case editHost:
		return drawSetHost(t, p)
	case editTagOwners:
		e := SetTagOwners{Tag: index(t, numTags, "tag")}
		none := chance(t, 3, "no-owners")
		os := owners.Draw(t, "owners")
		e.Defined = chance(t, 2, "defined")

		if !none {
			e.Owners = os
		}

		return e
	case editIP, editApp, editVia:
		if len(grants) > 0 {
			if e, ok := drawGrantPart(t, p, pick(t, grants, "grant"), kind); ok {
				return e
			}
		}
	case editAddSel:
		if len(refs) > 0 {
			return drawAddSel(t, p, pick(t, refs, "rule"))
		}
	case editRemoveSel:
		if e, ok := drawRemoveSel(t, p, refs); ok {
			return e
		}
	case editRemoveRule:
		if len(refs) > 0 {
			return RemoveRule{pick(t, refs, "rule")}
		}
	case editAllowAll:
		if !p.AllowAll {
			return AllowAll{}
		}
	case editSSH:
		if chance(t, 4, "none") {
			return SetSSH{}
		}

		return SetSSH{sshRuleLists.Draw(t, "ssh")}
	case editNodeAttrs:
		// Without its service hosts, mostly, when it has any.
		if chance(t, 4, "none") || len(NewView(w).ServiceHosts()) > 0 && chance(t, 2, "drop-service") {
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

// remapRefs returns e with every user token in what it writes passed
// through to.
func remapRefs(e Edit, to func(int) int) Edit {
	if g, ok := e.(SetGroup); ok {
		members := make([]int, len(g.Members))
		for i, m := range g.Members {
			members[i] = to(m)
		}

		g.Members = members

		return g
	}

	v := reflect.New(reflect.TypeOf(e)).Elem()
	v.Set(reflect.ValueOf(e))
	remapValue(v, to)

	out, _ := v.Interface().(Edit)

	return out
}

var selType = reflect.TypeFor[Sel]()

func remapValue(v reflect.Value, to func(int) int) {
	switch {
	case v.Type() == selType:
		if s, _ := v.Interface().(Sel); s.Kind == SelUser {
			v.Set(reflect.ValueOf(Sel{Kind: SelUser, I: to(s.I)}))
		}
	case v.Kind() == reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				remapValue(v.Field(i), to)
			}
		}
	case v.Kind() == reflect.Slice:
		if v.IsNil() {
			return
		}

		c := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(c, v)
		v.Set(c)

		for i := range v.Len() {
			remapValue(v.Index(i), to)
		}
	case v.Kind() == reflect.Array:
		for i := range v.Len() {
			remapValue(v.Index(i), to)
		}
	}
}

func drawSwapRules(t *rapid.T, p Policy) (Edit, bool) {
	var lists []bool

	for _, grant := range []bool{false, true} {
		if len(p.List(grant)) >= 2 {
			lists = append(lists, grant)
		}
	}

	if len(lists) == 0 {
		return nil, false
	}

	grant := pick(t, lists, "list")
	n := len(p.List(grant))
	i := index(t, n, "i")
	j := other(t, n, i, "j")

	return SwapRules{grant, min(i, j), max(i, j)}, true
}

// drawSetHost moves mostly a host the policy names.
func drawSetHost(t *rapid.T, p Policy) Edit {
	h := index(t, numHosts, "host")
	unnamed := chance(t, 4, "unnamed")
	n := rapid.IntRange(0, 15).Draw(t, "named")

	var hs []int

	for i, ok := range p.referenced().hosts {
		if ok {
			hs = append(hs, i)
		}
	}

	if !unnamed && len(hs) > 0 {
		h = hs[n%len(hs)]
	}

	return SetHost{h, other(t, numRulePrefixes, p.Hosts[h], "shift")}
}

func drawSetPorts(t *rapid.T, p Policy, refs []RuleRef) (Edit, bool) {
	type place struct {
		ref RuleRef
		at  int
	}

	var places []place

	for _, ref := range refs {
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

// drawSetProto changes a protocol to one the ports allow, in one of refs.
func drawSetProto(t *rapid.T, p Policy, refs []RuleRef) (Edit, bool) {
	refs = slices.DeleteFunc(slices.Clone(refs), func(ref RuleRef) bool { return ref.Grant && len(p.Rule(ref).IP) == 0 })
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

	proto := index(t, n-1, "proto")
	if proto >= cur {
		proto++
	}

	return SetProto{ref, at, proto}, true
}

// drawGrantPart replaces a grant's ip list, its app capabilities, or its
// via tags, keeping it a grant headscale accepts.
func drawGrantPart(t *rapid.T, p Policy, ref RuleRef, kind int) (Edit, bool) {
	r := p.Rule(ref)
	internet := slices.ContainsFunc(r.Dst, func(d Dest) bool { return d.Sel.Kind == SelInternet })

	switch kind {
	case editIP:
		none := chance(t, 4, "no-ip")
		ip := ips.Draw(t, "ip")

		if none && len(r.App) > 0 && len(r.Via) == 0 {
			return SetIP{ref, nil}, true
		}

		return SetIP{ref, ip}, true
	case editApp:
		none := chance(t, 4, "no-app")
		apps := drawApps(t)
		tail := chance(t, 3, "values-tail")

		switch {
		case none && len(r.IP) > 0:
			return SetApp{ref, nil}, true
		case internet:
			return nil, false
		case tail && slices.ContainsFunc(r.App, func(a App) bool { return a.Value > 0 }):
			// The same capabilities, values that differ past the first.
			return SetApp{ref, valuesTail(r.App)}, true
		}

		return SetApp{ref, apps}, true
	}

	if len(r.IP) == 0 || r.selfRule() {
		return nil, false
	}

	none := chance(t, 3, "no-via")
	tags := drawTags(t, allTags)

	if none {
		return SetVia{ref, nil}, true
	}

	return SetVia{ref, tags}, true
}

// selKinds is what rule r takes at a source, or at a destination.
func selKinds(r Rule, grant, dst bool) []SelKind {
	switch {
	case dst && len(r.App) > 0:
		return appDstKinds
	case dst:
		return dstKinds
	case r.selfRule() && grant:
		return selfSrcGrant
	case r.selfRule():
		return selfSrcACL
	}

	return srcKinds
}

// drawNewSel draws a selector for kinds: half the time one the policy
// names elsewhere.
func drawNewSel(t *rapid.T, p Policy, kinds []SelKind) Sel {
	named := chance(t, 2, "named")
	n := rapid.IntRange(0, 15).Draw(t, "sel")
	fresh := drawSel(t, kinds)

	if cands := slices.DeleteFunc(p.Selectors(), func(s Sel) bool { return !slices.Contains(kinds, s.Kind) }); named && len(cands) > 0 {
		return cands[n%len(cands)]
	}

	return fresh
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

	at := index(t, len(r.Src), "at")
	if dst {
		at = pick(t, dstAt, "at")
	}

	return SetSel{ref, dst, at, drawNewSel(t, p, selKinds(r, ref.Grant, dst))}
}

// drawAddSel adds a source or a non-self destination to rule ref.
func drawAddSel(t *rapid.T, p Policy, ref RuleRef) Edit {
	r := p.Rule(ref)
	dst := rapid.Bool().Draw(t, "dst")

	n := len(r.Src)
	if dst {
		n = len(r.Dst)
	}

	at := rapid.IntRange(0, n).Draw(t, "at")
	sel := drawNewSel(t, p, selKinds(r, ref.Grant, dst))
	ports := drawPorts(t)

	if !dst || ref.Grant || r.Proto >= portedProtos {
		ports = 0
	}

	return AddSel{ref, dst, at, sel, ports}
}

// drawRemoveSel removes a source or a non-self destination from one of
// refs that keeps one.
func drawRemoveSel(t *rapid.T, p Policy, refs []RuleRef) (Edit, bool) {
	var places []RemoveSel

	for _, ref := range refs {
		r := p.Rule(ref)
		if len(r.Src) > 1 {
			for i := range r.Src {
				places = append(places, RemoveSel{ref, false, i})
			}
		}

		if len(r.Dst) > 1 {
			for i, d := range r.Dst {
				if d.Sel.Kind != SelSelf {
					places = append(places, RemoveSel{ref, true, i})
				}
			}
		}
	}

	if len(places) == 0 {
		return nil, false
	}

	return pick(t, places, "place"), true
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
