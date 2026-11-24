// Properties of the filter cache and its change sets, driven as the world
// and the hub drive them: each commit makes filters following the last,
// the hub routes some commits and coalesces others, and only the sessions
// a step marks read. A node Changed leaves out is not merely left
// unwoken: its next read is served from the carry.

package v2

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// modeRun is one source mode's filters along a scenario: the stage the hub
// last routed to, and each node's session.
type modeRun struct {
	mode   SourceMode
	routed int
	sess   map[types.NodeID]*session
}

// session is what a node's session holds: the filter it read at step at,
// and whether routing has named it since, which wakes it to read again.
type session struct {
	at    int
	woken bool
}

func (m *modeRun) filters(st *stage) *Filters {
	if m.mode == CapabilitySources {
		return st.cap
	}

	return st.ip
}

func (m *modeRun) facts(st *stage, id types.NodeID) ReceiverFacts {
	if m.mode == CapabilitySources {
		return st.recv.Of(id)
	}

	return ReceiverFacts{}
}

// fresh is id's filter cut afresh from st's inputs in the form facts send.
func (m *modeRun) fresh(st *stage, id types.NodeID, facts ReceiverFacts) ([]tailcfg.FilterRule, error) {
	return m.filters(st).Fresh().ForNode(id, facts)
}

// named is what routing from a to b names, as Since does: the filters'
// change for the form each node's facts send it, and the nodes whose
// facts moved.
func (m *modeRun) named(a, b *stage) ([]types.NodeID, []types.NodeID, bool) {
	if m.mode != CapabilitySources {
		ids, all := b.ip.Changed(a.ip)

		return ids, nil, all
	}

	ids, all := b.cap.ChangedFor(a.cap, b.recv)

	return ids, b.recv.ChangedSince(a.recv), all
}

// changeTally counts what the property met, so a run shows it judged the
// cases that matter.
type changeTally struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *changeTally) add(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.n == nil {
		c.n = map[string]int{}
	}

	c.n[k]++
}

func (c *changeTally) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]string, 0, len(c.n))
	for _, k := range slices.Sorted(maps.Keys(c.n)) {
		out = append(out, fmt.Sprintf("%s=%d", k, c.n[k]))
	}

	return strings.Join(out, " ")
}

func sameRules(a []tailcfg.FilterRule, aerr error, b []tailcfg.FilterRule, berr error) bool {
	return (aerr == nil) == (berr == nil) && reflect.DeepEqual(a, b)
}

func nodeIDsOf(sts ...*stage) []types.NodeID {
	var ids []types.NodeID

	for _, st := range sts {
		for _, n := range st.list {
			ids = append(ids, n.ID)
		}
	}

	slices.Sort(ids)

	return slices.Compact(ids)
}

// soundness returns a session holding what it read that routing from a to
// b leaves stale: one whose filter, cut afresh at b in the form its facts
// there send it, differs from what it read, which routing must name (in
// the form b's facts send it, as Since names them: Filters.ChangedFor and
// the nodes whose facts moved); or whose filter in the form it holds moved
// from a to b, which Filters.Changed, listing every form, must name. A
// session that read at a step a follows holds what a holds of it, as it
// was not named since. stages are the stages by step.
func (m *modeRun) soundness(a, b *stage, stages []*stage, ids []types.NodeID, tally *changeTally) string {
	named, flipped, all := m.named(a, b)
	every, everyAll := m.filters(b).Changed(m.filters(a))

	// What routing would name were subnet routers not named wholesale,
	// trusting the cover and address indexes instead: held to
	// the same sessions, so that narrowing stays possible.
	narrow := routeFilters(m.filters(a), m.filters(b), true)
	narrowIDs := narrow.ids

	if m.mode == CapabilitySources {
		narrowIDs = narrow.namedFor(m.mode, b.recv)
	}

	for _, id := range ids {
		at := m.sess[id].at
		held, heldNow := m.facts(stages[at], id), m.facts(b, id)

		before, errBefore := m.fresh(stages[at], id, held)
		after, errAfter := m.fresh(b, id, heldNow)

		if !sameRules(before, errBefore, after, errAfter) {
			tally.add("session's filter moved")

			if !all && !slices.Contains(named, id) && !slices.Contains(flipped, id) {
				return fmt.Sprintf("n%d read %s at step %d (facts %+v), is cut %s now (facts %+v), and routing (%v, facts moved %v) leaves it out",
					id, rulesJSON(before, errBefore), at, held, rulesJSON(after, errAfter), heldNow, named, flipped)
			}

			if !narrow.all && !slices.Contains(narrowIDs, id) && !slices.Contains(flipped, id) {
				return fmt.Sprintf("n%d read %s at step %d (facts %+v), is cut %s now (facts %+v), and routing without routers wholesale (%v, facts moved %v) leaves it out",
					id, rulesJSON(before, errBefore), at, held, rulesJSON(after, errAfter), heldNow, narrowIDs, flipped)
			}
		}

		before, errBefore = m.fresh(a, id, held)
		after, errAfter = m.fresh(b, id, held)

		if !sameRules(before, errBefore, after, errAfter) && !everyAll && !slices.Contains(every, id) {
			return fmt.Sprintf("n%d holds the form %+v send, which moved from %s to %s, and Filters.Changed (%v) leaves it out",
				id, held, rulesJSON(before, errBefore), rulesJSON(after, errAfter), every)
		}
	}

	return ""
}

// everyNode returns a node at both a and b whose filter, cut afresh in the
// form its facts send it at each, moved from a to b and that routing from
// a to b leaves out, whether or not its session read: routing must not
// lean on which filters were read to name one.
func (m *modeRun) everyNode(a, b *stage, tally *changeTally) string {
	named, flipped, all := m.named(a, b)

	for _, id := range nodeIDsOf(a, b) {
		_, wasOK := a.cap.node(id)
		_, isOK := b.cap.node(id)

		if !wasOK || !isOK {
			continue
		}

		before, errBefore := m.fresh(a, id, m.facts(a, id))
		after, errAfter := m.fresh(b, id, m.facts(b, id))

		if sameRules(before, errBefore, after, errAfter) {
			continue
		}

		tally.add("node's filter moved")

		if !all && !slices.Contains(named, id) && !slices.Contains(flipped, id) {
			_, read := m.sess[id]

			return fmt.Sprintf("n%d (a session read: %t) is cut %s, then %s, and routing (%v, facts moved %v) leaves it out",
				id, read, rulesJSON(before, errBefore), rulesJSON(after, errAfter), named, flipped)
		}
	}

	return ""
}

// factsNamed returns a node whose facts moved from a to b that the
// receivers' change leaves out.
func (m *modeRun) factsNamed(a, b *stage) string {
	_, flipped, _ := m.named(a, b)

	for _, id := range nodeIDsOf(a, b) {
		if was, is := m.facts(a, id), m.facts(b, id); was != is && !slices.Contains(flipped, id) {
			return fmt.Sprintf("n%d's facts moved from %+v to %+v, and the receivers' change (%v) leaves it out", id, was, is, flipped)
		}
	}

	return ""
}

// route routes to stages[k] from the stage last routed to, as the hub does:
// every node is held to that routing, and each session not named since it
// read to routing from the stage it holds, the one last routed to or a
// later one it read (the hub's render log weighs those); then every
// session routing names is woken.
func (m *modeRun) route(stages []*stage, k int, tally *changeTally) string {
	from := map[int][]types.NodeID{}

	for _, id := range slices.Sorted(maps.Keys(m.sess)) {
		if s := m.sess[id]; !s.woken {
			j := max(s.at, m.routed)
			from[j] = append(from[j], id)
		}
	}

	if msg := m.factsNamed(stages[m.routed], stages[k]); msg != "" {
		return fmt.Sprintf("from step %d: %s", m.routed, msg)
	}

	if msg := m.everyNode(stages[m.routed], stages[k], tally); msg != "" {
		return fmt.Sprintf("from step %d: %s", m.routed, msg)
	}

	for _, j := range slices.Sorted(maps.Keys(from)) {
		if msg := m.soundness(stages[j], stages[k], stages, from[j], tally); msg != "" {
			return fmt.Sprintf("from step %d: %s", j, msg)
		}
	}

	wake := func(j int) {
		named, flipped, all := m.named(stages[j], stages[k])

		for _, id := range from[j] {
			if all || slices.Contains(named, id) || slices.Contains(flipped, id) {
				m.sess[id].woken = true
			}
		}
	}

	for j := range from {
		wake(j)
	}

	// The hub's routing from the stage it last routed to wakes every
	// session it names, whichever stage the session read.
	named, flipped, all := m.named(stages[m.routed], stages[k])

	for id, s := range m.sess {
		if all || slices.Contains(named, id) || slices.Contains(flipped, id) {
			s.woken = true
		}
	}

	return ""
}

// precision returns a node routing from a to b names in capability mode
// across membership changes alone though its filter did not move: one sent
// capabilities at both ends with the same facts whose capability-form
// filter is the same at both ends, unless routing names it for a reason it
// states (unmovedNamed), each of which is counted. It also counts, without
// judging, the nodes sent addresses at both ends that routing names in
// address form alone though their address form did not move.
func (m *modeRun) precision(a, b *stage, tally *changeTally) string {
	ids, flipped, all := m.named(a, b)
	if all {
		// Routing says all when it names every node: every node is named.
		tally.add("precision: routing named all")

		ids = nodeIDsOf(b)
	}

	change, _ := b.cap.changeFrom(a.cap)

	for _, id := range ids {
		_, wasOK := a.cap.node(id)
		_, isOK := b.cap.node(id)

		if slices.Contains(flipped, id) || !wasOK || !isOK || a.recv.Of(id) != b.recv.Of(id) {
			continue
		}

		if receiverForm(CapabilitySources, a.recv.Of(id)) != reasonNone {
			addressOnlyMeasure(a, b, m, change, id, tally)

			continue
		}

		before, errBefore := m.fresh(a, id, eligibleFacts)
		after, errAfter := m.fresh(b, id, eligibleFacts)

		if !sameRules(before, errBefore, after, errAfter) {
			tally.add("precision: named and moved")

			continue
		}

		why := unmovedNamed(a, b, id)
		if why == "" {
			return fmt.Sprintf("routing names n%d, sent capabilities at both ends, though its filter %s did not move", id, rulesJSON(after, errAfter))
		}

		tally.add("precision: named, unmoved: " + why)
	}

	return ""
}

// addressOnlyMeasure counts, without judging, the nodes sent addresses at
// both ends that routing names though their address form did not move:
// subnet routers and exit nodes, named whenever a rule moves, and the
// receivers named in address form alone (a grant whose address form alone
// moved, or every grant once any moved). A subnet router or exit node
// announces its routes, so it is always sent addresses.
func addressOnlyMeasure(a, b *stage, m *modeRun, change filterChange, id types.NodeID, tally *changeTally) {
	was, _ := a.cap.node(id)
	is, _ := b.cap.node(id)
	router := was.IsExitNode() || is.IsExitNode() || len(was.SubnetRoutes()) > 0 || len(is.SubnetRoutes()) > 0
	alone := !slices.Contains(change.ids, id) && change.addr.has(id)

	if !router && !alone {
		return
	}

	before, errBefore := m.fresh(a, id, unknownFacts)
	after, errAfter := m.fresh(b, id, unknownFacts)
	moved := "moved"

	if sameRules(before, errBefore, after, errAfter) {
		moved = "unmoved"
	}

	switch {
	case router:
		// TODO(kradalby): overwake/routers-wholesale: counted, not judged;
		// fail on an unmoved router named here once routeFilters in
		// expand.go routes subnet routers and exit nodes by the narrow set
		// instead of naming them wholesale.
		tally.add("address form: router or exit named, " + moved)
	default:
		// TODO(kradalby): overwake/address-form-only: counted, not judged;
		// fail on an unmoved receiver named here once anchorsDelta and
		// receivers(addressOnly) in expand.go name only the receivers whose
		// address form moved.
		tally.add("address form: named in address form alone, " + moved)
	}
}

// unmovedNamed says why routing names id, sent capabilities at both ends
// and its capability-form filter unmoved from a to b, by the first of the
// reasons routing states that applies; "" when none does. Each is an
// over-name production accepts, marked at its site with the same
// TODO(kradalby) key; overNamed's three were found by this property.
func unmovedNamed(a, b *stage, id types.NodeID) string {
	was, _ := a.cap.node(id)
	is, _ := b.cap.node(id)

	switch {
	case was != is && was.HasPolicyChange(is):
		// TODO(kradalby): overwake/policy-facts-moved: delete this case,
		// so the property is strict, when filterRoute.candidates and
		// movedNodes in expand.go name a node whose policy facts moved
		// only where what its filter reads of them moved.
		return "policy facts moved"
	case deltaHolder(a, b, id):
		// TODO(kradalby): overwake/delta-address-holders: delete this case
		// when filterRoute.destinations in expand.go names the holders of
		// an address a destination gained or lost only where the
		// receiver's own reach of the rule moved.
		return "holds an address a destination gained or lost"
	case selfOwnerMoved(a, b, is):
		// TODO(kradalby): overwake/self-owners-every-form: delete this case
		// when filterRoute.self and selfAddressOnly in expand.go, and
		// selfCapabilityOnly in fallback.go (which declines an app self
		// grant), name an owner in every form only where its
		// capability-form self rules moved.
		return "self owner whose rules are not capability-only alike at both ends"
	}

	return overNamed(a, b, id)
}

// deltaHolder reports whether id holds, at either end, an address some
// identity selector's resolution gained or lost from a to b: its own role
// set moved, or it shares an address with a node whose roles or policy
// facts did.
func deltaHolder(a, b *stage, id types.NodeID) bool {
	return movedSubjects(a, b)[id]
}

// TestFiltersChangedSoundPreciseAndCarried drives each scenario's filters
// in both source modes as the world and the hub do, the hub routing every
// commit but those it draws coalesced, and holds:
//
//   - soundness, by node: when the hub routes, every node whose filter, cut
//     afresh in the form its facts send it, moved since the stage the hub
//     last routed to is named by that routing (Filters.ChangedFor, with the
//     nodes whose facts moved, as Since names them), whatever its session
//     read;
//   - soundness, by session: every session that read and was not named
//     since holds what is cut afresh now, or routing from the snapshot it
//     holds names it (the one the hub last routed to, or a later one the
//     session read, which the hub's render log routes from), as above;
//     Filters.Changed names it when the form it holds moved; and so does
//     the narrow set routing would use without naming subnet routers
//     wholesale;
//   - precision, in capability mode across steps that edit no policy:
//     routing names no node sent capabilities at both ends whose
//     capability-form filter did not move, but the exceptions it states
//     (precision);
//   - the carry: every filter served to a session the step marks read
//     equals one cut afresh from the same inputs, however many commits it
//     was carried across and whichever form it was last read in.
//
// Oracle: the filters' fresh twin (Filters.Fresh), the same cutter over
// the same inputs with nothing carried; it sees routing and carry
// mistakes, not cutting mistakes (TestPipelineIncrementalMatchesScratch and
// the reference properties see those).
func TestFiltersChangedSoundPreciseAndCarried(t *testing.T) {
	t.Parallel()

	var (
		shapes shapeTally
		tally  changeTally
	)

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")
		coalesced := rapid.SliceOfN(rapid.Map(rapid.IntRange(0, 3), func(n int) bool { return n == 3 }), len(s.Steps), len(s.Steps)).Draw(t, "coalesced")

		shapes.add(s)

		st, err := stageAt(nil, s.Start, policymodel.Change{})
		if err != nil {
			t.Fatalf("the start's policy is refused: %s", stableError(err))
		}

		stages := make([]*stage, 1, 1+len(s.Steps))
		stages[0] = st
		policyEdited := make([]bool, 1, 1+len(s.Steps))
		runs := []*modeRun{{mode: AddressSources, sess: map[types.NodeID]*session{}}, {mode: CapabilitySources, sess: map[types.NodeID]*session{}}}

		read := func(k int, ids []types.NodeID) {
			for _, m := range runs {
				f := m.filters(stages[k])

				for _, id := range ids {
					facts := m.facts(stages[k], id)
					form := formOf(receiverForm(m.mode, facts))
					_, own := f.byNode[form].Load(id)

					served, err := f.ForNode(id, facts)
					fresh, errFresh := m.fresh(stages[k], id, facts)

					if !sameRules(served, err, fresh, errFresh) {
						t.Fatalf("mode %d after step %d: n%d (facts %+v) is served %s, cut afresh %s", m.mode, k, id, facts, rulesJSON(served, err), rulesJSON(fresh, errFresh))
					}

					if s, ok := m.sess[id]; ok && !own {
						if _, carried := f.carried[form].Load().Get(id); carried {
							tally.add("served from the carry")

							if s.at < k-1 {
								tally.add("served from the carry across unread commits")
							}

							if receiverForm(m.mode, m.facts(stages[s.at], id)) != receiverForm(m.mode, facts) {
								tally.add("served from the carry after a form flip")
							}
						}
					}

					m.sess[id] = &session{at: k}
				}
			}
		}

		read(0, nodeIDsOf(st))

		w := s.Start

		for i, step := range s.Steps {
			k := i + 1
			next, change := w.Commit(step)

			st, err = stageAt(st, next, change)
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", k, stableError(err))
			}

			stages = append(stages, st)
			policyEdited = append(policyEdited, change.Policy)

			// A session whose node left has ended.
			for _, m := range runs {
				for id := range m.sess {
					if _, ok := next.Topology.Node(id); !ok {
						delete(m.sess, id)
					}
				}
			}

			if coalesced[i] {
				tally.add("coalesced commits")
			} else {
				for _, m := range runs {
					// TODO(kradalby): overwake/compare-filters: precision is judged
					// across membership changes only; extend it to document edits
					// when compareFilters and the template-moved paths of
					// grantDelta in expand.go name only the receivers whose filter
					// a document edit moves.
					if m.mode == CapabilitySources && !slices.Contains(policyEdited[m.routed+1:], true) {
						if msg := m.precision(stages[m.routed], st, &tally); msg != "" {
							t.Fatalf("routing from step %d to step %d (%s), no policy edited: %s", m.routed, k, step, msg)
						}
					}

					if msg := m.route(stages, k, &tally); msg != "" {
						t.Fatalf("mode %d, routing to step %d (%s) %s", m.mode, k, step, msg)
					}

					m.routed = k
				}
			}

			read(k, slices.DeleteFunc(slices.Clone(step.Reads), func(id types.NodeID) bool {
				_, ok := next.Topology.Node(id)

				return !ok
			}))

			w = next
		}
	})

	t.Logf("filters change: %v", &tally)
	shapes.log(t, "filters change")
}

// overNamed says why routing names id though nothing it is cut reads
// moved, for the over-namings known: it receives a companion rule at
// either end (it holds a companion's destination atom, the sources the
// rule runs to), it holds a via grant's tag, or it receives a grant with
// an app or portless rule (it holds the grant's destination atoms).
func overNamed(a, b *stage, id types.NodeID) string {
	for _, st := range []*stage{a, b} {
		for g := range st.sides.plan.grants {
			gs := &st.sides.plan.grants[g]

			// TODO(kradalby): overwake/address-pair-destinations: delete
			// this class when grantDelta in expand.go stops naming every
			// receiver of an app or portless grant, in every form, when
			// only its destinations moved.
			if addressPair(st.t.grants[g]) {
				for _, at := range slices.Concat(gs.portDst, gs.capDst) {
					if slices.Contains(st.sides.Holders(at), id) {
						return "address-pair grant receiver"
					}
				}
			}

			// TODO(kradalby): overwake/companion-receivers: delete this
			// class when grantDelta in expand.go stops naming a companion's
			// receivers when only the grant's sources moved.
			for _, at := range gs.compDst {
				if gs.comp && slices.Contains(st.sides.Holders(at), id) {
					return "companion receiver"
				}
			}

			// TODO(kradalby): overwake/via-tag-holders: delete this class
			// when viaRouters in expand.go names only the tag holders a via
			// rule can reach (those serving a route), not every holder.
			for _, tag := range gs.viaTags {
				if slices.Contains(st.posts.Nodes(SelectorRole(tag)), id) {
					return "via tag holder"
				}
			}
		}
	}

	return ""
}

// selfOwnerMoved reports whether n is an owner node whose user's self
// rules of some self grant do not go as its capability at both ends with
// the same sources naming its nodes alike, which routing names in every
// form, as routing decides: naming read off the rules by address, not
// routing's shortcut.
func selfOwnerMoved(a, b *stage, n types.NodeView) bool {
	if n.IsTagged() || !n.User().Valid() {
		return false
	}

	uid := n.User().ID()

	xa, errA := a.cap.expansion()
	xb, errB := b.cap.expansion()

	if errA != nil || errB != nil {
		return true
	}

	for g := range b.t.grants {
		ga, gb := a.t.grants[min(g, len(a.t.grants)-1)], b.t.grants[g]
		if gb.kind != grantSelf && ga.kind != grantSelf {
			continue
		}

		if len(a.t.grants) != len(b.t.grants) || ga.kind != grantSelf || gb.kind != grantSelf || ga.none || gb.none {
			return true
		}

		na, nb := xa.selfRules(g, uid).named, xb.selfRules(g, uid).named
		if !xa.selfCapabilityOnly(g, na) || !xb.selfCapabilityOnly(g, nb) ||
			!slices.Equal(na, nb) || !slices.Equal(xa.srcIDs(g), xb.srcIDs(g)) {
			return true
		}
	}

	return false
}

// movedSubjects are the nodes a membership change is about: those whose
// policy facts or role sets moved from a to b, and those holding an
// address of one at either end, whose own reach of a destination moves
// with it.
func movedSubjects(a, b *stage) map[types.NodeID]bool {
	out := map[types.NodeID]bool{}

	for _, id := range nodeIDsOf(a, b) {
		was, wasOK := a.cap.node(id)
		is, isOK := b.cap.node(id)
		ra, _ := a.roles.Of(id)
		rb, _ := b.roles.Of(id)

		if wasOK != isOK || was != is && was.HasPolicyChange(is) || roleNames(a.sel.table, ra) != roleNames(b.sel.table, rb) {
			out[id] = true
		}
	}

	for _, st := range []*stage{a, b} {
		for _, ids := range st.sides.byAddr.Groups.All() {
			if slices.ContainsFunc(ids, func(id types.NodeID) bool { return out[id] }) {
				for _, id := range ids {
					out[id] = true
				}
			}
		}
	}

	return out
}
