package policymodel

import (
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// How large drawn cases grow. Most stay small, so that the default run
// stays cheap and shrinking has little to cut; a tail grows to the
// structure real tailnets have: dozens of nodes, more users, long rule
// lists, long edit scripts. Past its least length a rapid list stops at
// least one element in six whatever its bounds, so a long tail comes from
// lists of runs; gates set only the bounds, and a shrunk gate is the
// small case.
const (
	// fleetNodes is the most nodes a run of nodes holds, largeFleetNodes
	// in a large topology, which holds up to largeFleets runs.
	fleetNodes      = 4
	largeFleetNodes = 6
	largeFleets     = 12
	// largeTopologies is one in how many topologies is large.
	largeTopologies = 24

	// ruleRun is the most rules a run of rules holds; a long policy holds
	// up to longRuleRuns of them, one in longPolicies.
	ruleRun      = 4
	longRuleRuns = 8
	longPolicies = 12

	// stepRun is the most steps a run of steps holds. One scenario in
	// longScenarios may run longScenarioTimes as many steps as asked for,
	// in runs of up to longStepRun.
	stepRun           = 3
	longStepRun       = 6
	longScenarios     = 12
	longScenarioTimes = 3

	// quietBits sets how rarely a scenario takes no step: one in
	// 2^quietBits; and companyBits how rarely a topology is one run of
	// nodes, which is all a single node can come from.
	quietBits   = 4
	companyBits = 3

	// followUps is one in how many steps works on its run's focus.
	followUps = 4

	// shareChains is one scenario in how many that starts with the share
	// chain script (database only).
	shareChains = 30

	// anyOf bounds a draw picking among what the world decides, so that
	// every node of a large world can be picked.
	anyOf = 63

	// Database-only addresses are drawn rarely, and in small worlds: the
	// reference properties skip a world holding one whole. One small world
	// in outsideWorlds may hold addresses outside the tailnet, one in
	// sharedWorlds shared ones, and one address edit in strayAddrs may move
	// onto either.
	outsideWorlds = 32
	sharedWorlds  = 32
	strayAddrs    = 24
)

// crowd is the identity of users after the fourth, drawn in large
// topologies only: no token names one of them alone, so they come in
// through autogroup:member, autogroup:self, groups by e-mail domain and
// *; some log in through OIDC.
var crowd = []User{
	{ID: 5, Name: "frank", Email: "frank@example.com"},
	{ID: 6, Name: "grace", Email: "grace@example.com", Provider: providerPrefix + "6"},
	{ID: 7, Name: "heidi"},
	{ID: 8, Name: "ivan", Email: "ivan@example.com", Provider: providerPrefix + "8"},
	{ID: 9, Name: "judy", Email: "judy@example.org"},
	{ID: 10, Name: "mallory", Email: "mallory@example.com", Provider: providerPrefix + "10"},
}

// identities is every user a topology may start with, in ID order.
var identities = slices.Concat(defaultUsers, crowd)

// usually is true but for one draw in 2^bits, and false when shrunk: a
// gate for what most cases have and the plainest case does not.
func usually(t *rapid.T, bits int, label string) bool {
	on := false

	for range bits {
		if rapid.Bool().Draw(t, label) {
			on = true
		}
	}

	return on
}

// runs bounds a list of runs: from least to most runs, of 1 to each
// elements.
type runs struct{ each, least, most int }

// runsOf draws the runs r bounds, one after another. The shrinker deletes
// a run, or an element of one, whole.
func runsOf[E any](t *rapid.T, elem *rapid.Generator[E], r runs, label string) []E {
	var out []E

	for _, run := range rapid.SliceOfN(rapid.SliceOfN(elem, 1, r.each), r.least, r.most).Draw(t, label) {
		out = append(out, run...)
	}

	return out
}

// topologySize is how many users a topology may hold, how its nodes come,
// and whether it is large.
type topologySize struct {
	users int
	nodes runs
	large bool
}

// drawTopologySize draws a topology's size: one run of nodes, rarely,
// which is the plainest; two mostly; up to largeFleets longer ones, with
// the crowd of users, in a large topology.
func drawTopologySize(t *rapid.T) topologySize {
	company := usually(t, companyBits, "company")
	large := chance(t, largeTopologies, "large-topology")

	sz := topologySize{users: len(defaultUsers), nodes: runs{each: fleetNodes, least: 1, most: 1}, large: large}

	if company {
		sz.nodes.least, sz.nodes.most = 2, 2
	}

	if large {
		sz.users, sz.nodes.each, sz.nodes.most = len(identities), largeFleetNodes, largeFleets
	}

	return sz
}

// ruleRuns draws how a policy's rules come: one run mostly, several in a
// long policy.
func ruleRuns(t *rapid.T) runs {
	if chance(t, longPolicies, "long-policy") {
		return runs{each: ruleRun, least: 1, most: longRuleRuns}
	}

	return runs{each: ruleRun, least: 1, most: 1}
}

// stepRuns draws how a scenario's steps come, and how many it may take in
// all: none, rarely, which is the plainest; else at least one run, up to
// maxSteps steps, or a few times that in a long scenario.
func stepRuns(t *rapid.T, maxSteps int) (runs, int) {
	busy := usually(t, quietBits, "busy")
	long := chance(t, longScenarios, "long-scenario")

	r, total := runs{each: stepRun}, maxSteps
	if long {
		r.each, total = longStepRun, total*longScenarioTimes
	}

	if busy {
		r.least, r.most = 1, max(1, total/2)
	}

	return r, total
}

// focus is what a run of steps keeps working on: the node, the rule and
// the user at these ranks, re-read at each step. Nodes and users rank
// newest first, and half the runs keep to the newest, so that what a step
// of the run adds is what the run's next steps edit and delete.
type focus struct{ node, rule, user int }

func drawFocus(t *rapid.T) focus {
	older := rapid.Bool().Draw(t, "focus-older")
	f := focus{
		node: rapid.IntRange(0, anyOf).Draw(t, "focus-node"),
		rule: rapid.IntRange(0, anyOf).Draw(t, "focus-rule"),
		user: rapid.IntRange(0, anyOf).Draw(t, "focus-user"),
	}

	if !older {
		f.node, f.user = 0, 0
	}

	return f
}

// drawStep draws one step valid against w: one step in followUps edits
// the node or the rule of f, as a script does that joins a node, retags
// it and deletes it, or edits one rule twice.
func drawStep(t *rapid.T, w World, f focus) Step {
	focused := chance(t, followUps, "focused")

	var st Step

	if focused {
		st.Edits = drawFocused(t, w, f)
	}

	if len(st.Edits) == 0 {
		st.Edits = drawEdits(t, w)
	}

	st.Reads = drawReads(t, w.Apply(st.Edits...))

	return st
}

// drawReads draws which sessions read after a step: all one step in four,
// else up to two.
func drawReads(t *rapid.T, next World) []types.NodeID {
	all := chance(t, 4, "all-read")
	some := rapid.SliceOfN(rapid.IntRange(0, anyOf), 0, 2).Draw(t, "reads")

	var reads []types.NodeID

	for i, n := range next.Topology.Nodes {
		if all || slices.ContainsFunc(some, func(r int) bool { return r%len(next.Topology.Nodes) == i }) {
			reads = append(reads, n.ID)
		}
	}

	return reads
}

// drawFocused draws an edit of f's node, rule or user in w, in the areas'
// proportions drawEdit draws: registering a node or creating a user makes
// it the plainest focus. Nil when w holds nothing of the area drawn, or
// the rule takes no edit of the kind drawn.
func drawFocused(t *rapid.T, w World, f focus) []Edit {
	nodes, refs, users := w.Topology.Nodes, w.Policy.Refs(), w.Topology.Users

	switch index(t, 5, "focus-area") {
	case 0, 1:
		kind := index(t, numNodeEdits, "node-edit")

		switch {
		case kind == editJoin:
			if n, ok := drawJoiner(t, w, nodes); ok {
				return []Edit{Join{n}}
			}
		case len(nodes) > 0:
			return []Edit{drawNodeEditOn(t, w, kind, nodes[len(nodes)-1-f.node%len(nodes)])}
		}
	case 2, 3:
		if len(refs) > 0 {
			if e := drawRuleEditOn(t, w, refs[f.rule%len(refs)]); e != nil {
				return []Edit{e}
			}
		}
	default:
		kind := index(t, 4, "user-edit")

		if len(users) > 0 {
			return []Edit{drawUserEditOn(t, w, kind, users[len(users)-1-f.user%len(users)])}
		}
	}

	return nil
}

// drawRuleEditOn draws an in-place edit of rule ref, as drawPolicyEdit
// would draw one for it; nil when the document holds a token users made
// ambiguous, which only replacing it fixes, or when ref takes no edit of
// the kind drawn.
func drawRuleEditOn(t *rapid.T, w World, ref RuleRef) Edit {
	v := NewView(w)
	p := w.Policy
	kind := index(t, numRuleEdits, "rule-edit-kind")

	if len(v.AmbiguousRefs()) > 0 {
		return nil
	}

	var e Edit

	switch kind {
	case editSel:
		e = drawSetSel(t, p, ref)
	case editPorts:
		e, _ = drawSetPorts(t, p, []RuleRef{ref})
	case editProto:
		e, _ = drawSetProto(t, p, []RuleRef{ref})
	case editIP, editApp, editVia:
		if ref.Grant {
			e, _ = drawGrantPart(t, p, ref, kind)
		}
	case editAddSel:
		e = drawAddSel(t, p, ref)
	case editRemoveSel:
		e, _ = drawRemoveSel(t, p, []RuleRef{ref})
	}

	if e == nil {
		return nil
	}

	return remapRefs(e, func(r int) int { return unambiguous(v, r) })
}
