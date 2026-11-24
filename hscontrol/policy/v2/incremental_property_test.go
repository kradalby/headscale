// Properties of the policy pipeline as the world runs it: every layer
// updated from its previous value, step by step, over generated scenarios.
// The oracle is the same pipeline built from nothing for the same world;
// it shares every function with what it checks and so sees only what
// incremental updating, reuse and identity get wrong, not what a layer
// means (the reference properties judge that).

package v2

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// stage is the pipeline after one step: [served]'s cells and the via plan,
// each updated from the stage before.
type stage struct {
	*served

	via ViaPlans
}

// stageAt returns the pipeline for w, following prev across the step that
// led to w, which change describes; from scratch when prev is nil.
func stageAt(prev *stage, w policymodel.World, change policymodel.Change) (*stage, error) {
	var (
		ps *served
		pv ViaPlans
	)

	if prev != nil {
		ps, pv = prev.served, prev.via
	}

	sv, err := serve(ps, w, change)
	if err != nil {
		return nil, err
	}

	return &stage{served: sv, via: UpdateViaPlans(pv, sv.sides)}, nil
}

// shapeTally counts, for one property, the classifier's shapes the
// scenarios it judged held, so a report shows which it never met.
type shapeTally struct {
	mu        sync.Mutex
	scenarios int
	n         map[string]int
}

func (s *shapeTally) add(sc policymodel.Scenario) {
	names := policymodel.Classify(sc, policymodel.Required)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.n == nil {
		s.n = map[string]int{}
	}

	s.scenarios++

	for _, n := range names {
		s.n[n]++
	}
}

// log prints what was reached and, by name, what was not.
func (s *shapeTally) log(t *testing.T, what string) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	var hit, missed []string

	for _, sh := range policymodel.Required {
		if c := s.n[sh.Name]; c > 0 {
			hit = append(hit, fmt.Sprintf("%s=%d", sh.Name, c))
		} else {
			missed = append(missed, sh.Name)
		}
	}

	t.Logf("%s: shapes over %d scenarios: %s", what, s.scenarios, strings.Join(hit, " "))
	t.Logf("%s: shapes never reached: %v", what, missed)
}

// fingerprint is a stage written out layer by layer, key by key, so two
// stages compare as maps and a difference names its layer and key. Role
// sets are written as the selectors and atoms they hold, never as their
// handles: a handle means something only within its table.
type fingerprint map[string]string

func (f fingerprint) set(k string, v any) { f[k] = fmt.Sprint(v) }

// firstDiff returns the first key, in order, where a and b differ, with
// both values.
func firstDiff(a, b fingerprint) string {
	keys := slices.Sorted(maps.Keys(a))
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)

	for _, k := range slices.Compact(keys) {
		av, aok := a[k]
		bv, bok := b[k]

		if aok != bok || av != bv {
			return fmt.Sprintf("%s: incremental %s, from scratch %s", k, orAbsent(av, aok), orAbsent(bv, bok))
		}
	}

	return ""
}

func orAbsent(v string, ok bool) string {
	if !ok {
		return "(absent)"
	}

	return v
}

// roleName writes r with selector roles by name, under table.
func roleName(table *SelectorTable, r Role) string {
	if id, ok := r.Selector(); ok && int(id) < table.Len() {
		return table.Selector(id).Name
	}

	if id := SelectorID(r.value); r.kind == roleLiteral && int(id) < table.Len() { //nolint:gosec // a literal role holds a selector ID
		return "literal:" + table.Selector(id).Name
	}

	return r.String()
}

func roleNames(table *SelectorTable, rs RoleSet) string {
	var out []string
	for r := range rs.All() {
		out = append(out, roleName(table, r))
	}

	return strings.Join(out, ",")
}

func selNames(table *SelectorTable, ids []SelectorID) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = table.Selector(id).Name
	}

	return strings.Join(out, ",")
}

func rulesJSON(rules []tailcfg.FilterRule, err error) string {
	if err != nil {
		return "error " + err.Error()
	}

	return jsonString(rules)
}

// jsonString is v as JSON, or why it is not, for messages.
func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unmarshalable: " + err.Error()
	}

	return string(b)
}

// eligibleFacts send a node capability form, unknownFacts address form:
// cutting both shows a node's two forms whatever its own facts.
var (
	eligibleFacts = ReceiverFacts{Client: true}
	unknownFacts  = ReceiverFacts{}
)

// fingerprintOf writes st out. filters are the filters to cut: st's own
// for a stage built from scratch, their fresh twins for an incremental one.
func fingerprintOf(st *stage, ip, capf *Filters) fingerprint {
	f := fingerprint{}
	table := st.sel.table

	sels := make([]string, 0, table.Len())
	for _, s := range table.Selectors() {
		sels = append(sels, s.Kind.String()+" "+s.Name)
	}

	f.set("selectors", strings.Join(sels, "; "))
	f.set("selectors self", table.self)

	for _, id := range table.users {
		f.set("user set "+table.Selector(id).Name, st.us.Users(id))
	}

	for uid, ids := range st.us.byUser.All() {
		f.set(fmt.Sprintf("user %d selectors", uid), selNames(table, ids))
	}

	for id, rs := range st.roles.All() {
		f.set(fmt.Sprintf("roles n%d", id), roleNames(table, rs))
	}

	for r, ids := range st.posts.All() {
		f.set("posting "+roleName(table, r), ids)
	}

	f.set("approvals", st.appr.Strings())

	fingerprintSides(f, st.sides, table)

	for _, n := range st.list {
		f.set(fmt.Sprintf("peers n%d", n.ID), st.peers.Peers(n.ID))

		var readers []types.NodeID
		for _, ids := range st.peers.Readers(n.ID) {
			readers = append(readers, ids...)
		}

		slices.Sort(readers)
		f.set(fmt.Sprintf("readers n%d", n.ID), slices.Compact(readers))

		f.set(fmt.Sprintf("receiver n%d", n.ID), fmt.Sprintf("%+v", st.recv.Of(n.ID)))

		rs, _ := st.roles.Of(n.ID)
		f.set(fmt.Sprintf("stamps n%d", n.ID), st.t.StampsOf(rs))

		f.set(fmt.Sprintf("ip filter n%d", n.ID), rulesJSON(ip.ForNode(n.ID, unknownFacts)))
		f.set(fmt.Sprintf("cap filter n%d capability form", n.ID), rulesJSON(capf.ForNode(n.ID, eligibleFacts)))
		f.set(fmt.Sprintf("cap filter n%d address form", n.ID), rulesJSON(capf.ForNode(n.ID, unknownFacts)))
		f.set(fmt.Sprintf("cap filter n%d served form", n.ID), rulesJSON(capf.ForNode(n.ID, st.recv.Of(n.ID))))

		for _, p := range st.list {
			if routes := p.View().AllApprovedRoutes(); len(routes) > 0 && p.ID != n.ID {
				f.set(fmt.Sprintf("route access n%d to n%d", n.ID, p.ID), st.sides.RouteAccess(n.ID, routes))
			}
		}
	}

	// The per-kind counts are held apart, to their facts, by
	// TestReceiverKindsCountEachNodeOnce.
	f.set("receivers address form", st.recv.addressForm)

	f.set("ip global", rulesJSON(ip.Global()))
	f.set("cap global", rulesJSON(capf.Global()))

	fingerprintVia(f, st.via.Plan)

	return f
}

func fingerprintSides(f fingerprint, s Sides, table *SelectorTable) {
	if s.sidesState == nil {
		f.set("sides", "none")

		return
	}

	for id, rs := range s.sets.All() {
		f.set(fmt.Sprintf("side set n%d", id), roleNames(table, rs))
	}

	for id, sf := range s.facts.All() {
		f.set(fmt.Sprintf("side facts n%d", id), fmt.Sprintf(
			"roles=%s ips=%v routes=%v share=%v addrLit=%s routeLit=%s approvedAddr=%t exit=%t pub=%t clique=%d/%t owner=%d/%t named=%t/%t/%t targets=%v touch=%s",
			roleNames(table, sf.roles), sf.ips, sf.routes, sf.share, selNames(table, sf.addrLit), selNames(table, sf.routeLit),
			sf.approvedAddr, sf.exit, sf.pub, sf.clique, sf.cliqued, sf.owner, sf.owned, sf.namedPort, sf.namedApp, sf.namedComp,
			sf.targets, roleNames(table, sf.touch)))
	}

	for r, ids := range s.held.Groups.All() {
		f.set("held "+roleName(table, r), ids)
	}

	for p, atoms := range s.cover.All() {
		var out []string
		for _, a := range atoms {
			out = append(out, fmt.Sprintf("%s×%d", roleName(table, a.r), a.n))
		}

		f.set("cover "+p.String(), strings.Join(out, ","))
	}

	for ip, ids := range s.byAddr.Groups.All() {
		f.set("by address "+ip.String(), ids)
	}

	for p, ids := range s.routers.Groups.All() {
		f.set("routers "+p.String(), ids)
	}

	f.set("targeted", s.targeted)
	f.set("public nodes", s.pub)
	f.set("public selectors", selNames(table, s.pubSel))
	f.set("public owners", slices.Sorted(maps.Keys(s.owners)))
}

func fingerprintVia(f fingerprint, v *ViaPlan) {
	if v == nil {
		f.set("via", "none")

		return
	}

	for p, scopes := range v.scopes {
		var out []string
		for _, sc := range scopes {
			out = append(out, fmt.Sprintf("%s=%v", sc.via, sc.candidates.AsSlice()))
		}

		f.set("via scopes "+p.String(), strings.Join(out, " "))
	}

	f.set("via destinations", v.dsts)
}

// templatesDiffer returns how inc's templates differ from scr's: grants and
// literals compared by content, each template read by its grant.
func templatesDiffer(inc, scr *Templates) string {
	if (inc.err == nil) != (scr.err == nil) {
		return fmt.Sprintf("template error: incremental %v, from scratch %v", inc.err, scr.err)
	}

	if len(inc.grants) != len(scr.grants) {
		return fmt.Sprintf("%d grant templates, from scratch %d", len(inc.grants), len(scr.grants))
	}

	for g := range inc.grants {
		if !reflect.DeepEqual(*inc.grants[g], *scr.grants[g]) {
			return fmt.Sprintf("grant %d's template differs from one built from scratch: incremental %s, from scratch %s", g, grantJSON(inc.grants[g]), grantJSON(scr.grants[g]))
		}
	}

	if !reflect.DeepEqual(inc.literals, scr.literals) {
		return fmt.Sprintf("literals differ: incremental %v, from scratch %v", literalStrings(inc), literalStrings(scr))
	}

	return ""
}

func grantJSON(gt *GrantTemplate) string {
	return fmt.Sprintf("%s (srcs %v dsts %v none %t kind %d)", jsonString(gt.src), gt.srcs, gt.dsts, gt.none, gt.kind)
}

func literalStrings(t *Templates) []string {
	out := make([]string, len(t.literals))

	for i, l := range t.literals {
		if l.res != nil {
			out[i] = strings.Join(l.res.Strings(), " ")
		}
	}

	return out
}

// identityDiffers returns how cur, updated from prev, breaks an identity
// later layers rely on: what did not change keeps its value by identity,
// and what is kept by identity did not change.
func identityDiffers(prev, cur *stage) string {
	keptTable := cur.sel.table == prev.sel.table
	if same := prev.sel.table.sameSelectors(cur.sel.table); keptTable != same {
		return fmt.Sprintf("the selector table is kept %t, though its selectors are the same %t", keptTable, same)
	}

	if !cur.sel.Describes(cur.pm) {
		return "the selectors do not describe the policy compiled"
	}

	if keptTable && slices.EqualFunc(prev.us.bySel, cur.us.bySel, slices.Equal[[]uint]) && cur.us != prev.us {
		return "every user selector names the users it named, yet the user sets are new"
	}

	if msg := roleIdentity(prev, cur, keptTable); msg != "" {
		return msg
	}

	if msg := postingIdentity(prev, cur, keptTable); msg != "" {
		return msg
	}

	if msg := templateIdentity(prev.t, cur.t); msg != "" {
		return msg
	}

	if cur.via.Plan != prev.via.Plan && prev.via.Plan != nil && cur.via.Plan.plan == prev.via.Plan.plan && cur.via.Plan.sameContent(prev.via.Plan) {
		return "the via plan's content is the same, yet it is a new plan"
	}

	if cur.recv.Same(prev.recv) {
		for _, n := range cur.list {
			if prev.recv.Of(n.ID) != cur.recv.Of(n.ID) {
				return fmt.Sprintf("the receivers are kept, yet n%d's facts moved", n.ID)
			}
		}
	}

	return ""
}

// roleIdentity: within a table a role set's handle is its content, so two
// nodes, or one node at two steps, hold equal handles exactly when their
// roles are equal; and the roles are kept by identity exactly when no
// node's set moved.
func roleIdentity(prev, cur *stage, keptTable bool) string {
	byContent := map[string]RoleSet{}

	check := func(at string, id types.NodeID, rs RoleSet) string {
		k := roleNames(cur.sel.table, rs)
		if was, ok := byContent[k]; ok && was != rs {
			return fmt.Sprintf("%s n%d's role set {%s} is not the handle another node holds for the same roles", at, id, k)
		}

		byContent[k] = rs

		return ""
	}

	for id, rs := range cur.roles.All() {
		if msg := check("now", id, rs); msg != "" {
			return msg
		}
	}

	moved := false

	if keptTable {
		for id, rs := range prev.roles.All() {
			if msg := check("before", id, rs); msg != "" {
				return msg
			}

			if is, ok := cur.roles.Of(id); !ok || is != rs {
				moved = true
			}
		}

		if prev.roles.sets.Len() != cur.roles.sets.Len() {
			moved = true
		}

		if !moved && !cur.roles.Same(prev.roles) {
			return "no node's role set moved, yet the roles are new"
		}
	}

	if cur.roles.Same(prev.roles) && (!keptTable || moved) {
		return "the roles are kept, yet a role set moved or the table is new"
	}

	return ""
}

// postingIdentity: a list no edit changed keeps its backing array, and
// Postings.Changed names every role whose list moved, all of them across
// tables.
func postingIdentity(prev, cur *stage, keptTable bool) string {
	changed, all := cur.posts.Changed(prev.posts)

	if !keptTable {
		if !all {
			return "across a new selector table the postings' change is not all"
		}

		return ""
	}

	if all {
		return "within one selector table the postings' change is all"
	}

	for r, ids := range cur.posts.All() {
		was := prev.posts.Nodes(r)

		switch {
		case slices.Equal(was, ids):
			if len(ids) > 0 && &was[0] != &ids[0] {
				return fmt.Sprintf("posting %s is unchanged, yet its list was copied", roleName(cur.sel.table, r))
			}
		case !slices.Contains(changed, r):
			return fmt.Sprintf("posting %s moved from %v to %v, and Postings.Changed (%v) leaves it out", roleName(cur.sel.table, r), was, ids, changed)
		}
	}

	for r, ids := range prev.posts.All() {
		if len(cur.posts.Nodes(r)) == 0 && len(ids) > 0 && !slices.Contains(changed, r) {
			return fmt.Sprintf("posting %s emptied, and Postings.Changed leaves it out", roleName(cur.sel.table, r))
		}
	}

	return ""
}

// templateIdentity: a template is shared across two builds only for the
// same table and an equal grant, and within one table an equal grant is
// always shared, which is what routing reads as "this grant did not move".
func templateIdentity(prev, cur *Templates) string {
	if prev.sel == cur.sel && prev != cur {
		return "the selectors are the same, yet the templates are new"
	}

	for g, gt := range cur.grants {
		var equals []*GrantTemplate

		for pg, pt := range prev.grants {
			equal := prev.table() == cur.table() && reflect.DeepEqual(pt.src, gt.src)
			if pt == gt && !equal {
				return fmt.Sprintf("grant %d keeps grant %d's template, though the table or the grant moved: %s", g, pg, grantJSON(gt))
			}

			if equal {
				equals = append(equals, pt)
			}
		}

		if len(equals) > 0 && !slices.Contains(equals, gt) {
			return fmt.Sprintf("grant %d equals a grant of the last build in one table, yet its template is new: %s", g, grantJSON(gt))
		}
	}

	return ""
}

// tableDiffersFromModel holds the selector table to the model's reading
// of what the document names in the sections the table covers (rules,
// via lists, SSH rules; * for a document allowing everything): an
// oracle that is not headscale's.
func tableDiffersFromModel(table *SelectorTable, p policymodel.Policy) string {
	got := make([]string, 0, table.Len())
	for _, s := range table.Selectors() {
		got = append(got, s.Name)
	}

	sels := p.Selectors()

	want := make([]string, 0, len(sels))
	for _, s := range sels {
		want = append(want, s.String())
	}

	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, slices.Compact(want)) {
		return fmt.Sprintf("the selector table names %v, the document %v", got, slices.Compact(want))
	}

	return ""
}

// TestPipelineIncrementalMatchesScratch drives each scenario through the
// pipeline step by step, each layer updated from its previous value as the
// world updates it, and after every step holds every layer to the same
// layer built from nothing for that world: the selector table, user sets,
// role sets, postings, templates and literals, approvals, sides (side
// sets, facts, holders, cover, address and route indexes, public lists),
// peers and readers, receiver facts and the address-form index, the via
// plan, route access, stamps, and every node's filter in address mode and in both capability-mode forms,
// cut from the incremental inputs. It also holds the identities later
// layers key on (identityDiffers), and the table to the model's reading
// of the document (tableDiffersFromModel).
//
// Oracle: the pipeline from scratch, the same functions; it sees only what
// updating, reuse and carried values get wrong.
func TestPipelineIncrementalMatchesScratch(t *testing.T) {
	t.Parallel()

	var shapes shapeTally

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")
		shapes.add(s)

		inc, err := stageAt(nil, s.Start, policymodel.Change{})
		if err != nil {
			t.Fatalf("the start's policy is refused: %s", stableError(err))
		}

		w := s.Start

		for i, st := range s.Steps {
			next, change := w.Commit(st)

			prev := inc

			inc, err = stageAt(prev, next, change)
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i+1, stableError(err))
			}

			scr, err := stageAt(nil, next, policymodel.Change{})
			if err != nil {
				t.Fatalf("after step %d the policy is refused from scratch: %s", i+1, stableError(err))
			}

			if msg := nodeCapsDiffer(inc, scr); msg != "" {
				t.Fatalf("after step %d (%s): %s", i+1, st, msg)
			}

			if msg := tableDiffersFromModel(inc.sel.table, next.Policy); msg != "" {
				t.Fatalf("after step %d (%s): %s", i+1, st, msg)
			}

			if msg := identityDiffers(prev, inc); msg != "" {
				t.Fatalf("step %d (%s): %s", i+1, st, msg)
			}

			if msg := templatesDiffer(inc.t, scr.t); msg != "" {
				t.Fatalf("after step %d (%s): %s", i+1, st, msg)
			}

			if msg := firstDiff(fingerprintOf(inc, inc.ip.Fresh(), inc.cap.Fresh()), fingerprintOf(scr, scr.ip, scr.cap)); msg != "" {
				t.Fatalf("after step %d (%s): %s", i+1, st, msg)
			}

			w = next
		}
	})

	shapes.log(t, "incremental matches scratch")
}

// nodeCapsDiffer compares the compile's node capabilities, which the
// receivers' facts and the rendered caps read.
func nodeCapsDiffer(inc, scr *stage) string {
	for _, n := range inc.list {
		a, _ := inc.caps.Get(n.ID)
		b, _ := scr.caps.Get(n.ID)

		if !a.Equal(b) {
			return fmt.Sprintf("n%d's node capabilities: incremental %v, from scratch %v", n.ID, slices.Sorted(maps.Keys(a)), slices.Sorted(maps.Keys(b)))
		}
	}

	return ""
}

// receiverKindsDiffer returns how r's count of nodes per kind of facts,
// which the census reports receivers from, differs from a count of the
// facts r holds.
func receiverKindsDiffer(r Receivers) string {
	var want [numFactKinds]int

	for _, f := range r.facts.All() {
		want[f.kind()]++
	}

	if want != r.kinds {
		return fmt.Sprintf("receivers count %v nodes by kind, they hold facts for %v", r.kinds, want)
	}

	return ""
}

// TestReceiverKindsCountEachNodeOnce holds the receivers' count of nodes
// per kind of facts, which the census's receiver counts come from, to the
// facts they hold, after every step of each scenario. Oracle: a count of
// the same facts.
//
// A node whose node and capabilities change in one commit, as every node
// holding a capability does when it joins, must still be counted once.
func TestReceiverKindsCountEachNodeOnce(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(propertySteps).Draw(t, "scenario")

		st, err := stageAt(nil, s.Start, policymodel.Change{})
		if err != nil {
			t.Fatalf("the start's policy is refused: %s", stableError(err))
		}

		if msg := receiverKindsDiffer(st.recv); msg != "" {
			t.Fatalf("at the start: %s", msg)
		}

		w := s.Start

		for i, step := range s.Steps {
			next, change := w.Commit(step)

			st, err = stageAt(st, next, change)
			if err != nil {
				t.Fatalf("after step %d the policy is refused: %s", i+1, stableError(err))
			}

			if msg := receiverKindsDiffer(st.recv); msg != "" {
				t.Fatalf("after step %d (%s): %s", i+1, step, msg)
			}

			w = next
		}
	})
}
