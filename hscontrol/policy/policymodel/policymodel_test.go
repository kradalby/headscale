package policymodel

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

const modulePath = "github.com/juanfont/headscale/"

// TestImports keeps the package independent of what its properties check:
// it imports, of headscale, only hscontrol/types. And it stays out of the
// binary: no file outside tests imports it.
func TestImports(t *testing.T) {
	t.Parallel()

	allowed := []string{modulePath + "hscontrol/types", "tailscale.com/", "go4.org/", "pgregory.net/rapid"}

	for path, imports := range importsOf(t, ".", false) {
		for _, imp := range imports {
			std := !strings.Contains(strings.Split(imp, "/")[0], ".")
			if !std && !slices.ContainsFunc(allowed, func(a string) bool { return imp == a || strings.HasPrefix(imp, a) && strings.HasSuffix(a, "/") }) {
				t.Errorf("%s imports %s; the model must not share code with what it checks", path, imp)
			}
		}
	}

	self := modulePath + "hscontrol/policy/policymodel"

	for _, dir := range []string{"../..", "../../../cmd"} {
		for path, imports := range importsOf(t, dir, true) {
			if !strings.Contains(path, "policymodel") && slices.Contains(imports, self) {
				t.Errorf("%s imports %s; only tests may", path, self)
			}
		}
	}
}

// importsOf returns the imports of every non-test Go file in dir, and
// below it if deep, by path.
func importsOf(t *testing.T, dir string, deep bool) map[string][]string {
	t.Helper()

	out := map[string][]string{}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if path != dir && (!deep || d.Name() == "testdata") {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			out[path] = append(out[path], p)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// TestGeneratorsAreDeterministic: the same seed draws the same case, and
// building it twice gives the same document and nodes. Anything reading
// the clock or a map's order would break both, and with them shrinking.
func TestGeneratorsAreDeterministic(t *testing.T) {
	t.Parallel()

	gen := Scenarios(30)

	for i := range 200 {
		a, b := gen.Example(i), gen.Example(i)
		if !reflect.DeepEqual(a, b) || a.GoString() != b.GoString() {
			t.Fatalf("seed %d drew two scenarios:\n%#v\n%#v", i, a, b)
		}

		for _, w := range a.Worlds() {
			first, second := w.Policy.HuJSON(), w.Policy.HuJSON()
			if string(first) != string(second) {
				t.Fatalf("seed %d: the document differs between writes", i)
			}

			u1, n1 := w.Topology.Build()
			u2, n2 := w.Topology.Build()

			if !reflect.DeepEqual(u1, u2) || !reflect.DeepEqual(n1, n2) {
				t.Fatalf("seed %d: the topology builds differently twice", i)
			}
		}
	}
}

// TestSimplestDrawIsPlain draws from all zeros, which is where shrinking
// heads: it must be the plain case, so a minimised counterexample shows
// only what its failure needs.
func TestSimplestDrawIsPlain(t *testing.T) {
	t.Parallel()

	var got Scenario

	rapid.MakeFuzz(func(t *rapid.T) {
		got = Scenarios(30).Draw(t, "scenario")
	})(t, make([]byte, 1<<12))

	want := Scenario{Start: World{
		Policy: Policy{ACLs: []Rule{{Src: []Sel{{Kind: SelAll}}, Dst: []Dest{{Sel: Sel{Kind: SelAll}}}}}},
		Topology: Topology{
			Users:  []User{{ID: 1, Name: "alice"}},
			Nodes:  []Node{{ID: 1, User: 1, V4: ownAddr(4, 1), V6: ownAddr(6, 1)}},
			NextID: 2,
		},
	}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the simplest draw is\n%#v\nwant\n%#v", got, want)
	}

	if doc := string(got.Start.Policy.HuJSON()); !strings.Contains(doc, `{"action": "accept", "src": ["*"], "dst": ["*:*"]}`) {
		t.Fatalf("the simplest document is\n%s", doc)
	}

	_, nodes := got.Start.Topology.Build()
	if hi := nodes[0].Hostinfo; hi.GoVersion == "" || hi.IPNVersion == "" || !nodes[0].Online() {
		t.Fatalf("the simplest node is not an official, online client: %+v", hi)
	}
}

// policyDoc is a policy document read back as plain JSON.
type policyDoc struct {
	Groups    map[string][]string `json:"groups"`
	TagOwners map[string][]string `json:"tagOwners"`
	Hosts     map[string]string   `json:"hosts"`
	ACLs      []struct {
		Action, Proto string
		Src, Dst      []string
	} `json:"acls"`
	Grants []struct {
		Src, Dst, IP, Via []string
		App               map[string][]json.RawMessage
	} `json:"grants"`
	SSH       []json.RawMessage `json:"ssh"`
	NodeAttrs []struct {
		Target, Attr []string
	} `json:"nodeAttrs"`
}

// TestHuJSONSaysWhatThePlanSays reads the document back as plain JSON: it
// has the plan's rules, in order, and defines every name they use.
func TestHuJSONSaysWhatThePlanSays(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		p := Policies().Draw(t, "policy")

		var doc policyDoc

		err := json.Unmarshal(p.HuJSON(), &doc)
		if err != nil {
			t.Fatalf("not JSON: %v\n%s", err, p.HuJSON())
		}

		if len(doc.ACLs) != len(p.ACLs) || len(doc.Grants) != len(p.Grants) || len(doc.SSH) != len(p.SSH) || len(doc.NodeAttrs) != len(p.NodeAttrs) {
			t.Fatalf("the document has %d acls, %d grants, %d ssh and %d nodeAttrs rules", len(doc.ACLs), len(doc.Grants), len(doc.SSH), len(doc.NodeAttrs))
		}

		names := slices.Concat(docACLs(t, p, doc), docGrants(t, p, doc))
		for _, a := range doc.NodeAttrs {
			names = append(names, a.Target...)
		}

		for _, n := range names {
			var defined bool

			switch {
			case strings.HasPrefix(n, "group:"):
				_, defined = doc.Groups[n]
			case strings.HasPrefix(n, "tag:"):
				_, defined = doc.TagOwners[n]
			case slices.Contains(Hosts, n):
				_, defined = doc.Hosts[n]
			default:
				defined = true
			}

			if !defined {
				t.Fatalf("%s is not defined", n)
			}
		}
	})
}

// docACLs holds the document's acls to p's and returns the names they use.
func docACLs(t *rapid.T, p Policy, doc policyDoc) []string {
	var names []string

	for i, r := range p.ACLs {
		d := doc.ACLs[i]
		if d.Action != "accept" || d.Proto != Protos[r.Proto] || !slices.Equal(d.Src, selStrings(r.Src)) || len(d.Dst) != len(r.Dst) {
			t.Fatalf("acls[%d] is %+v", i, d)
		}

		for j, dst := range r.Dst {
			if want := dst.Sel.String() + ":" + Ports[dst.Ports]; d.Dst[j] != want {
				t.Fatalf("acls[%d] dst[%d] is %q, want %q", i, j, d.Dst[j], want)
			}

			names = append(names, dst.Sel.String())
		}

		names = append(names, d.Src...)
	}

	return names
}

// docGrants holds the document's grants to p's and returns the names they
// use.
func docGrants(t *rapid.T, p Policy, doc policyDoc) []string {
	var names []string

	for i, r := range p.Grants {
		d := doc.Grants[i]

		ips := make([]string, len(r.IP))
		for j, ip := range r.IP {
			ips[j] = ip.String()
		}

		if !slices.Equal(d.Src, selStrings(r.Src)) || len(d.Dst) != len(r.Dst) || !slices.Equal(d.IP, ips) || len(d.App) != len(r.App) || len(d.Via) != len(r.Via) {
			t.Fatalf("grants[%d] is %+v", i, d)
		}

		for _, a := range r.App {
			if v, ok := d.App[Apps[a.Cap]]; !ok || len(v) != 1 || string(v[0]) != AppValues[a.Value] {
				t.Fatalf("grants[%d] app is %v", i, d.App)
			}
		}

		names = slices.Concat(names, d.Src, d.Dst, d.Via)
	}

	return names
}

// TestEditUndo applies each step and then the step that undoes it: the
// plan must come back, but for the next ID, which is never handed out
// twice.
func TestEditUndo(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(30).Draw(t, "scenario")

		w := s.Start
		for i, st := range s.Steps {
			next := w.Apply(st...)

			back := next.Apply(Undo(w, st)...)
			back.Topology.NextID = w.Topology.NextID

			if !reflect.DeepEqual(back, w) {
				t.Fatalf("step %d (%s) undone by %s gives\n%#v\nnot\n%#v", i+1, st, Undo(w, st), back, w)
			}

			w = next
		}
	})
}

// TestEditsChangeWhatTheySay applies each edit alone and holds what moved
// to its name: one node's one field, the users, or one part of the
// policy. A property can then tell which input a failure needed.
func TestEditsChangeWhatTheySay(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(30).Draw(t, "scenario")

		w := s.Start
		for _, st := range s.Steps {
			for _, e := range st {
				next := w.Apply(e)

				got, want := touched(w, next), mayTouch(w, e)
				for _, g := range got {
					if !slices.Contains(want, g) {
						t.Fatalf("%s changed %s; it may change only %v", e, g, want)
					}
				}

				err := checkTopology(next.Topology)
				if err != nil {
					t.Fatalf("after %s: %v", e, err)
				}

				w = next
			}
		}
	})
}

// TestCommitTellsWhatChanged replays each step's Change on a mirror of
// the nodes: deleting what it removes and writing what it names must give
// the next world's nodes, a node re-registered under its ID must be both
// removed and written, and the users and policy flags must be exact.
func TestCommitTellsWhatChanged(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(30).Draw(t, "scenario")

		mirror := map[types.NodeID]Node{}
		for _, n := range s.Start.Topology.Nodes {
			mirror[n.ID] = n
		}

		w := s.Start
		for i, st := range s.Steps {
			next, c := w.Commit(st)

			for _, id := range c.Removed {
				delete(mirror, id)
			}

			for _, id := range c.Nodes {
				mirror[id], _ = next.Topology.Node(id)
			}

			if got := slices.SortedFunc(maps.Values(mirror), func(a, b Node) int { return cmp.Compare(a.ID, b.ID) }); !reflect.DeepEqual(got, next.Topology.Nodes) {
				t.Fatalf("step %d (%s): %+v leaves the nodes\n%v\nnot\n%v", i+1, st, c, got, next.Topology.Nodes)
			}

			for j, e := range st {
				if l, ok := e.(Leave); ok && slices.ContainsFunc(st[j+1:], func(o Edit) bool { jn, ok := o.(Join); return ok && jn.Node.ID == l.ID }) &&
					(!slices.Contains(c.Removed, l.ID) || !slices.Contains(c.Nodes, l.ID)) {
					t.Fatalf("step %d (%s): n%d registered again is not both removed and written: %+v", i+1, st, l.ID, c)
				}
			}

			if c.Users != !slices.Equal(w.Topology.Users, next.Topology.Users) || c.Policy != (string(w.Policy.HuJSON()) != string(next.Policy.HuJSON())) {
				t.Fatalf("step %d (%s): %+v", i+1, st, c)
			}

			w = next
		}
	})
}

// touched lists what differs from before to after: "users", and per node
// and per part of the policy what changed.
func touched(before, after World) []string {
	var out []string

	if !reflect.DeepEqual(before.Topology.Users, after.Topology.Users) {
		out = append(out, "users")
	}

	ids := map[types.NodeID]bool{}
	for _, n := range slices.Concat(before.Topology.Nodes, after.Topology.Nodes) {
		ids[n.ID] = true
	}

	for _, id := range slices.Sorted(maps.Keys(ids)) {
		b, okb := before.Topology.Node(id)
		a, oka := after.Topology.Node(id)

		switch {
		case !okb:
			out = append(out, fmt.Sprintf("n%d joined", id))
		case !oka:
			out = append(out, fmt.Sprintf("n%d left", id))
		default:
			bv, av := reflect.ValueOf(b), reflect.ValueOf(a)
			for i := range bv.NumField() {
				if !reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
					out = append(out, fmt.Sprintf("n%d %s", id, bv.Type().Field(i).Name))
				}
			}
		}
	}

	bp, ap := before.Policy, after.Policy
	for i := range numGroups {
		if !slices.Equal(bp.Groups[i], ap.Groups[i]) {
			out = append(out, Groups[i])
		}
	}

	for i := range numTags {
		if !slices.Equal(bp.TagOwners[i], ap.TagOwners[i]) {
			out = append(out, "tagOwners "+Tags[i])
		}
	}

	for i := range numHosts {
		if bp.Hosts[i] != ap.Hosts[i] {
			out = append(out, Hosts[i])
		}
	}

	for _, grant := range []bool{false, true} {
		bl, al := bp.List(grant), ap.List(grant)
		if len(bl) != len(al) {
			out = append(out, listName(grant)+" list")

			continue
		}

		for i := range bl {
			if !reflect.DeepEqual(bl[i], al[i]) {
				out = append(out, RuleRef{grant, i}.String())
			}
		}
	}

	for _, part := range []struct {
		name    string
		changed bool
	}{
		{"ssh", !reflect.DeepEqual(bp.SSH, ap.SSH)},
		{"nodeAttrs", !reflect.DeepEqual(bp.NodeAttrs, ap.NodeAttrs)},
		{"autoApprovers", !reflect.DeepEqual(bp.AutoApprovers, ap.AutoApprovers)},
	} {
		if part.changed {
			out = append(out, part.name)
		}
	}

	return out
}

// mayTouch is what e's name says it changes, as touched writes it.
func mayTouch(w World, e Edit) []string {
	node := func(id types.NodeID, fields ...string) []string {
		out := make([]string, len(fields))
		for i, f := range fields {
			out[i] = fmt.Sprintf("n%d %s", id, f)
		}

		return out
	}

	family := func(f int) string { return "V" + strconv.Itoa(f) }

	switch e := e.(type) {
	case Join:
		return node(e.Node.ID, "joined")
	case Leave:
		return node(e.ID, "left")
	case Retag:
		return node(e.ID, "Tags", "User")
	case SetOwner:
		return node(e.ID, "User")
	case SetAddr:
		return node(e.ID, family(e.Family))
	case SwapAddrs:
		return slices.Concat(node(e.A, family(e.Family)), node(e.B, family(e.Family)))
	case Announce, Withdraw:
		return node(nodeOf(e), "Announced")
	case Approve, Unapprove:
		return node(nodeOf(e), "Approved")
	case SetClient:
		return node(e.ID, "Client")
	case SetExpired:
		return node(e.ID, "Expired")
	case SetOnline:
		return node(e.ID, "Offline")
	case AddUser, DeleteUser, RenameUser, SetEmail:
		return []string{"users"}
	case SetPorts:
		return []string{e.Rule.String()}
	case SetProto:
		return []string{e.Rule.String()}
	case SetSel:
		return []string{e.Rule.String()}
	case SwapRules:
		return []string{RuleRef{e.Grant, e.I}.String(), RuleRef{e.Grant, e.J}.String()}
	case SetGroup:
		return []string{Groups[e.Group]}
	case SetHost:
		return []string{Hosts[e.Host]}
	case SetTagOwners:
		return []string{"tagOwners " + Tags[e.Tag]}
	case AddRule:
		return []string{listName(e.Ref.Grant) + " list"}
	case RemoveRule:
		return []string{listName(e.Ref.Grant) + " list"}
	case SetSSH:
		return []string{"ssh"}
	case SetNodeAttrs:
		return []string{"nodeAttrs"}
	case SetAutoApprovers:
		return []string{"autoApprovers"}
	}

	panic(fmt.Sprintf("no rule for %T in %v", e, w.Topology.NextID))
}

func listName(grant bool) string {
	if grant {
		return "grants"
	}

	return "acls"
}

func nodeOf(e Edit) types.NodeID {
	switch e := e.(type) {
	case Announce:
		return e.ID
	case Withdraw:
		return e.ID
	case Approve:
		return e.ID
	case Unapprove:
		return e.ID
	}

	return 0
}

// checkTopology holds what production holds of users and nodes: one ID
// each, an untagged node owned by a user who exists, a tagged node
// carrying none or one who does, route lists sorted, IDs below NextID.
var errTopology = errors.New("not a topology production holds")

func checkTopology(tp Topology) error {
	if !slices.IsSortedFunc(tp.Users, func(a, b User) int { return int(a.ID) - int(b.ID) }) { //nolint:gosec // small
		return fmt.Errorf("%w: users out of order: %v", errTopology, tp.Users)
	}

	for i, n := range tp.Nodes {
		if i > 0 && tp.Nodes[i-1].ID >= n.ID {
			return fmt.Errorf("%w: nodes out of order at n%d", errTopology, n.ID)
		}

		if n.ID >= tp.NextID {
			return fmt.Errorf("%w: n%d at or past the next ID %d", errTopology, n.ID, tp.NextID)
		}

		_, ok := tp.User(n.User)

		switch {
		case !n.Tagged() && !ok:
			return fmt.Errorf("%w: n%d belongs to u%d, who does not exist", errTopology, n.ID, n.User)
		case n.Tagged() && n.User != 0 && !ok:
			return fmt.Errorf("%w: n%d carries u%d, who does not exist", errTopology, n.ID, n.User)
		}

		for _, rs := range [][]int{n.Tags, n.Announced, n.Approved} {
			if !slices.IsSorted(rs) || len(slices.Compact(slices.Clone(rs))) != len(rs) {
				return fmt.Errorf("%w: n%d has an unsorted list %v", errTopology, n.ID, rs)
			}
		}
	}

	return nil
}

// TestShrinksToSmallCases runs two properties that fail on purpose and
// requires rapid to minimise each to a case a person can read. The output
// of the second is what a builder's failing property prints.
func TestShrinksToSmallCases(t *testing.T) {
	// Fail files go nowhere, and the seed is fixed so the minimised case
	// is the same on every run. Flags are process-wide: not parallel.
	for name, value := range map[string]string{"rapid.nofailfile": "true", "rapid.seed": "1"} {
		old := flag.Lookup(name).Value.String()

		err := flag.Set(name, value)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = flag.Set(name, old) })
	}

	t.Run("a tag on a shared address", func(t *testing.T) {
		var last World

		out := failing(t, func(t *rapid.T) {
			w := Worlds().Draw(t, "world")
			last = w

			v := NewView(w)
			for _, r := range slices.Concat(w.Policy.ACLs, w.Policy.Grants) {
				for _, s := range r.Src {
					for _, n := range v.MembersOf(s) {
						if s.Kind == SelTag && slices.ContainsFunc(n.Addrs(), func(a netip.Addr) bool { return v.heldByOther(n, a) }) {
							t.Fatalf("%s names n%d, which shares an address", s, n.ID)
						}
					}
				}
			}
		})

		rules := len(last.Policy.ACLs) + len(last.Policy.Grants)
		if len(last.Topology.Nodes) > 3 || rules > 2 {
			t.Errorf("minimised to %d nodes and %d rules:\n%s", len(last.Topology.Nodes), rules, out)
		}
	})

	t.Run("a system that loses retags after an address change", func(t *testing.T) {
		var last Scenario

		out := failing(t, func(t *rapid.T) {
			s := Scenarios(15).Draw(t, "scenario")
			last = s

			sys := newToySystem(s.Start)
			w := s.Start

			for i, st := range s.Steps {
				next, change := w.Commit(st)
				sys.commit(change, next)

				for _, n := range next.Topology.Nodes {
					if !slices.Equal(sys.tags[n.ID], n.Tags) {
						t.Fatalf("after step %d n%d has tags %v, want %v", i+1, n.ID, tagNames(sys.tags[n.ID]), tagNames(n.Tags))
					}
				}

				w = next
			}
		})

		edits := 0
		for _, st := range last.Steps {
			edits += len(st)
		}

		if len(last.Start.Topology.Nodes) > 2 || edits > 3 {
			t.Errorf("minimised to %d nodes and %d edits:\n%s", len(last.Start.Topology.Nodes), edits, out)
		}
	})
}

func tagNames(tags []int) []string {
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = Tags[t]
	}

	return out
}

// toySystem follows a world's node tags from what [World.Commit] reports, and
// stops following a node's tags once its address has moved: the bug the
// property above finds.
type toySystem struct {
	tags  map[types.NodeID][]int
	addrs map[types.NodeID][2]netip.Addr
	moved map[types.NodeID]bool
}

func newToySystem(w World) *toySystem {
	s := &toySystem{tags: map[types.NodeID][]int{}, addrs: map[types.NodeID][2]netip.Addr{}, moved: map[types.NodeID]bool{}}
	for _, n := range w.Topology.Nodes {
		s.tags[n.ID], s.addrs[n.ID] = n.Tags, [2]netip.Addr{n.V4, n.V6}
	}

	return s
}

func (s *toySystem) commit(c Change, w World) {
	for _, id := range c.Removed {
		delete(s.tags, id)
		delete(s.addrs, id)
	}

	for _, id := range c.Nodes {
		n, _ := w.Topology.Node(id)

		if old, ok := s.addrs[id]; ok && old != [2]netip.Addr{n.V4, n.V6} {
			s.moved[id] = true
		}

		s.addrs[id] = [2]netip.Addr{n.V4, n.V6}

		if !s.moved[id] {
			s.tags[id] = n.Tags
		}
	}
}

// failing runs prop under rapid, which must find it failing, and returns
// what rapid printed.
func failing(t *testing.T, prop func(*rapid.T)) string {
	t.Helper()

	fl := &failureLog{name: t.Name()}
	rapid.Check(fl, prop)

	if !fl.failed {
		t.Fatal("the property did not fail")
	}

	out := strings.Join(fl.lines, "\n")
	t.Log(out)

	return out
}

// failureLog is a [rapid.TB] that keeps what rapid reports instead of
// failing the test.
type failureLog struct {
	name   string
	lines  []string
	failed bool
}

func (r *failureLog) Helper()      {}
func (r *failureLog) Name() string { return r.name }
func (r *failureLog) Logf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}
func (r *failureLog) Log(args ...any) { r.lines = append(r.lines, fmt.Sprint(args...)) }
func (r *failureLog) Skipf(format string, args ...any) {
	r.Logf(format, args...)
}
func (r *failureLog) Skip(args ...any) { r.Log(args...) }
func (r *failureLog) SkipNow()         {}
func (r *failureLog) Errorf(format string, args ...any) {
	r.failed = true
	r.Logf(format, args...)
}

func (r *failureLog) Error(args ...any) {
	r.failed = true
	r.Log(args...)
}
func (r *failureLog) Fatalf(format string, args ...any) { r.Errorf(format, args...) }
func (r *failureLog) Fatal(args ...any)                 { r.Error(args...) }
func (r *failureLog) FailNow()                          { r.failed = true }
func (r *failureLog) Fail()                             { r.failed = true }
func (r *failureLog) Failed() bool                      { return r.failed }
